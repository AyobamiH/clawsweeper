"""Durable bounded concurrency reservations for ClawSweeper ephemeral JIT workers.

A reservation is written and fsynced BEFORE any external registration attempt.
Crashes leave the slot held. Replaying the same GitHub job/attempt is forbidden.
This module does not dispatch GitHub jobs or access credentials.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from datetime import datetime, timezone

from estate_policy import Hold, CLASSES, REPO

MAX_PARALLEL = 4
MIN_RESERVE_MIB = 2048
BUDGET_MIB = {
    "ordinary": 2048,
    "privileged": 3072,
    "review": 3584,
    "codeql": 5500,
    "e2e": 6500,
    "windows": 2048,
}
SENSITIVE_EVIDENCE = {
    "privileged": ("external_effects_verified",),
    "review": ("review_verdict_complete", "source_bundle_verified"),
    "codeql": ("sarif_upload_verified",),
    "e2e": ("all_scenarios_verified", "rootless_runtime_verified"),
    "windows": ("native_windows_execution_verified",),
}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
HELD = frozenset(("reserved", "running", "held"))


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def _private(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise Hold("unsafe_estate_state_permissions")


def _atomic_json(target, record):
    _private(target.parent)
    fd, tmp = tempfile.mkstemp(prefix=".estate-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(record, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, target)
        pfd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(pfd)
        finally:
            os.close(pfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def key_of(candidate):
    return f"{candidate.run_id}-{candidate.job_id}-{candidate.attempt}"


class SlotLedger:
    def __init__(self, root):
        self.root = Path(root)
        _private(self.root)
        self.path = self.root / "ledger.json"
        self.lock_path = self.root / "ledger.lock"

    @contextmanager
    def locked(self):
        _private(self.root)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise Hold("world_readable_slot_lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self):
        if not self.path.exists():
            return {"schema": "clawsweeper.estate-slots.v1", "attempts": {}}
        if self.path.is_symlink() or self.path.stat().st_mode & 0o077:
            raise Hold("unsafe_slot_ledger")
        data = json.loads(self.path.read_text())
        if (data.get("schema") != "clawsweeper.estate-slots.v1" or
                not isinstance(data.get("attempts"), dict)):
            raise Hold("slot_ledger_corrupt")
        return data

    def inspect(self):
        with self.locked():
            return self._read()

    def reserve(self, candidate, controls, *, memory_available_mib, fleet_busy=False, disk_free_gib=0):
        """Returns a unique slot, or holds. Never silently reclaims uncertain intent."""
        if not isinstance(controls, dict) or controls.get("enabled") is not True or controls.get("repo") != REPO:
            raise Hold("estate_controller_disabled")
        if candidate.job_class not in CLASSES:
            raise Hold("unrecognised_reservation_class")
        limit = controls.get("max_parallel")
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= MAX_PARALLEL):
            raise Hold("invalid_parallel_capacity")
        caps = controls.get("class_parallel_caps")
        if not isinstance(caps, dict) or set(caps) != set(CLASSES):
            raise Hold("missing_class_capacity_contract")
        if any(not isinstance(x, int) or isinstance(x, bool) or not (0 <= x <= limit) for x in caps.values()):
            raise Hold("invalid_class_capacity")
        if fleet_busy:
            raise Hold("shared_fleet_has_priority")
        if not isinstance(memory_available_mib, int) or isinstance(memory_available_mib, bool) or memory_available_mib < 0:
            raise Hold("unreliable_memory_observation")
        if not isinstance(disk_free_gib, (int, float)) or disk_free_gib < 20:
            raise Hold("insufficient_disk_reserve")

        key = key_of(candidate)
        with self.locked():
            data = self._read()
            attempts = data["attempts"]
            if key in attempts:
                raise Hold("duplicate_or_uncertain_job_intent")
            active = [value for value in attempts.values() if value["state"] in HELD]
            if len(active) >= limit:
                raise Hold("fleet_capacity_exhausted")
            if sum(a["job_class"] == candidate.job_class for a in active) >= caps[candidate.job_class]:
                raise Hold("class_capacity_exhausted")
            # Memory observation already reflects running workers; subtracting
            # other reservations additionally errs on the safe side.
            reserved = sum(BUDGET_MIB[a["job_class"]] for a in active)
            if memory_available_mib < MIN_RESERVE_MIB + BUDGET_MIB[candidate.job_class] + reserved:
                raise Hold("aggregate_memory_reserve")
            occupied = {a["slot"] for a in active}
            available = [i for i in range(limit) if i not in occupied]
            if not available:
                raise Hold("no_verified_free_slot")
            slot = available[0]
            record = {
                "job_key": candidate.job_key,
                "class": candidate.job_class,
                "job_class": candidate.job_class,
                "slot": slot,
                "run_id": candidate.run_id,
                "job_id": candidate.job_id,
                "attempt": candidate.attempt,
                "head_sha": candidate.sha,
                "label": candidate.label,
                "state": "reserved",  # External effects must not precede this write.
                "created_at": timestamp(),
                "reserved_pid": os.getpid(),
            }
            attempts[key] = record
            _atomic_json(self.path, data)
            return dict(record)

    def update(self, candidate, *, state, proof=None):
        """Advance once; fail closed on crashes or missing cleanup readback."""
        if state not in ("running", "finished", "held"):
            raise Hold("invalid_slot_transition")
        key = key_of(candidate)
        with self.locked():
            data = self._read()
            record = data["attempts"].get(key)
            if not isinstance(record, dict) or record.get("job_key") != candidate.job_key:
                raise Hold("reservation_identity_missing")
            if record.get("state") not in ("reserved", "running"):
                raise Hold("reservation_already_final_or_held")
            if state == "running":
                if record["state"] != "reserved":
                    raise Hold("cannot_run_twice")
                record["state"] = "running"
            else:
                if not isinstance(proof, dict):
                    raise Hold("missing_final_receipt")
                expected = (candidate.run_id, candidate.job_id, candidate.attempt)
                observed = (proof.get("run_id"), proof.get("job_id"), proof.get("attempt"))
                if observed != expected:
                    raise Hold("final_receipt_identity_mismatch")
                digest = proof.get("log_sha256")
                if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                    raise Hold("runner_log_digest_missing")
                # Never release a slot with uncertain runner registration or
                # leftover containers, even when GitHub says completed.
                if not (proof.get("runner_absent_verified") is True and
                        proof.get("containers_absent_verified") is True and
                        proof.get("github_terminal_verified") is True):
                    record["state"] = "held"
                    record["reason"] = "cleanup_or_github_state_unverified"
                elif state == "finished" and any(proof.get(k) is not True for k in
                                                  SENSITIVE_EVIDENCE.get(candidate.job_class, ())):
                    # CodeQL SARIF can be published after the first language
                    # job has terminally cleaned up. Keep its attempt pending
                    # but free the PHYSICAL slot so the second language can
                    # run on memory-constrained hardware. Never replay it.
                    if candidate.job_class == "codeql":
                        record["state"] = "awaiting_evidence"
                        record["reason"] = "sarif_readback_pending"
                    else:
                        record["state"] = "held"
                        record["reason"] = "class_evidence_incomplete"
                else:
                    record["state"] = state
                record["proof_sha256"] = hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest()
                record["log_sha256"] = digest
                record["finished_at"] = timestamp()
            _atomic_json(self.path, data)
            return dict(record)


    def reconcile_held(self, candidate, *, proof):
        """Independently clear a crash/held slot WITHOUT approving or replaying its job.

        All class-specific provider effects must be read back. Original attempt
        and failure/uncertainty remain immutable in the ledger lineage.
        """
        key = key_of(candidate)
        with self.locked():
            data = self._read()
            record = data["attempts"].get(key)
            if not isinstance(record, dict) or record.get("job_key") != candidate.job_key:
                raise Hold("held_attempt_missing")
            if record.get("state") not in HELD | {"awaiting_evidence"}:
                raise Hold("attempt_not_held")
            if not isinstance(proof, dict) or (proof.get("run_id"), proof.get("job_id"), proof.get("attempt")) != (
                    candidate.run_id, candidate.job_id, candidate.attempt):
                raise Hold("reconciliation_identity_mismatch")
            if any(proof.get(k) is not True for k in (
                "github_terminal_verified", "runner_absent_verified", "containers_absent_verified",
                *SENSITIVE_EVIDENCE.get(candidate.job_class, ()))):
                raise Hold("independent_reconciliation_incomplete")
            if not isinstance(proof.get("log_sha256"), str) or not SHA256.fullmatch(proof["log_sha256"]):
                raise Hold("reconciliation_log_digest_missing")
            record["state_before_reconciliation"] = record["state"]
            record["state"] = "reconciled"  # Not 'passed'. Never replay same tuple.
            record["independent_reconciliation_sha256"] = hashlib.sha256(
                json.dumps(proof, sort_keys=True).encode()).hexdigest()
            record["reconciled_at"] = timestamp()
            _atomic_json(self.path, data)
            return dict(record)
