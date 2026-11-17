#!/usr/bin/env python3
"""Fail-closed worker provenance for signed LOCAL requests in the existing fleet.

A queue row is NOT an execution grant. The installed owner controller must call
this before dispatch and again in the detached worker, then apply its normal
isolation, resource limits, canonical lock and crash recovery. This module is
read-only: it cannot enqueue, execute, publish statuses or start a provider run.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess

import direct_local_fleet_claim as claims
import direct_local_manual_run as manual
import direct_local_workflow as routing
from estate_policy import Hold

SCHEMA = "clawsweeper.owner-signed-local-manual-worker-provenance.v1"
MAX_OBSERVATIONS = 2048


def _verify_signed_claim_envelope(key: str, evidence: dict, source: str) -> None:
    """The SQLite observation alone never authenticates an execution grant.

    Check the preserved SSH signature and signed intent at each dispatch and
    worker start. Never log raw signed requests, signatures or nonce values.
    """
    request_b64 = evidence.get("signed_request_b64")
    signature_b64 = evidence.get("signed_request_signature_b64")
    if (not isinstance(request_b64, str)
            or not 0 < len(request_b64) <= 5500
            or not isinstance(signature_b64, str)
            or not 0 < len(signature_b64) <= 11000):
        raise Hold("missing_signed_local_manual_request_envelope")
    try:
        raw = base64.b64decode(request_b64, validate=True)
        sig = base64.b64decode(signature_b64, validate=True)
        seed = json.loads(raw, object_pairs_hook=manual.unique_object)
        if not isinstance(seed, dict) or type(seed.get("issued_at")) is not int:
            raise Hold("malformed_signed_local_manual_intent")
        intent = manual.parse_intent(raw, seed["issued_at"])
    except (ValueError, UnicodeError, TypeError, OverflowError) as exc:
        raise Hold("malformed_signed_local_manual_intent") from exc
    if (intent["source_sha"] != source
            or hashlib.sha256(raw).hexdigest() != evidence["request_sha256"]
            or hashlib.sha256(intent["nonce"].encode("ascii")).hexdigest()
               != evidence["nonce_sha256"]
            or key != "direct-local-manual:" + hashlib.sha256(
                (manual.REPO + "\n" + intent["nonce"]).encode("ascii")
            ).hexdigest()
            or intent["job_intents"] != evidence["job_intents"]):
        raise Hold("signed_local_manual_claim_binding_mismatch")
    manual.verify_owner_signature_bytes(
        raw, sig, manual.owner_allowed_signers())


def verify_manual_queue_provenance(*, fleet_root: Path, job_id: str) -> dict:
    """Validate the exact single-owner admission record, before any effect.

    This inexpensive local-only validation is also safe inside the owner fleet
    lock. Only the explicit queue/admission data and existing policy are read.
    The live source readback MUST independently run at worker execution.
    """
    if not isinstance(job_id, str) or not claims.ID.fullmatch(job_id):
        raise Hold("invalid_local_manual_fleet_job_identity")
    root = claims.checked_fleet_root(fleet_root)
    policy = json.loads(manual.owner_bytes(
        root / "fleet-policy.json", 262144, private=False))
    cfg = policy.get("repositories", {}).get(manual.REPO, {})
    source = cfg.get("enrolled_head")
    if (not isinstance(source, str) or not routing.HEX40.fullmatch(source)
            or policy.get("execution_hosts", {}).get(manual.REPO)
                != os.uname().nodename):
        raise Hold("manual_worker_policy_source_or_host_drift")
    policy_digest = claims.reviewed_policy_hash(policy)
    with sqlite3.connect((root / "fleet.sqlite3").as_uri() + "?mode=ro",
                         uri=True, timeout=3) as db:
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT id,repo,sha,suite,policy,ref,state FROM jobs WHERE id=?",
            (job_id,),
        ).fetchone()
        if (row is None or row["repo"] != manual.REPO
                or row["sha"] != source or row["suite"] != claims.SUITE
                or row["policy"] != policy_digest or row["ref"] != manual.REF
                or row["state"] not in (
                    "queued", "claimed", "running", "completed")):
            raise Hold("manual_worker_job_identity_or_state_mismatch")
        records = db.execute(
            "SELECT key,value FROM observations "
            "WHERE key LIKE ? "
            "OR key LIKE ? LIMIT ?",
            ("direct-local-manual:%", "direct-local:%", MAX_OBSERVATIONS + 1),
        ).fetchall()
        if len(records) > MAX_OBSERVATIONS:
            raise Hold("unbounded_manual_worker_provenance")
        matched = []
        for candidate in records:
            try:
                record = json.loads(candidate["value"])
            except (ValueError, TypeError) as exc:
                raise Hold("unreadable_manual_worker_observation") from exc
            if not isinstance(record, dict):
                raise Hold("unreadable_manual_worker_observation")
            if record.get("job_id") != job_id:
                continue
            matched.append((candidate["key"], record))
    if len(matched) != 1:
        raise Hold("missing_or_ambiguous_local_manual_owner_claim")
    key, evidence = matched[0]
    expected_jobs = list(manual.JOBS)
    if (not key.startswith("direct-local-manual:")
            or evidence.get("proof_kind") != manual.PROOF
            or evidence.get("repo") != manual.REPO
            or evidence.get("source_sha") != source
            or evidence.get("source_ref") != manual.PROVIDER_REF
            or evidence.get("ref") != manual.REF
            or evidence.get("suite") != claims.SUITE
            or evidence.get("event") != "local-manual"
            or evidence.get("owner_principal") != manual.PRINCIPAL
            or evidence.get("job_intents") != expected_jobs
            or not isinstance(evidence.get("request_sha256"), str)
            or not routing.HEX64.fullmatch(evidence["request_sha256"])
            or not isinstance(evidence.get("nonce_sha256"), str)
            or not routing.HEX64.fullmatch(evidence["nonce_sha256"])):
        raise Hold("untrusted_local_manual_worker_observation")
    _verify_signed_claim_envelope(key, evidence, source)
    return {
        "schema": SCHEMA,
        "repo": manual.REPO, "source_sha": source,
        "ref": manual.REF, "suite": claims.SUITE, "job_id": job_id,
        "job_intents": expected_jobs,
        "request_sha256": evidence["request_sha256"],
        "nonce_sha256": evidence["nonce_sha256"],
        "queue_state": row["state"],
        "verified_owner_origin": True,
        "provider_status_authorised": False,
        "github_actions_admission_authorised": False,
        "job_executed": False,
    }


def verify_exact_clean_checkout(checkout: Path, expected_sha: str) -> None:
    """Compare HEAD, index and worktree blobs without running Git clean filters.

    Even /usr/bin/git status may execute a repository-configured filter.clean
    BEFORE source integrity is known. Only use non-executing Git plumbing, then
    hash the working-tree bytes directly against the signed HEAD object IDs.
    """
    source = Path(checkout)
    if (source.is_symlink() or not source.is_dir()
            or source.stat().st_uid != os.getuid()
            or source.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not routing.HEX40.fullmatch(expected_sha)):
        raise Hold("manual_worker_unsafe_source_checkout")
    binary = manual._trusted_system_binary("git")
    home = str(Path(manual.owner_allowed_signers()).parents[2])
    env = {"PATH": "/usr/bin:/bin", "HOME": home, "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_TERMINAL_PROMPT": "0"}
    prefix = [binary, "-c", "core.fsmonitor=false",
              "-c", "core.hooksPath=/dev/null", "-C", str(source)]

    def git_bytes(*args: str) -> bytes:
        try:
            result = subprocess.run(
                [*prefix, *args], capture_output=True, check=False,
                timeout=15, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Hold("manual_worker_checkout_verifier_unavailable") from exc
        if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
            raise Hold("manual_worker_source_checkout_not_exact_clean_head")
        return result.stdout

    if git_bytes("rev-parse", "HEAD").strip() != expected_sha.encode("ascii"):
        raise Hold("manual_worker_source_checkout_not_exact_clean_head")

    def records(raw: bytes, *, index: bool) -> dict[bytes, tuple[bytes, bytes]]:
        parsed = {}
        for item in raw.split(b"\0"):
            if not item:
                continue
            try:
                meta, name = item.split(b"\t", 1)
                fields = meta.split()
                if index:
                    mode, digest, stage = fields
                    if stage != b"0":
                        raise ValueError("unmerged index")
                else:
                    mode, kind, digest = fields
                    if kind != b"blob":
                        raise ValueError("nonblob source")
                if (mode not in (b"100644", b"100755") or len(digest) != 40
                        or any(c not in b"0123456789abcdef" for c in digest)
                        or not name or name.startswith(b"/")
                        or b".." in name.split(b"/") or name in parsed):
                    raise ValueError("unexpected source path or mode")
            except (ValueError, IndexError) as exc:
                raise Hold("manual_worker_source_checkout_not_exact_clean_head") from exc
            parsed[name] = (mode, digest)
            if len(parsed) > 30000:
                raise Hold("manual_worker_source_checkout_not_exact_clean_head")
        return parsed

    head = records(git_bytes("ls-tree", "-rz", "HEAD"), index=False)
    staged = records(git_bytes("ls-files", "--stage", "-z"), index=True)
    if not head or head != staged or git_bytes(
            "ls-files", "--others", "--exclude-standard", "-z"):
        raise Hold("manual_worker_source_checkout_not_exact_clean_head")

    total_size = 0
    for name, (mode, digest) in head.items():
        path = source / os.fsdecode(name)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                before = os.fstat(fd)
                total_size += before.st_size
                if (not stat.S_ISREG(before.st_mode)
                        or before.st_size > 128 * 1024 * 1024
                        or total_size > 1024 * 1024 * 1024
                        or bool(before.st_mode & 0o111) != (mode == b"100755")):
                    raise Hold("manual_worker_source_checkout_not_exact_clean_head")
                h = hashlib.sha1(
                    b"blob " + str(before.st_size).encode("ascii") + b"\0")
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
                after = os.fstat(fd)
                if (h.hexdigest().encode("ascii") != digest
                        or (before.st_dev, before.st_ino, before.st_size,
                            before.st_mtime_ns, before.st_ctime_ns) !=
                           (after.st_dev, after.st_ino, after.st_size,
                            after.st_mtime_ns, after.st_ctime_ns)):
                    raise Hold("manual_worker_source_checkout_not_exact_clean_head")
            finally:
                os.close(fd)
        except OSError as exc:
            raise Hold("manual_worker_source_checkout_not_exact_clean_head") from exc


def verify_manual_worker_start(*, checkout: Path, fleet_root: Path,
                               job_id: str) -> dict:
    """Production worker entry point. No injectable source or trust bypass."""
    result = verify_manual_queue_provenance(
        fleet_root=fleet_root, job_id=job_id)
    if result["queue_state"] not in ("queued", "claimed", "running"):
        raise Hold("manual_worker_terminal_job_cannot_be_restarted")
    fresh = manual.read_fresh_develop_sha()
    if fresh != result["source_sha"]:
        raise Hold("manual_worker_develop_moved_or_unavailable")
    verify_exact_clean_checkout(checkout, fresh)
    policy = json.loads(manual.owner_bytes(
        Path(fleet_root) / "fleet-policy.json", 262144, private=False))
    plan = routing.compile_plan(
        Path(checkout), policy, commit=fresh,
        hostname=os.uname().nodename)
    selected = sorted(job["key"] for job in plan["jobs"]
                      if job["class"] == "ordinary"
                      and job["route"] == "existing-local-fleet"
                      and job["suite"] == claims.SUITE)
    if (plan.get("source_verified") is not True
            or len(plan.get("jobs", [])) != 88
            or selected != sorted(manual.JOBS)):
        raise Hold("manual_worker_exact_88_job_plan_changed")
    return {**result, "live_develop_verified": True,
            "exact_clean_source_verified": True}
