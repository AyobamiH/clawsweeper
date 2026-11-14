#!/usr/bin/env python3
"""Callable owner-fleet ingress reconciliation; NOT a second scheduler/worker.

An already-running, source-authorised fleet cycle may invoke this bounded
adapter. The network-facing webhook receiver only writes its existing private
delivery journal; only the fleet cycle holds control.lock and writes fleet.sqlite3.
Do not install a separate service or run it as a standalone job driver.
"""
from __future__ import annotations

import fcntl
import importlib.util
import os
from pathlib import Path
import stat
import sys

MAX_BATCH = 8
SCHEMA = "clawsweeper.existing-fleet-ingress-reconcile.v1"


def _require_prelock_fleet_phase(root: Path) -> None:
    """Do not deadlock the existing fleet cycle's non-reentrant control.lock.

    The fleet's core.lock() already owns an exclusive flock while discovery
    and execution run. The ordinary SQLite claim independently acquires that
    same lock. Therefore ingress reconciliation belongs in the existing
    fleet_ci.py cycle BEFORE core.lock(), never inside it. An active
    different owner also causes a fail-closed hold, not competing admission.
    This probe does not create or permanently retain a lock or queue.
    """
    path = Path(root) / "control.lock"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("missing_or_untrusted_canonical_fleet_lock")
    info = path.stat()
    if (info.st_uid != os.getuid()
            or not stat.S_ISREG(info.st_mode)
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("untrusted_canonical_fleet_lock")
    fd = None
    acquired = False
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        current = os.fstat(fd)
        if (current.st_ino, current.st_dev) != (info.st_ino, info.st_dev):
            raise RuntimeError("canonical_fleet_lock_changed")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("ingress_must_run_before_canonical_fleet_lock") from exc
        acquired = True
    except OSError as exc:
        raise RuntimeError("canonical_fleet_lock_unavailable") from exc
    finally:
        if fd is not None:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _private_secret(path: Path) -> bytes:
    """Read one private existing webhook secret, never reveal its value."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("unsafe_existing_webhook_secret")
    info = path.stat()
    if (info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 32 <= info.st_size <= 4096):
        raise RuntimeError("unsafe_existing_webhook_secret_permissions")
    secret = path.read_bytes().strip()
    if len(secret) < 32:
        raise RuntimeError("invalid_existing_webhook_secret")
    return secret


def reconcile_existing_fleet_ingress(
    *, ledger_dir: Path, release_file: Path, secret_file: Path,
    batch_limit: int = MAX_BATCH, claim=None,
) -> dict:
    """Reconcile already-staged envelopes once, under the existing fleet owner.

    A caller's authorised source-bound fleet cycle owns execution and recovery.
    No direct shell execution, runner admission, status publication or API POST.
    External caller decides whether this routine can run under its owner lease.
    A failed GET/queue claim remains staged and is not automatically replayed as
    a new provider effect. The queue itself deduplicates eventual local claims.
    """
    if type(batch_limit) is not int or not 1 <= batch_limit <= MAX_BATCH:
        raise RuntimeError("unsafe_ingress_reconciliation_batch")
    # Even an injected test claim must not skip secret/source validation in
    # production: a non-injected claim loads only the existing owner release.
    # Load the pre-existing source-bound release verifier from THIS module's
    # owned repository directory, not ambient PYTHONPATH or a user checkout.
    sidecar_path = Path(__file__).with_name("direct_local_receiver_integration.py")
    if sidecar_path.is_symlink() or not sidecar_path.is_file():
        raise RuntimeError("unsafe_local_fleet_release_verifier")
    spec = importlib.util.spec_from_file_location(
        "fleet_bound_direct_local_release", sidecar_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unloadable_owner_release_verifier")
    release = importlib.util.module_from_spec(spec)
    prior_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(release)
    finally:
        sys.dont_write_bytecode = prior_bytecode
    doc = release.read_release(Path(release_file))
    release.verify_release(doc)
    fleet_root = Path(doc["fleet_root"])
    expected_ledger = fleet_root / "webhook-deliveries"
    expected_secret = fleet_root / "secrets" / "webhook-hmac"
    if (Path(ledger_dir).absolute() != expected_ledger
            or Path(secret_file).absolute() != expected_secret):
        raise RuntimeError("unrecognised_existing_fleet_ingress_paths")
    # The claim's canonical flock is not re-entrant. Validate the existing
    # fleet's pre-lock phase before inspecting staged bytes or making a GET.
    _require_prelock_fleet_phase(fleet_root)
    if (expected_ledger.is_symlink() or not expected_ledger.is_dir()
            or (expected_ledger / "deliveries.sqlite3").is_symlink()
            or not (expected_ledger / "deliveries.sqlite3").is_file()):
        raise RuntimeError("missing_existing_webhook_ingress_ledger")
    if claim is None:
        claim = release.load_released_claim(Path(release_file))
    secret = _private_secret(Path(secret_file))
    module = Path(doc["checkout"]) / "scripts" / "ci-webhook-deliveries.py"
    if module.is_symlink() or not module.is_file() or module.stat().st_uid != os.getuid():
        raise RuntimeError("unsafe_released_ingress_ledger_module")
    # SOURCE is exact clean Git HEAD; import from the pinned owner checkout.
    spec = importlib.util.spec_from_file_location("released_ci_webhook_ledger", module)
    if spec is None or spec.loader is None:
        raise RuntimeError("unloadable_released_ingress_ledger")
    ledger_module = importlib.util.module_from_spec(spec)
    prior_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(ledger_module)
    finally:
        sys.dont_write_bytecode = prior_bytecode
    ledger = ledger_module.DeliveryLedger(Path(ledger_dir))
    pending = ledger.staged_ordinary(limit=batch_limit)
    counters = {"inspected": 0, "consumed": 0, "held": 0, "already_consumed": 0}
    # No secret, payload, ref, SHA or provider error text is emitted in the
    # results: even malformed events must not leak into shared CI journals.
    for record in pending:
        counters["inspected"] += 1
        try:
            result = claim(
                body=record["body"], event_name=record["event"],
                signature=record["signature"], delivery_id=record["delivery_id"],
                secret=secret,
            )
            if (not isinstance(result, dict)
                    or result.get("fresh_provider_source_verified") is not True
                    or result.get("suite") != "linux-node24"
                    or result.get("admission") not in ("queued", "already_admitted")
                    or result.get("job_executed") is not False
                    or result.get("github_status_published") is not False):
                raise RuntimeError("unverified_local_fleet_queue_claim")
            if not ledger.consume_ordinary(record["delivery_id"], record["fingerprint"]):
                counters["already_consumed"] += 1
            else:
                counters["consumed"] += 1
        except Exception:
            # HOLD is safe: the exact staged envelope survives process death
            # and is retried by the already-installed fleet timer, never by a
            # new queue/service. The claim's SQLite dedup handles interruption.
            counters["held"] += 1
    return {"schema": SCHEMA, "kind": "source_bound_queue_admission_only",
            "job_execution_proved": False, "github_actions_check_proved": False,
            **counters}
