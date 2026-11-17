#!/usr/bin/env python3
"""Callable owner-fleet ingress reconciliation; NOT a second scheduler/worker.

An already-running, source-authorised fleet cycle may invoke this bounded
adapter. The network-facing webhook receiver only writes its existing private
delivery journal; only the fleet cycle holds control.lock and writes fleet.sqlite3.
Do not install a separate service or run it as a standalone job driver.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import types

MAX_BATCH = 8
SCHEMA = "clawsweeper.existing-fleet-ingress-reconcile.v1"
DISTINCT_SCHEMA = "clawsweeper.existing-fleet-distinct-ingress-reconcile.v1"
SPLIT_SCHEMA = "clawsweeper.existing-fleet-split-source-ingress-reconcile.v1"


def _preverified_release_verifier(release_file: Path, sidecar_path: Path,
                                  profile: str):
    """Authenticate executable verifier BYTES before compiling any of them.

    The existing owner-private release pins an immutable implementation Git
    commit. Read that manifest with built-ins, fetch its exact verifier blob
    through sealed, absolute Git, and execute only those verified bytes. No
    ambient Python import path, filesystem race or Git executable is trusted.
    This is a pre-import boundary; the verifier still checks the full release,
    source closure and live fleet policy before any claim.
    """
    file = Path(release_file)
    if file.is_symlink() or not file.is_file():
        raise RuntimeError("unsafe_preimport_owner_release")
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 8192):
            raise RuntimeError("unsafe_preimport_owner_release")
        raw = os.read(fd, info.st_size + 1)
        if len(raw) != info.st_size:
            raise RuntimeError("changed_preimport_owner_release")
    finally:
        os.close(fd)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeError("duplicate_preimport_release_key")
            result[key] = value
        return result

    try:
        doc = json.loads(raw, object_pairs_hook=unique)
        schema = {
            "aggregate": "clawsweeper.direct-local-owner-release.v1",
            "distinct": "clawsweeper.direct-local-owner-release.v2-distinct",
            "split": "clawsweeper.direct-local-owner-release.v3-split",
        }[profile]
        if (not isinstance(doc, dict) or doc.get("schema") != schema
                or doc.get("repo") != "AyobamiH/clawsweeper"):
            raise RuntimeError("unapproved_preimport_release_identity")
        commit_key = ("implementation_commit" if profile == "split" else "commit")
        checkout_key = ("implementation_checkout" if profile == "split" else "checkout")
        commit = doc[commit_key]
        checkout = doc[checkout_key]
        if (not isinstance(commit, str)
                or not re.fullmatch(r"[a-f0-9]{40}", commit)
                or not isinstance(checkout, str) or not checkout.startswith("/")):
            raise RuntimeError("unapproved_preimport_release_identity")
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError) as exc:
        raise RuntimeError("invalid_preimport_release") from exc

    root = Path(checkout)
    if (root.is_symlink() or not root.is_dir()
            or root.stat().st_uid != os.getuid()
            or root.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or any(parent.is_symlink() for parent in root.parents)):
        raise RuntimeError("untrusted_preimport_implementation_checkout")
    binary = Path("/usr/bin/git")
    if (binary.is_symlink() or not binary.is_file()
            or binary.stat().st_uid != 0
            or binary.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("untrusted_preimport_git_binary")
    sidecar = Path(sidecar_path)
    if sidecar.is_symlink() or not sidecar.is_file():
        raise RuntimeError("untrusted_preimport_release_verifier")
    fd = os.open(sidecar, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode)
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 0 < info.st_size <= 131072):
            raise RuntimeError("untrusted_preimport_release_verifier")
        candidate = os.read(fd, info.st_size + 1)
        if len(candidate) != info.st_size:
            raise RuntimeError("changed_preimport_release_verifier")
    finally:
        os.close(fd)
    env = {
        "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    try:
        expected = subprocess.run(
            [str(binary), "-c", "core.fsmonitor=false", "-C", str(root),
             "show", "--no-ext-diff",
             commit + ":scripts/ci/direct_local_receiver_integration.py"],
            env=env, capture_output=True, timeout=6, check=True).stdout
        head = subprocess.run(
            [str(binary), "-c", "core.fsmonitor=false", "-C", str(root),
             "rev-parse", "--verify", "HEAD^{commit}"],
            env=env, capture_output=True, timeout=6, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("unavailable_preimport_signed_source") from exc
    if (head != commit.encode("ascii")
            or hashlib.sha256(candidate).digest() != hashlib.sha256(expected).digest()):
        raise RuntimeError("unverified_preimport_release_verifier")
    # Compile the verified byte snapshot, never reopen a mutable file.
    module = types.ModuleType("fleet_bound_direct_local_release")
    module.__file__ = str(sidecar)
    exec(compile(candidate, str(sidecar), "exec"), module.__dict__)
    return module


def _verified_distinct_queue_receipt(result: dict, event: str) -> bool:
    """No legacy aggregate or two labels sharing one job can be consumed."""
    expected = {
        ".github/workflows/ci.yml#check": "linux-node24-claw-check",
        ".github/workflows/ci.yml#sparse-repair-builds": "linux-node24-claw-sparse",
    }
    if (not isinstance(result, dict)
            or result.get("schema") !=
               "clawsweeper.existing-fleet-distinct-ordinary-claim.v1"
            or result.get("fresh_provider_source_verified") is not True
            or result.get("admission") not in ("queued", "already_admitted")
            or result.get("queue_admitted") is not (result["admission"] == "queued")
            or result.get("independent_jobs_executed") != 0
            or result.get("accepted_independent_jobs") != 0
            or result.get("provider_ci_execution") is not False
            or result.get("github_actions_dispatched") is not False
            or result.get("github_status_published") is not False
            or not isinstance(result.get("source_sha"), str)
            or not re.fullmatch(r"[a-f0-9]{40}", result["source_sha"])):
        return False
    ref = result.get("ref")
    records = result.get("jobs")
    if (not isinstance(ref, str) or not isinstance(records, list)
            or not (1 <= len(records) <= 2)):
        return False
    if event == "push" and ref == "main":
        expected_set = {".github/workflows/ci.yml#check"}
    elif event == "pull_request" and re.fullmatch(r"pr/[1-9][0-9]*", ref):
        expected_set = set(expected)
    else:
        return False
    if len(records) != len(expected_set):
        return False
    identities = []
    for record in records:
        if not isinstance(record, dict):
            return False
        name = record.get("workflow_job")
        if (name not in expected_set or record.get("suite") != expected[name]
                or not isinstance(record.get("job_id"), str)
                or not re.fullmatch(r"local-fleet-[a-f0-9]{12}", record["job_id"])
                or not isinstance(record.get("policy"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", record["policy"])):
            return False
        identities.append((name, record["job_id"], record["suite"]))
    return (len(set(name for name, _, _ in identities)) == len(records)
            and len(set(j for _, j, _ in identities)) == len(records))


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
    batch_limit: int = MAX_BATCH, claim=None, profile: str = "aggregate",
) -> dict:
    """Reconcile already-staged envelopes once, under the existing fleet owner.

    A caller's authorised source-bound fleet cycle owns execution and recovery.
    No direct shell execution, runner admission, status publication or API POST.
    External caller decides whether this routine can run under its owner lease.
    A failed GET/queue claim remains staged and is not automatically replayed as
    a new provider effect. The queue itself deduplicates eventual local claims.
    """
    if profile not in ("aggregate", "distinct", "split"):
        raise RuntimeError("unsupported_local_ingress_profile")
    if type(batch_limit) is not int or not 1 <= batch_limit <= MAX_BATCH:
        raise RuntimeError("unsafe_ingress_reconciliation_batch")
    # Even an injected test claim must not skip secret/source validation in
    # production: a non-injected claim loads only the existing owner release.
    # Load the pre-existing source-bound release verifier from THIS module's
    # owned repository directory, not ambient PYTHONPATH or a user checkout.
    release = _preverified_release_verifier(
        Path(release_file),
        Path(__file__).with_name("direct_local_receiver_integration.py"),
        profile,
    )
    if profile == "split":
        doc = release.read_split_source_release(Path(release_file))
        # This also verifies the REAL installed fleet-policy enrolment, not
        # just a caller-supplied execution SHA or in-memory proposal.
        release.verify_split_source_release(
            doc, enrolled_sha=doc["execution_commit"])
    elif profile == "distinct":
        doc = release.read_distinct_release(Path(release_file))
        release.verify_distinct_release(doc)
    else:
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
        if profile == "split":
            claim = release.load_split_source_claim(
                Path(release_file), enrolled_sha=doc["execution_commit"])
        elif profile == "distinct":
            claim = release.load_released_distinct_claim(Path(release_file))
        else:
            claim = release.load_released_claim(Path(release_file))
    secret = _private_secret(Path(secret_file))
    # The journal decoder belongs to the verified IMPLEMENTATION tree, never
    # a mutable or separately enrolled execution checkout.
    source_checkout = (doc["implementation_checkout"] if profile == "split"
                       else doc["checkout"])
    module = Path(source_checkout) / "scripts" / "ci-webhook-deliveries.py"
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
            if profile in ("distinct", "split"):
                authenticated = _verified_distinct_queue_receipt(result, record["event"])
                if profile == "split":
                    # A valid-looking local queue identity from ANOTHER source
                    # cannot consume this release's enrolled execution event.
                    authenticated = (authenticated and
                                     result["source_sha"] == doc["execution_commit"])
            else:
                authenticated = (
                    isinstance(result, dict)
                    and result.get("fresh_provider_source_verified") is True
                    and result.get("suite") == "linux-node24"
                    and result.get("admission") in ("queued", "already_admitted")
                    and result.get("job_executed") is False
                    and result.get("github_status_published") is False)
            if not authenticated:
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
    return {"schema": (SPLIT_SCHEMA if profile == "split" else
                       DISTINCT_SCHEMA if profile == "distinct" else SCHEMA),
            "kind": "source_bound_queue_admission_only",
            "job_execution_proved": False, "github_actions_check_proved": False,
            **counters}
