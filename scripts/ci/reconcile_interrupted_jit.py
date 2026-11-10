#!/usr/bin/env python3
"""Owner-verified, one-intent-at-a-time cleanup of an interrupted ClawSweeper JIT.

This is an explicit recovery operation, not runner dispatch or a retry of POST.
It cannot promote an interrupted run to passing CI. Execution requires an
exclusive executor lock, exact durable receipt and live GitHub identity proof.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from self_hosted_executor import (
    LOCK, RECEIPTS, REPOSITORY, REPO_SLUG, atomic, gh, inspect_owned,
    lookup_owned_runner, now, private_dir, runner_absent_verified, stop_owned,
)
from self_hosted_policy import EVENTS, JOB_LABEL, WORKFLOWS

KEY = re.compile(r"run-([1-9][0-9]*)-job-([1-9][0-9]*)-attempt-([1-9][0-9]*)\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
STATES = frozenset(("registration_uncertain", "registered", "runner_started"))


def verify_identity(directory: Path) -> tuple[dict, str]:
    directory = Path(directory)
    if (directory.is_symlink() or directory.parent.resolve() != RECEIPTS.resolve()
            or not directory.is_dir()):
        raise RuntimeError("unowned_or_unsafe_receipt_directory")
    match = KEY.fullmatch(directory.name)
    if match is None:
        raise RuntimeError("invalid_receipt_directory_name")
    source = directory / "receipt.json"
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("unsafe_or_missing_original_receipt")
    original = source.read_bytes()
    receipt = json.loads(original)
    run_id, job_id, attempt = map(int, match.groups())
    name = f"csw-ci-{run_id}-{job_id}-{attempt}"
    label = receipt.get("label")
    claimed = JOB_LABEL.fullmatch(label) if isinstance(label, str) else None
    if (not claimed or int(claimed.group(2)) != run_id
            or receipt.get("role") != claimed.group(1)
            or (claimed.group(1), claimed.group(3)) not in WORKFLOWS
            or WORKFLOWS[(claimed.group(1), claimed.group(3))][0] != receipt.get("workflow")
            or receipt.get("event") not in EVENTS[(claimed.group(1), claimed.group(3))]
            or receipt.get("schema") != "clawsweeper.selfhosted-jit.v1"
            or [receipt.get("run_id"), receipt.get("job_id"), receipt.get("attempt")] !=
                    [run_id, job_id, attempt]
            or receipt.get("runner_name") != name
            or not isinstance(receipt.get("head_sha"), str)
            or not SHA.fullmatch(receipt["head_sha"])
            or receipt.get("state") not in STATES
            or receipt.get("finished_at") is not None):
        raise RuntimeError("interrupted_receipt_identity_mismatch")
    runner_id = receipt.get("runner_id")
    if runner_id is not None and (not isinstance(runner_id, int)
                                  or isinstance(runner_id, bool) or runner_id <= 0):
        raise RuntimeError("invalid_original_runner_id")
    return receipt, hashlib.sha256(original).hexdigest()


def verify_github(receipt: dict) -> dict:
    run_id, job_id = receipt["run_id"], receipt["job_id"]
    run = gh(f"{REPO_SLUG}/actions/runs/{run_id}")
    if (run.get("id") != run_id or run.get("run_attempt") != receipt["attempt"]
            or run.get("head_sha") != receipt["head_sha"]
            or run.get("path") != receipt["workflow"]
            or run.get("repository", {}).get("full_name") != REPOSITORY):
        raise RuntimeError("github_run_source_mismatch")
    job = gh(f"{REPO_SLUG}/actions/jobs/{job_id}")
    if (job.get("id") != job_id or job.get("run_id") != run_id
            or job.get("runner_name") not in (None, "", receipt["runner_name"])
            or job.get("status") not in ("queued", "in_progress", "completed")):
        raise RuntimeError("github_job_identity_mismatch")
    return {k: job.get(k) for k in ("id", "run_id", "status", "conclusion", "runner_name")}


def recover(directory: Path) -> dict:
    directory = Path(directory)
    private_dir(RECEIPTS)
    # Any live owner task holds this same exclusive lock. Never race active JIT.
    if LOCK.is_symlink():
        raise RuntimeError("unsafe_executor_lock")
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("live_executor_owns_lock") from exc
        receipt, digest = verify_identity(directory)
        job = verify_github(receipt)
        name, label = receipt["runner_name"], receipt["label"]
        intent = directory / "interrupted-recovery-intent.json"
        proof = directory / "interrupted-recovery-proof.json"
        if intent.is_symlink() or proof.is_symlink():
            raise RuntimeError("unsafe_recovery_evidence_path")
        if intent.exists():
            previous = json.loads(intent.read_text())
            if (previous.get("schema") != "clawsweeper.jit-interrupted-intent.v1"
                    or previous.get("original_receipt_sha256") != digest
                    or previous.get("runner_name") != name):
                raise RuntimeError("existing_recovery_intent_drift")
        else:
            atomic(intent, {
                "schema": "clawsweeper.jit-interrupted-intent.v1",
                "original_receipt_sha256": digest,
                "runner_name": name, "head_sha": receipt["head_sha"],
                "run_id": receipt["run_id"], "job_id": receipt["job_id"],
                "attempt": receipt["attempt"], "created_at": now(),
                "replay_registration": False,
            })
        # Validate every owned object before removing any. A foreign label
        # or busy runner is not a cleanup target.
        worker, net = name + "-worker", name + "-net"
        inspect_owned(worker, name)
        inspect_owned(net, name)
        runner_id = lookup_owned_runner(name, label, receipt.get("runner_id"))
        if proof.exists():
            stored = json.loads(proof.read_text())
            if (stored.get("original_receipt_sha256") != digest
                    or stored.get("decision") != "cleanup_verified_no_replay"):
                raise RuntimeError("completed_recovery_proof_drift")
            if inspect_owned(worker, name) is not None or inspect_owned(net, name) is not None:
                raise RuntimeError("cleanup_regressed_owned_container_returned")
            runner_absent_verified(receipt.get("runner_id"), name)
            return stored
        # No re-registration. Stop ONLY the exact owned, non-busy remnants.
        for child in (worker, net):
            stop_owned(child, name)
        if runner_id is not None:
            try:
                gh(f"{REPO_SLUG}/actions/runners/{runner_id}", "DELETE")
            except Exception:
                pass  # The definitive condition is complete inventory absence.
        for child in (worker, net):
            if inspect_owned(child, name) is not None:
                raise RuntimeError("owned_container_cleanup_unverified")
        runner_absent_verified(receipt.get("runner_id") or runner_id, name)
        record = {
            "schema": "clawsweeper.jit-interrupted-recovery.v1",
            "decision": "cleanup_verified_no_replay",
            "original_state": receipt["state"],
            "original_receipt_sha256": digest,
            "run_id": receipt["run_id"], "job_id": receipt["job_id"],
            "attempt": receipt["attempt"], "runner_name": name,
            "head_sha": receipt["head_sha"],
            "github_job": job,
            "runner_absent": True, "owned_containers_absent": True,
            "new_registration_attempted": False,
            "release_acceptance": False,
            "verified_at": now(),
        }
        atomic(proof, record)
        return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt_dir", type=Path)
    args = parser.parse_args()
    try:
        result = recover(args.receipt_dir)
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:
        print(json.dumps({"state": "held", "reason": type(exc).__name__,
                          "detail": str(exc)[:160]}), file=sys.stderr)
        raise SystemExit(1)
