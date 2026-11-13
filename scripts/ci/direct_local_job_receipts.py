#!/usr/bin/env python3
"""Read-only, job-level proof for direct-local ordinary CI in the existing fleet.

A completed aggregate suite is NOT independently sufficient to accept both
ordinary workflow definitions. Only an authenticated event-bound queue claim,
exact job/ref/policy and each required command's successful real fleet receipt
can establish local command execution. This never publishes GitHub statuses,
admits a runner or mutates either the queue or source.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

import direct_local_fleet_claim as claims
import direct_local_workflow as routing
from estate_policy import Hold

STEP_COMMANDS = {
    "Exact commit checkout": None,
    "Workflow semantic validation": """actionlint -shellcheck= -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml""",
    "Pinned pnpm dependency install": "pnpm install --frozen-lockfile",
    "Full repository validation": "pnpm run check",
    "Sparse repair checkout smoke": "pnpm run test:workflow-sparse-checkout",
}
STEP_FOR_JOB = {
    ".github/workflows/ci.yml#check": "Full repository validation",
    ".github/workflows/ci.yml#sparse-repair-builds": "Sparse repair checkout smoke",
}
MAX_RECEIPT = 262144
MAX_LOG = 16777216


def _owner_file(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise Hold("receipt_or_log_missing_or_symlinked")
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Hold("unsafe_receipt_or_log_owner_permissions")
    if info.st_size > limit:
        raise Hold("unbounded_receipt_or_log")
    return path.read_bytes()


def _object_bytes(value: bytes) -> dict:
    try:
        doc = json.loads(value)
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise Hold("malformed_existing_fleet_evidence") from exc
    if not isinstance(doc, dict):
        raise Hold("invalid_existing_fleet_evidence")
    return doc


def verify_existing_ordinary_job_receipts(*, fleet_root: Path, fleet_job_id: str,
                                          source_sha: str, source_ref: str) -> dict:
    """Return per-definition local evidence, never GitHub-provider acceptance.

    Reads immutable receipts, checked log bytes and the existing fleet WAL
    queue without changing any installed state. Stale pre-adapter successes
    lacking an authenticated direct-local observation are HELD.
    """
    if (not claims.ID.fullmatch(fleet_job_id)
            or not routing.HEX40.fullmatch(source_sha)
            or source_ref != "main"
                and (not source_ref.startswith("pr/") or
                     not source_ref[3:].isdigit() or source_ref[3:].startswith("0"))):
        raise Hold("invalid_exact_ordinary_job_identity")
    root = claims.checked_fleet_root(fleet_root)
    policy = _object_bytes(_owner_file(root / "fleet-policy.json", 262144))
    cfg = policy.get("repositories", {}).get(routing.REPO, {})
    if (cfg.get("enrolled_head") != source_sha
            or cfg.get("contract") is None
            or policy.get("execution_hosts", {}).get(routing.REPO) != os.uname().nodename):
        raise Hold("existing_fleet_policy_not_pinned_to_exact_source")
    policy_hash = claims.reviewed_policy_hash(policy)
    db_path = root / "fleet.sqlite3"
    if db_path.is_symlink() or not db_path.is_file() or db_path.stat().st_uid != os.getuid():
        raise Hold("unsafe_existing_fleet_queue")
    uri = db_path.as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM jobs WHERE id=?", (fleet_job_id,)).fetchone()
        if (row is None or row["repo"] != routing.REPO
                or row["sha"] != source_sha or row["ref"] != source_ref
                or row["suite"] != claims.SUITE or row["policy"] != policy_hash
                or row["state"] != "completed" or row["outcome"] != "success"
                or not isinstance(row["attempt"], int) or row["attempt"] < 1):
            raise Hold("existing_fleet_execution_not_terminal_or_exact")
        # A compromised/unbounded observations table must not turn a
        # read-only evidence operation into uncontrolled memory usage.
        observations = db.execute(
            "SELECT value FROM observations WHERE key LIKE 'direct-local:%' LIMIT 2049"
        ).fetchall()
        if len(observations) > 2048:
            raise Hold("unbounded_direct_local_delivery_evidence")
        linked = []
        for item in observations:
            record = _object_bytes(item["value"].encode("utf-8"))
            if record.get("job_id") != fleet_job_id:
                continue
            if (record.get("proof_kind") != "authenticated_queue_admission_not_execution"
                    or record.get("source_sha") != source_sha
                    or record.get("ref") != source_ref
                    or record.get("suite") != claims.SUITE
                    or record.get("event") not in ("push", "pull_request")
                    or not isinstance(record.get("delivery_sha256"), str)
                    or not routing.HEX64.fullmatch(record["delivery_sha256"])):
                raise Hold("untrusted_direct_local_delivery_evidence")
            linked.append(record)
        if not linked:
            raise Hold("legacy_suite_has_no_authenticated_ordinary_job_claim")
        expected = ({".github/workflows/ci.yml#check"} if source_ref == "main"
                    else set(STEP_FOR_JOB))
        if any(not isinstance(r.get("job_intents"), list)
               or len(r["job_intents"]) != len(expected)
               or set(r["job_intents"]) != expected
               or r.get("event") != ("push" if source_ref == "main" else "pull_request")
               for r in linked):
            raise Hold("direct_local_event_job_identity_mismatch")
        receipt_path = root / "evidence" / "fleet" / (fleet_job_id + ".json")
        if row["receipt"] != str(receipt_path):
            raise Hold("foreign_existing_fleet_receipt_path")
        receipt_raw = _owner_file(receipt_path, MAX_RECEIPT)
        receipt = _object_bytes(receipt_raw)
        if (any(receipt.get(k) != row[k] for k in
                ("id", "repo", "sha", "suite", "ref", "policy", "attempt"))
                or receipt.get("outcome") != "success"
                or not isinstance(receipt.get("finished_at"), str)
                or not receipt.get("started_at")
                or receipt.get("mode") != "local-scheduler-not-github-actions"
                or receipt.get("cleanup", {}).get("container_absent") is not True):
            raise Hold("incomplete_or_foreign_real_fleet_receipt")
        steps = receipt.get("steps")
        if not isinstance(steps, list) or len(steps) != len(STEP_COMMANDS):
            raise Hold("missing_exact_real_step_execution")
        for step, (name, command) in zip(steps, STEP_COMMANDS.items()):
            if (not isinstance(step, dict) or step.get("name") != name
                    or type(step.get("exit_code")) is not int
                    or step["exit_code"] != 0
                    or (command is not None and step.get("command") != command)):
                raise Hold("failed_or_relabelled_real_fleet_step")
        initial = steps[0].get("command", "")
        if (not isinstance(initial, str)
                or "git checkout --quiet --detach FETCH_HEAD" not in initial
                or f"fetch --quiet --depth=1 origin {source_sha}" not in initial
                or 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' not in initial):
            raise Hold("real_checkout_not_bound_to_exact_sha")
        log_path = root / "logs" / "fleet" / (fleet_job_id + ".log")
        log = _owner_file(log_path, MAX_LOG)
        if (receipt.get("log_bytes") != len(log)
                or receipt.get("log_sha256") != hashlib.sha256(log).hexdigest()):
            raise Hold("real_execution_log_digest_mismatch")
    return {
        "schema": "clawsweeper.direct-local-ordinary-job-readback.v1",
        "repo": routing.REPO, "source_commit": source_sha,
        "source_ref": source_ref, "fleet_job_id": fleet_job_id,
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "log_sha256": hashlib.sha256(log).hexdigest(),
        "verified_local_job_steps": [
            {"job": key, "step": STEP_FOR_JOB[key],
             "local_execution": "passed_verified_existing_fleet_receipt"}
            for key in sorted(expected)
        ],
        "authenticated_event_claim_count": len(linked),
        "github_provider_check_independently_verified": False,
        "protected_codeql_satisfied": False,
    }
