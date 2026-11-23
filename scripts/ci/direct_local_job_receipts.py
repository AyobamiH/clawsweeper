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


def verify_current_source_ordinary_jobs(*, fleet_root: Path,
                                        source_sha: str, source_ref: str) -> dict:
    """Verify one real existing-fleet execution for an exact eligible event.

    Read-only across the canonical queue and per-step receipts. Historical
    aggregate jobs without authenticated event provenance are never accepted.
    There is no new queue, worker, scheduler, webhook or provider effect.
    """
    if (not routing.HEX40.fullmatch(source_sha)
            or not (source_ref == "main" or (
                source_ref.startswith("pr/") and source_ref[3:].isdigit()
                and not source_ref[3:].startswith("0")))):
        raise Hold("invalid_source_for_existing_ordinary_readback")
    root = claims.checked_fleet_root(fleet_root)
    db_path = root / "fleet.sqlite3"
    if (db_path.is_symlink() or not db_path.is_file()
            or db_path.stat().st_uid != os.getuid()):
        raise Hold("unsafe_existing_fleet_readback_queue")
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=3) as db:
        # Count all matching attempts, including failed and still-running
        # duplicates. Filtering only successes can hide ambiguous admission.
        rows = db.execute(
            "SELECT id,state,outcome FROM jobs WHERE repo=? AND sha=? AND ref=? "
            "AND suite=? ORDER BY id DESC LIMIT 2",
            (routing.REPO, source_sha, source_ref, claims.SUITE),
        ).fetchall()
    if not rows:
        raise Hold("no_exact_authenticated_real_ordinary_execution")
    if len(rows) != 1:
        raise Hold("ambiguous_multiple_authenticated_ordinary_executions")
    if rows[0][1:] != ("completed", "success"):
        raise Hold("exact_authenticated_ordinary_execution_not_successful")
    # Do not swallow a failed provenance or step check just because another
    # historical fleet row happens to have completed successfully.
    return verify_existing_ordinary_job_receipts(
        fleet_root=root, fleet_job_id=rows[0][0],
        source_sha=source_sha, source_ref=source_ref)


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
        if len(linked) != 1:
            raise Hold("ambiguous_authenticated_ordinary_event_claims")
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
        # One fleet receipt can prove command execution but cannot establish
        # two independently scheduled, sandboxed workflow-job executions.
        # Keep the aggregate evidence available without an acceptance-shaped
        # field name that downstream reporting could count as 2/2.
        "verified_aggregate_command_steps": [
            {"workflow_job": key, "step": STEP_FOR_JOB[key],
             "fleet_job_id": fleet_job_id,
             "local_execution": "command_passed_in_shared_aggregate_fleet_job"}
            for key in sorted(expected)
        ],
        "aggregate_fleet_execution_id_count": 1,
        "independent_definition_execution_ids": [],
        "independent_definition_sandboxes_verified": 0,
        "accepted_independent_ordinary_jobs": 0,
        "acceptance_hold": "distinct_per_definition_job_ids_and_sandboxes_not_proven",
        "authenticated_event_claim_count": len(linked),
        "github_provider_check_independently_verified": False,
        "protected_codeql_satisfied": False,
    }


def verify_distinct_ordinary_definition_receipts(
    *, checkout: Path, fleet_root: Path, source_sha: str, source_ref: str,
    reviewed_controller_sha256: str,
) -> dict:
    """Accept only two independent, authenticated, terminal fleet sandboxes.

    Distinct command labels in one aggregate sandbox never satisfy this check.
    The reviewed controller digest, per-job sandbox identity and immutable
    receipt/log paths are mandatory; legacy receipts lacking them remain held.
    This function never writes to the local fleet or to a provider.
    """
    import direct_local_distinct_admission as split

    if (not routing.HEX40.fullmatch(source_sha)
            or not routing.HEX64.fullmatch(reviewed_controller_sha256)
            or not source_ref.startswith("pr/")
            or not source_ref[3:].isdigit()
            or source_ref[3:].startswith("0")):
        raise Hold("invalid_distinct_ordinary_acceptance_source_or_controller")
    root = claims.checked_fleet_root(fleet_root)
    controller_path = root / "fleet_ci.py"
    if (hashlib.sha256(_owner_file(controller_path, 262144)).hexdigest()
            != reviewed_controller_sha256):
        raise Hold("reviewed_fleet_controller_digest_mismatch")
    policy = _object_bytes(_owner_file(root / "fleet-policy.json", 262144))
    plan = routing.compile_plan(
        checkout, policy, commit=source_sha, hostname=os.uname().nodename)
    if plan["summary"]["mapped_to_existing_fleet"] != 2:
        raise Hold("split_execution_source_not_enrolled")
    requested = [{"job": job} for job in split.SPLIT]
    expected = split._split_policy(policy, requested)
    expected_by_suite = {spec["suite"]: spec for spec in expected}
    db_path = root / "fleet.sqlite3"
    if (db_path.is_symlink() or not db_path.is_file()
            or db_path.stat().st_uid != os.getuid()):
        raise Hold("unsafe_distinct_execution_queue")
    verified = []
    receipt_paths = set()
    log_paths = set()
    physical_container_ids = set()
    with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=3) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT * FROM jobs WHERE repo=? AND sha=? AND ref=?",
            (routing.REPO, source_sha, source_ref)).fetchall()
        # Unknown/legacy suites and duplicate attempts on this source are
        # ambiguous, even if the two expected jobs happen to be successful.
        if len(rows) != 2 or {r["suite"] for r in rows} != set(expected_by_suite):
            raise Hold("unrecognised_or_ambiguous_distinct_fleet_execution")
        observations = db.execute(
            "SELECT key,value FROM observations WHERE key LIKE "
            "'direct-local-distinct:%' LIMIT 2049").fetchall()
        if len(observations) > 2048:
            raise Hold("unbounded_distinct_delivery_provenance")
        matching = []
        ids = {r["id"] for r in rows}
        for record in observations:
            data = _object_bytes(record["value"].encode("utf-8"))
            entries = data.get("jobs")
            if not isinstance(entries, list):
                raise Hold("malformed_distinct_delivery_provenance")
            if ids.intersection(
                    e.get("job_id") for e in entries if isinstance(e, dict)):
                matching.append(data)
        if len(matching) != 1:
            raise Hold("missing_or_ambiguous_distinct_delivery_claim")
        claim = matching[0]
        if (claim.get("source_sha") != source_sha
                or claim.get("ref") != source_ref
                or claim.get("event") != "pull_request"
                or claim.get("proof_kind") !=
                "authenticated_distinct_admission_not_execution"
                or any(not isinstance(claim.get(k), str)
                       or not routing.HEX64.fullmatch(claim[k])
                       for k in ("intent_identity_sha256", "delivery_sha256"))):
            raise Hold("untrusted_distinct_execution_event_claim")
        entries = claim["jobs"]
        if len(entries) != 2 or not all(isinstance(e, dict) for e in entries):
            raise Hold("partial_or_invalid_distinct_execution_provenance")
        for row in rows:
            if (not isinstance(row["id"], str) or not claims.ID.fullmatch(row["id"])
                    or row["state"] != "completed" or row["outcome"] != "success"
                    or type(row["attempt"]) is not int or row["attempt"] != 1):
                raise Hold("distinct_execution_not_terminal_first_attempt")
            spec = expected_by_suite[row["suite"]]
            related = [e for e in entries
                       if e.get("job_id") == row["id"]
                       and e.get("suite") == spec["suite"]
                       and e.get("policy") == spec["policy"]
                       and e.get("workflow_job") == spec["workflow_job"]]
            if len(related) != 1 or row["policy"] != spec["policy"]:
                raise Hold("distinct_job_policy_or_identity_mismatch")
            receipt_path = root / "evidence" / "fleet" / (row["id"] + ".json")
            log_path = root / "logs" / "fleet" / (row["id"] + ".log")
            if row["receipt"] != str(receipt_path):
                raise Hold("foreign_distinct_fleet_receipt")
            raw = _owner_file(receipt_path, MAX_RECEIPT)
            receipt = _object_bytes(raw)
            log = _owner_file(log_path, MAX_LOG)
            if (any(receipt.get(k) != row[k] for k in
                    ("id", "repo", "sha", "suite", "ref", "policy", "attempt"))
                    or receipt.get("outcome") != "success"
                    or receipt.get("mode") != "local-scheduler-not-github-actions"
                    or receipt.get("controller_sha256") != reviewed_controller_sha256
                    or receipt.get("executor") != "web/docker"
                    or not receipt.get("started_at") or not receipt.get("finished_at")
                    or receipt.get("cleanup", {}).get("container_absent") is not True
                    or receipt.get("cleanup", {}).get(
                        "workspace_and_dependency_cache_removed") is not True
                    or receipt.get("sandbox_identity") != row["id"]
                    or not isinstance(receipt.get("engine_container_id"), str)
                    or not routing.HEX64.fullmatch(receipt["engine_container_id"])
                    or receipt.get("image") != policy["repositories"][
                        routing.REPO]["suites"][row["suite"]]["image"]
                    or receipt.get("isolation") !=
                        "unprivileged Docker container with no host socket or personal files"
                    or not isinstance(receipt.get("resource_limits"), dict)
                    or set(receipt["resource_limits"]) != {
                        "cpus", "memory_mib", "pids", "writable_mib",
                        "host_cpu_affinity"}
                    or any(receipt["resource_limits"].get(field) !=
                           policy["repositories"][routing.REPO][
                               "suites"][row["suite"]][field]
                           for field in ("cpus", "memory_mib", "pids", "writable_mib"))
                    or not isinstance(
                        receipt["resource_limits"].get("host_cpu_affinity"), list)
                    or len(receipt["resource_limits"]["host_cpu_affinity"]) !=
                        receipt["resource_limits"]["cpus"]
                    or any(type(core) is not int or core < 0 for core in
                           receipt["resource_limits"]["host_cpu_affinity"])
                    or len(set(receipt["resource_limits"][
                        "host_cpu_affinity"])) !=
                        len(receipt["resource_limits"]["host_cpu_affinity"])
                    or receipt.get("log_bytes") != len(log)
                    or receipt.get("log_sha256") != hashlib.sha256(log).hexdigest()):
                raise Hold("incomplete_distinct_sandbox_or_log_receipt")
            steps = receipt.get("steps")
            commands = [*split.SETUP, (
                split.TERMINAL_NAME[spec["workflow_job"]],
                split.SPLIT[spec["workflow_job"]][1])]
            if (not isinstance(steps, list) or len(steps) != 4
                    or any(not isinstance(step, dict)
                           or step.get("name") != label
                           or step.get("command") != command
                           or type(step.get("exit_code")) is not int
                           or step["exit_code"] != 0
                           for step, (label, command) in zip(steps[1:], commands))):
                raise Hold("distinct_sandbox_command_execution_unverified")
            initial = steps[0]
            if (not isinstance(initial, dict)
                    or initial.get("name") != "Exact commit checkout"
                    or initial.get("exit_code") != 0
                    or not isinstance(initial.get("command"), str)
                    or f"fetch --quiet --depth=1 origin {source_sha}"
                       not in initial["command"]
                    or "git checkout --quiet --detach FETCH_HEAD"
                       not in initial["command"]):
                raise Hold("distinct_sandbox_checkout_not_source_bound")
            if (receipt_path in receipt_paths or log_path in log_paths
                    or receipt["engine_container_id"] in physical_container_ids):
                raise Hold("shared_distinct_fleet_sandbox_or_proof")
            receipt_paths.add(receipt_path)
            log_paths.add(log_path)
            physical_container_ids.add(receipt["engine_container_id"])
            verified.append({
                "engine_container_id_sha256": hashlib.sha256(
                    receipt["engine_container_id"].encode()).hexdigest(),
                "workflow_job": spec["workflow_job"],
                "fleet_job_id": row["id"],
                "sandbox_identity": receipt["sandbox_identity"],
                "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                "log_sha256": hashlib.sha256(log).hexdigest(),
            })
    if len({v["sandbox_identity"] for v in verified}) != 2:
        raise Hold("distinct_workflow_jobs_share_sandbox_identity")
    return {
        "schema": "clawsweeper.distinct-real-local-ordinary-readback.v1",
        "source_sha": source_sha,
        "source_ref": source_ref,
        "independent_definition_jobs": sorted(
            verified, key=lambda item: item["workflow_job"]),
        "accepted_independent_ordinary_jobs": 2,
        "github_provider_checks_verified": False,
        "protected_codeql_satisfied": False,
    }
