#!/usr/bin/env python3
"""Source-only, fail-closed per-definition admission into the ONE existing fleet.

This entry point is NOT installed or called by the live controller. It only
uses the existing control.lock, SQLite jobs and observations. Each ordinary
workflow definition needs a separately reviewed suite, job ID and sandbox.
It never reinterprets the historical aggregate run as two executed jobs.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

import direct_local_fleet_claim as fleet
import direct_local_event_admission as events
import direct_local_workflow as router
from estate_policy import Hold

SPLIT = {
    ".github/workflows/ci.yml#check": ("linux-node24-claw-check", "pnpm run check"),
    ".github/workflows/ci.yml#sparse-repair-builds": (
        "linux-node24-claw-sparse", "pnpm run test:workflow-sparse-checkout"),
}
SETUP = (
    ("Workflow semantic validation",
     """actionlint -shellcheck= -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml"""),
    ("Pinned pnpm dependency install", "pnpm install --frozen-lockfile"),
)
TERMINAL_NAME = {
    ".github/workflows/ci.yml#check": "Full repository validation",
    ".github/workflows/ci.yml#sparse-repair-builds": "Sparse repair checkout smoke",
}


def _split_policy(policy: dict, intents: list[dict]) -> list[dict]:
    """Review both definition-specific policy suites, even for a main push."""
    cfg = policy["repositories"][router.REPO]
    base = cfg["suites"]["linux-node24"]
    if (not isinstance(base, dict) or base.get("node") != "24"
            or not isinstance(base.get("image"), str)
            or not router.HEX64.fullmatch(base["image"].removeprefix("sha256:"))
            or not base["image"].startswith("sha256:")
            or any(type(base.get(field)) is not int or base[field] < 1
                   for field in ("cpus", "memory_mib", "pids", "writable_mib"))
            or not isinstance(base.get("execution_environment_revision"), str)
            or not base["execution_environment_revision"]):
        raise Hold("base_ordinary_sandbox_profile_untrusted")
    if set(SPLIT) != set(router.ORDINARY):
        raise Hold("ordinary_split_source_mapping_changed")
    profiles = {}
    for definition, (suite_name, final_cmd) in SPLIT.items():
        spec = cfg["suites"].get(suite_name)
        if not isinstance(spec, dict):
            raise Hold("independent_definition_fleet_suite_not_installed")
        # Require the same immutable image and resource boundaries as the
        # existing tested aggregate profile. No mutable commands/credentials.
        fields = ("node", "image", "cpus", "memory_mib", "pids",
                  "writable_mib", "execution_environment_revision")
        if (set(spec) != {*fields, "steps"}
                or any(spec.get(field) != base.get(field) for field in fields)):
            raise Hold("independent_definition_resource_or_image_drift")
        expected_steps = (*SETUP, (TERMINAL_NAME[definition], final_cmd))
        steps = spec.get("steps")
        if (not isinstance(steps, list) or len(steps) != 3
                or any(not isinstance(step, dict)
                       or set(step) != {"name", "command", "timeout"}
                       or step.get("name") != name
                       or step.get("command") != command
                       or type(step.get("timeout")) is not int
                       or not 1 <= step["timeout"] <= 1800
                       for step, (name, command) in zip(steps, expected_steps))):
            raise Hold("independent_definition_command_contract_drift")
        profiles[definition] = {
            "workflow_job": definition,
            "suite": suite_name,
            "policy": hashlib.sha256(json.dumps({
                "version": policy["version"], "suite": spec,
                "contract": cfg["contract"], "image": policy["image"],
                "node_versions": policy["node_versions"],
            }, sort_keys=True).encode()).hexdigest(),
        }
    keys = [item["job"] for item in intents]
    if not keys or len(keys) != len(set(keys)) or not set(keys) <= set(SPLIT):
        raise Hold("invalid_authenticated_ordinary_split_intents")
    return [profiles[name] for name in keys]


def propose_split_fleet_policy(*, checkout: Path, policy: dict,
                               commit: str, hostname: str) -> dict:
    """Pure in-memory policy proposal for the SAME installed fleet, not rollout.

    Bind every command to the existing trusted four-step aggregate contract.
    Never infer a new command, image, credential, worker or resource allowance.
    The caller must separately authorise an exact policy/controller installation.
    """
    if not isinstance(policy, dict) or not isinstance(policy.get("repositories"), dict):
        raise Hold("invalid_existing_fleet_policy")
    plan = router.compile_plan(checkout, policy, commit=commit, hostname=hostname)
    if plan["summary"]["mapped_to_existing_fleet"] != 2:
        raise Hold("source_is_not_enrolled_for_existing_fleet")
    cfg = policy["repositories"][router.REPO]
    suites = cfg["suites"]
    base = suites.get("linux-node24")
    fields = ("node", "image", "cpus", "memory_mib", "pids",
              "writable_mib", "execution_environment_revision")
    if not isinstance(base, dict) or set(base) != {*fields, "steps"}:
        raise Hold("unreviewed_aggregate_fleet_profile")
    steps = base["steps"]
    expected = (*SETUP,
                (TERMINAL_NAME[".github/workflows/ci.yml#check"],
                 SPLIT[".github/workflows/ci.yml#check"][1]),
                (TERMINAL_NAME[".github/workflows/ci.yml#sparse-repair-builds"],
                 SPLIT[".github/workflows/ci.yml#sparse-repair-builds"][1]))
    if (not isinstance(steps, list) or len(steps) != len(expected)
            or any(not isinstance(step, dict)
                   or set(step) != {"name", "command", "timeout"}
                   or step.get("name") != label
                   or step.get("command") != command
                   or type(step.get("timeout")) is not int
                   or not 1 <= step["timeout"] <= 1800
                   for step, (label, command) in zip(steps, expected))):
        raise Hold("aggregate_commands_do_not_match_source_review")
    present = set(suites).intersection(suite for suite, _ in SPLIT.values())
    expected_suites = {suite for suite, _ in SPLIT.values()}
    if present and present != expected_suites:
        raise Hold("preexisting_split_suite_differs_from_reviewed_source")
    candidate = copy.deepcopy(policy)
    candidate_suites = candidate["repositories"][router.REPO]["suites"]
    for i, (_definition, (suite, _)) in enumerate(SPLIT.items()):
        proposed = {field: copy.deepcopy(base[field]) for field in fields}
        proposed["steps"] = [copy.deepcopy(step) for step in
                             (steps[0], steps[1], steps[i + 2])]
        if suite in candidate_suites and candidate_suites[suite] != proposed:
            raise Hold("preexisting_split_suite_differs_from_reviewed_source")
        candidate_suites[suite] = proposed
    verified = _split_policy(candidate, [{"job": name} for name in SPLIT])
    canonical = lambda data: json.dumps(data, sort_keys=True,
                                        separators=(",", ":")).encode()
    return {
        "schema": "clawsweeper.source-only-split-policy-proposal.v1",
        "source_sha": commit,
        "original_policy_sha256": hashlib.sha256(canonical(policy)).hexdigest(),
        "proposed_policy_sha256": hashlib.sha256(canonical(candidate)).hexdigest(),
        "proposed_policy": candidate,
        "suites": verified,
        "installed": False,
        "admitted": False,
        "executed": False,
        "accepted": 0,
    }


def claim_distinct_existing_fleet_jobs(
    *, checkout: Path, fleet_root: Path, body: bytes, event_name: str,
    signature: str, delivery_id: str, secret: bytes, fresh_ref_sha: str,
) -> dict:
    """Atomically claim 1 main or 2 PR definition jobs; never execute either.

    Requires genuinely authenticated GitHub event and fresh source GET supplied
    by the already-reviewed caller, plus an owner-installed exact split policy.
    This uninstalled source does not authorise a production policy change.
    """
    root = fleet.checked_fleet_root(fleet_root)
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Hold("existing_fleet_owner_is_active") from exc
        policy_file = root / "fleet-policy.json"
        if policy_file.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise Hold("writable_existing_fleet_policy")
        policy = json.loads(policy_file.read_text())
        plan = router.compile_plan(checkout, policy, commit=fresh_ref_sha,
                                   hostname=os.uname().nodename)
        intent = events.verified_ordinary_intents(
            plan, body=body, event_name=event_name, signature=signature,
            delivery_id=delivery_id, secret=secret, fresh_ref_sha=fresh_ref_sha)
        suites = _split_policy(policy, intent["intents"])
        key_digest = hashlib.sha256(
            (router.REPO + "\n" + delivery_id.lower()).encode("ascii")).hexdigest()
        key = "direct-local-distinct:" + key_digest
        legacy_key = "direct-local:" + key_digest
        uri = (root / "fleet.sqlite3").as_uri() + "?mode=rw"
        with sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None) as db:
            db.row_factory = sqlite3.Row
            fleet._queue_schema(db)
            try:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM observations WHERE key=?",
                              (legacy_key,)).fetchone():
                    raise Hold("legacy_aggregate_delivery_identity_collision")
                if db.execute(
                    "SELECT 1 FROM jobs WHERE repo=? AND sha=? AND suite=?",
                    (router.REPO, fresh_ref_sha, fleet.SUITE)).fetchone():
                    raise Hold("aggregate_execution_must_not_be_relabelled")
                prior = db.execute("SELECT value FROM observations WHERE key=?",
                                   (key,)).fetchone()
                if prior:
                    try:
                        observed = json.loads(prior["value"])
                    except (TypeError, ValueError) as exc:
                        raise Hold("corrupt_independent_delivery_record") from exc
                    if (not isinstance(observed, dict)
                            or any(observed.get(k) != v for k, v in (
                                ("source_sha", fresh_ref_sha),
                                ("ref", intent["source_ref"]),
                                ("event", event_name),
                                ("intent_identity_sha256", intent["intent_identity_sha256"]),
                                ("delivery_sha256", intent["delivery_sha256"]),
                                ("proof_kind", "authenticated_distinct_admission_not_execution")))
                            or not isinstance(observed.get("jobs"), list)
                            or len(observed["jobs"]) != len(suites)):
                        raise Hold("changed_signed_distinct_delivery_identity")
                    records = observed["jobs"]
                    if any(record.get("workflow_job") != spec["workflow_job"]
                           or record.get("suite") != spec["suite"]
                           or record.get("policy") != spec["policy"]
                           or not isinstance(record.get("job_id"), str)
                           or not fleet.ID.fullmatch(record["job_id"])
                           for record, spec in zip(records, suites)):
                        raise Hold("corrupt_independent_delivery_job_mapping")
                    for record in records:
                        row = db.execute(
                            "SELECT repo,sha,ref,suite,policy FROM jobs WHERE id=?",
                            (record["job_id"],)).fetchone()
                        if (row is None or tuple(row) != (
                                router.REPO, fresh_ref_sha, intent["source_ref"],
                                record["suite"], record["policy"])):
                            raise Hold("orphaned_or_relabelled_independent_fleet_job")
                    admission = "already_admitted"
                else:
                    # A different delivery may never relabel an existing job
                    # as this source's independently authenticated execution.
                    if any(db.execute(
                        "SELECT 1 FROM jobs WHERE repo=? AND sha=? AND suite=?",
                        (router.REPO, fresh_ref_sha, spec["suite"])).fetchone()
                           for spec in suites):
                        raise Hold("foreign_independent_execution_claim_exists")
                    now = datetime.now(timezone.utc).isoformat()
                    records = []
                    for spec in suites:
                        job_id = "local-fleet-" + uuid.uuid4().hex[:12]
                        if not fleet.ID.fullmatch(job_id):
                            raise Hold("unsafe_existing_fleet_job_id")
                        db.execute(
                            "INSERT INTO jobs(id,repo,sha,suite,policy,ref,created_at,updated_at) "
                            "VALUES(?,?,?,?,?,?,?,?)",
                            (job_id, router.REPO, fresh_ref_sha, spec["suite"],
                             spec["policy"], intent["source_ref"], now, now))
                        records.append({**spec, "job_id": job_id})
                    db.execute(
                        "INSERT INTO observations(key,value,updated_at) VALUES(?,?,?)",
                        (key, json.dumps({
                            "source_sha": fresh_ref_sha, "ref": intent["source_ref"],
                            "event": event_name,
                            "intent_identity_sha256": intent["intent_identity_sha256"],
                            "delivery_sha256": intent["delivery_sha256"],
                            "proof_kind": "authenticated_distinct_admission_not_execution",
                            "jobs": records,
                        }, sort_keys=True), now))
                    admission = "queued"
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {
            "schema": "clawsweeper.existing-fleet-distinct-ordinary-claim.v1",
            "source_sha": fresh_ref_sha, "ref": intent["source_ref"],
            "jobs": records, "admission": admission,
            "queue_admitted": admission == "queued",
            "independent_jobs_executed": 0, "accepted_independent_jobs": 0,
            "github_actions_dispatched": False,
            "github_status_published": False,
        }
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
