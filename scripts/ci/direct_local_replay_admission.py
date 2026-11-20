#!/usr/bin/env python3
"""One owner-signed offline replay admission to the EXISTING durable local fleet.

Source-only until an exact signed fleet release wires the new ref into the
controller, detached worker and local-only publisher. Never dispatch Actions.
"""
from __future__ import annotations

import base64
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
import direct_local_manual_auth as auth
import direct_local_replay_release_contract as contract
import direct_local_offline_replay_suite as suite
import direct_local_workflow as estate
from estate_policy import Hold

REPO = estate.REPO
REF = contract.REF
JOB = contract.JOB
SUITE = suite.SUITE
PREFIX = "direct-local-manual-replay:"
OLD_PREFIX = "direct-local-manual-split:"
PROOF = "owner_signed_single_replay_queue_admission_not_execution"
SCHEMA = "clawsweeper.existing-fleet-single-replay-claim.v1"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _policy_hash(policy: dict) -> str:
    """Match fleet_ci.policy_hash on the public ClawSweeper suite exactly."""
    cfg = policy["repositories"][REPO]
    return hashlib.sha256(json.dumps({
        "version": policy["version"], "suite": cfg["suites"][SUITE],
        "contract": cfg["contract"], "image": policy["image"],
        "node_versions": policy["node_versions"],
    }, sort_keys=True).encode()).hexdigest()


def _checked_policy(root: Path) -> dict:
    data = auth.owner_bytes(root / "fleet-policy.json", 262144, private=False)
    return json.loads(data, object_pairs_hook=auth.unique_object)


def _review_runtime(checkout: Path, policy: dict, source_sha: str) -> str:
    """Source and installed candidate must be exactly the reviewed main suite."""
    if os.getuid() != 1000 or os.uname().nodename != "web":
        raise Hold("replay_wrong_execution_host")
    if not isinstance(policy, dict) or not isinstance(source_sha, str):
        raise Hold("replay_missing_runtime_policy")
    cfg = policy.get("repositories", {}).get(REPO, {})
    if (policy.get("execution_hosts", {}).get(REPO) != "web"
            or cfg.get("branch") != "main"
            or cfg.get("enrolled_head") != source_sha
            or cfg.get("source_workflow", ".github/workflows/ci.yml")
               != ".github/workflows/ci.yml"):
        raise Hold("replay_policy_not_exact_enrolled_main")
    installed = cfg.get("suites", {})
    if not isinstance(installed, dict) or SUITE not in installed:
        raise Hold("replay_suite_not_installed")
    if any(key not in installed for key in
           ("linux-node24-claw-check", "linux-node24-claw-sparse")):
        raise Hold("replay_original_two_suites_missing")
    staging = copy.deepcopy(policy)
    staging["repositories"][REPO]["suites"].pop(SUITE)
    proposed = suite.prepare(checkout, staging)
    if proposed["candidate_source_sha"] != source_sha:
        raise Hold("replay_checkout_not_exact_enrolled_main")
    if installed[SUITE] != proposed["suite"]:
        raise Hold("replay_installed_suite_differs_from_review")
    return _policy_hash(policy)


def _nonce_key(doc: dict) -> str:
    digest = hashlib.sha256((REPO + "\n" + doc["nonce"]).encode("ascii"))
    return digest.hexdigest()


def _verified_envelope(evidence: dict, key: str, expected_sha: str) -> dict:
    try:
        if set(evidence) != {
            "proof_kind", "repo", "source_sha", "source_ref", "ref",
            "event", "job_intents", "jobs", "request_sha256",
            "owner_principal", "signed_request_b64",
            "signed_request_signature_b64",
        }:
            raise ValueError("unexpected replay evidence shape")
        raw = base64.b64decode(evidence["signed_request_b64"], validate=True)
        sig = base64.b64decode(
            evidence["signed_request_signature_b64"], validate=True)
        if len(raw) > 4096 or len(sig) > 8192:
            raise ValueError("oversized replay envelope")
        original = json.loads(raw, object_pairs_hook=auth.unique_object)
        if type(original.get("issued_at")) is not int:
            raise ValueError("missing replay issue time")
        doc = contract.parse_intent(raw, now=original["issued_at"])
    except (TypeError, ValueError, KeyError, UnicodeError, OverflowError) as exc:
        raise Hold("replay_admitted_envelope_invalid") from exc
    if (evidence["proof_kind"] != PROOF or evidence["repo"] != REPO
            or evidence["source_sha"] != expected_sha
            or evidence["source_ref"] != "main"
            or evidence["ref"] != REF or evidence["event"] != REF
            or evidence["job_intents"] != [JOB]
            or evidence["owner_principal"] != auth.PRINCIPAL
            or evidence["request_sha256"] != hashlib.sha256(raw).hexdigest()
            or doc["source_sha"] != expected_sha
            or key != PREFIX + _nonce_key(doc)):
        raise Hold("replay_admitted_envelope_drift")
    contract.verify_owner_intent(raw, sig)
    return doc


def _checked_row(db: sqlite3.Connection, evidence: dict, policy: dict,
                 source_sha: str, job_id: str | None = None) -> dict:
    entries = evidence.get("jobs")
    if not isinstance(entries, list) or len(entries) != 1:
        raise Hold("replay_not_one_distinct_job")
    item = entries[0]
    expected_hash = _policy_hash(policy)
    if (not isinstance(item, dict)
            or set(item) != {"workflow_job", "job_id", "suite", "policy"}
            or item["workflow_job"] != JOB or item["suite"] != SUITE
            or not isinstance(item["job_id"], str)
            or not fleet.ID.fullmatch(item["job_id"])
            or item["policy"] != expected_hash
            or (job_id is not None and item["job_id"] != job_id)):
        raise Hold("replay_job_identity_or_policy_changed")
    row = db.execute(
        "SELECT repo,sha,ref,suite,policy,state FROM jobs WHERE id=?",
        (item["job_id"],)).fetchone()
    if (row is None or row["repo"] != REPO or row["sha"] != source_sha
            or row["ref"] != REF or row["suite"] != SUITE
            or row["policy"] != expected_hash
            or row["state"] not in ("queued", "claimed", "running", "completed")):
        raise Hold("replay_queue_row_missing_or_relabelled")
    return item


def claim_owner_signed_replay(*, checkout: Path, fleet_root: Path,
                              request_file: Path, signature_file: Path) -> dict:
    """One ACID insert under the existing control.lock; never execute a job."""
    root = fleet.checked_fleet_root(fleet_root)
    raw = auth.owner_bytes(request_file, 4096)
    sig = auth.owner_bytes(signature_file, 8192)
    doc = contract.parse_intent(raw)
    contract.verify_owner_intent(raw, sig)
    fd = os.open(root / "control.lock",
                 os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    locked = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise Hold("replay_existing_fleet_owner_active") from exc
        policy = _checked_policy(root)
        # Fresh provider GET is inside lock; no stale preflight can admit work.
        current_main = contract.read_fresh_main_sha()
        if doc["source_sha"] != current_main:
            raise Hold("replay_signed_source_no_longer_main")
        reviewed_hash = _review_runtime(checkout, policy, current_main)
        uri = (root / "fleet.sqlite3").as_uri() + "?mode=rw"
        with sqlite3.connect(uri, uri=True, timeout=3,
                             isolation_level=None) as db:
            db.row_factory = sqlite3.Row
            fleet._queue_schema(db)
            db.execute("BEGIN IMMEDIATE")
            try:
                key = PREFIX + _nonce_key(doc)
                if db.execute("SELECT 1 FROM observations WHERE key=?",
                              (OLD_PREFIX + _nonce_key(doc),)).fetchone():
                    raise Hold("replay_reuses_prior_split_owner_nonce")
                prior = db.execute(
                    "SELECT value FROM observations WHERE key=?", (key,)
                ).fetchone()
                if prior is not None:
                    prior_doc = json.loads(
                        prior["value"], object_pairs_hook=auth.unique_object)
                    _verified_envelope(prior_doc, key, current_main)
                    if prior_doc["request_sha256"] != hashlib.sha256(raw).hexdigest():
                        raise Hold("replay_nonce_reused_with_changed_intent")
                    entry = _checked_row(db, prior_doc, policy, current_main)
                    admission = "already_admitted"
                else:
                    # Never rebrand a pre-existing job as newly owner-signed.
                    if db.execute(
                        "SELECT 1 FROM jobs WHERE repo=? AND sha=? AND suite=?",
                        (REPO, current_main, SUITE)).fetchone():
                        raise Hold("replay_existing_unrelated_job_claim")
                    ident = "local-fleet-" + uuid.uuid4().hex[:12]
                    if not fleet.ID.fullmatch(ident):
                        raise Hold("replay_invalid_generated_job_id")
                    stamp = datetime.now(timezone.utc).isoformat()
                    db.execute(
                        "INSERT INTO jobs(id,repo,sha,suite,policy,ref,"
                        "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        (ident, REPO, current_main, SUITE, reviewed_hash,
                         REF, stamp, stamp))
                    entry = {"workflow_job": JOB, "job_id": ident,
                             "suite": SUITE, "policy": reviewed_hash}
                    evidence = {
                        "proof_kind": PROOF, "repo": REPO,
                        "source_sha": current_main, "source_ref": "main",
                        "ref": REF, "event": REF, "job_intents": [JOB],
                        "jobs": [entry],
                        "request_sha256": hashlib.sha256(raw).hexdigest(),
                        "owner_principal": auth.PRINCIPAL,
                        "signed_request_b64": base64.b64encode(raw).decode(),
                        "signed_request_signature_b64":
                            base64.b64encode(sig).decode(),
                    }
                    db.execute(
                        "INSERT INTO observations(key,value,updated_at)"
                        " VALUES(?,?,?)",
                        (key, json.dumps(evidence, sort_keys=True), stamp))
                    admission = "queued"
                db.commit()
            except BaseException:
                db.rollback()
                raise
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return {"schema": SCHEMA, "source_sha": current_main,
            "ref": REF, "job_intents": [JOB], "jobs": [entry],
            "admission": admission, "queue_admitted": admission == "queued",
            "runner_started": False, "jobs_executed": 0,
            "github_actions_dispatched": False,
            "github_provider_status_published": False}


def verify_existing_replay(*, checkout: Path, fleet_root: Path,
                           job_id: str) -> dict:
    """Detached worker read-only proof before start, container and report."""
    if not isinstance(job_id, str) or not fleet.ID.fullmatch(job_id):
        raise Hold("replay_invalid_worker_job_id")
    root = fleet.checked_fleet_root(fleet_root)
    policy = _checked_policy(root)
    source_sha = policy["repositories"][REPO]["enrolled_head"]
    _review_runtime(checkout, policy, source_sha)
    if contract.read_fresh_main_sha() != source_sha:
        raise Hold("replay_source_changed_before_worker_start")
    uri = (root / "fleet.sqlite3").as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=3) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        matches = []
        rows = db.execute(
            "SELECT key,value FROM observations WHERE key LIKE ? LIMIT 2049",
            (PREFIX + "%",)).fetchall()
        if len(rows) > 2048:
            raise Hold("replay_evidence_count_unbounded")
        for row in rows:
            evidence = json.loads(row["value"], object_pairs_hook=auth.unique_object)
            entries = evidence.get("jobs") if isinstance(evidence, dict) else None
            if (isinstance(entries, list) and len(entries) == 1
                    and isinstance(entries[0], dict)
                    and entries[0].get("job_id") == job_id):
                matches.append((row["key"], evidence))
        if len(matches) != 1:
            raise Hold("replay_missing_or_ambiguous_signed_claim")
        key, evidence = matches[0]
        _verified_envelope(evidence, key, source_sha)
        _checked_row(db, evidence, policy, source_sha, job_id)
        state = db.execute("SELECT state FROM jobs WHERE id=?",
                           (job_id,)).fetchone()["state"]
        db.rollback()
    return {"schema": SCHEMA, "job_id": job_id, "source_sha": source_sha,
            "ref": REF, "queue_state": state,
            "request_sha256": evidence["request_sha256"],
            "verified_owner_origin": True,
            "provider_status_authorised": False,
            "github_actions_admission_authorised": False}
