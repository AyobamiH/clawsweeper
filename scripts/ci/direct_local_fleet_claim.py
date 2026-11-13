#!/usr/bin/env python3
"""Fail-closed authenticated event admission into the EXISTING local CI SQLite queue.

No second queue, executor, GitHub Actions dispatch, provider effect or new job
definition. This is a source-only integration point until the fleet owner
authorises an exact-source release and calls it under the canonical fleet lock.
"""
from __future__ import annotations

import fcntl
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

import direct_local_event_admission as events
import direct_local_workflow as routing
from estate_policy import Hold

REPO = routing.REPO
SUITE = "linux-node24"
ID = re.compile(r"local-fleet-[0-9a-f]{12}\Z")
REQUIRED_JOB_COLUMNS = frozenset({
    "id", "repo", "sha", "suite", "policy", "ref", "state", "attempt",
    "ready_at", "created_at", "updated_at", "outcome", "receipt", "reported"
})
REQUIRED_OBSERVATION_COLUMNS = frozenset({"key", "value", "updated_at"})


def reviewed_policy_hash(policy: dict) -> str:
    """Match fleet_ci.policy_hash's canonical suite schema, not its secrets."""
    cfg = policy["repositories"][REPO]
    spec = {
        "version": policy["version"],
        "suite": cfg["suites"][SUITE],
        "contract": cfg["contract"],
        "image": policy["image"],
        "node_versions": policy["node_versions"],
    }
    return hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()


def checked_fleet_root(root: Path) -> Path:
    """A pre-existing owner-marked fleet; never initialise a second one."""
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise Hold("unsafe_existing_fleet_root")
    if root.stat().st_uid != os.getuid():
        raise Hold("foreign_fleet_owner")
    for name in ("OWNED_BY_LOCAL_CI", "fleet-policy.json",
                 "fleet.sqlite3", "control.lock"):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise Hold("existing_fleet_file_missing_or_symlinked")
        if path.stat().st_uid != os.getuid():
            raise Hold("foreign_fleet_file_owner")
    return root


def _queue_schema(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
        raise Hold("existing_queue_not_durable_wal")
    for table, required in (
        ("jobs", REQUIRED_JOB_COLUMNS), ("observations", REQUIRED_OBSERVATION_COLUMNS)
    ):
        cols = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        if not required <= cols:
            raise Hold("unrecognised_existing_fleet_queue_schema")


def claim_existing_fleet_delivery(
    *, checkout: Path, fleet_root: Path, body: bytes, event_name: str,
    signature: str, delivery_id: str, secret: bytes, fresh_ref_sha: str,
) -> dict:
    """Durably admit at most one reviewed ordinary fleet suite for an event.

    Caller must obtain fresh provider ref readback independently. Under the
    existing fleet's EXCLUSIVE control.lock, re-evaluate the exact 41/88 source,
    policy and HMAC before one transaction. A simultaneous poller may already
    have admitted the same suite; its job is NEVER duplicated or re-labelled.
    No raw webhook body or secret is stored in the queue.
    """
    root = checked_fleet_root(fleet_root)
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Hold("existing_fleet_owner_is_active") from exc
        policy_path = root / "fleet-policy.json"
        if policy_path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise Hold("writable_existing_fleet_policy")
        policy = json.loads(policy_path.read_text())
        plan = routing.compile_plan(checkout, policy, commit=fresh_ref_sha,
                                    hostname=os.uname().nodename)
        intent = events.verified_ordinary_intents(
            plan, body=body, event_name=event_name, signature=signature,
            delivery_id=delivery_id, secret=secret, fresh_ref_sha=fresh_ref_sha)
        if (not intent["intents"]
                or {i["suite"] for i in intent["intents"]} != {SUITE}
                or any(i["job"] not in routing.ORDINARY for i in intent["intents"])):
            raise Hold("unrecognised_existing_fleet_ordinary_intent")
        policy_sha = reviewed_policy_hash(policy)
        uri = (root / "fleet.sqlite3").as_uri() + "?mode=rw"
        with sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None) as db:
            db.row_factory = sqlite3.Row
            _queue_schema(db)
            try:
                db.execute("BEGIN IMMEDIATE")
                # One delivery UUID has one immutable authenticated identity.
                # The event/commit-dependent intent digest is unsuitable as the
                # dedup key: a recycled signed UUID could otherwise claim a new
                # source/event before the receiver's ledger can reconcile it.
                key = "direct-local:" + hashlib.sha256(
                    (REPO + "\\n" + delivery_id.lower()).encode("ascii")
                ).hexdigest()
                prior = db.execute(
                    "SELECT value FROM observations WHERE key=?", (key,)
                ).fetchone()
                if prior:
                    try:
                        previous = json.loads(prior["value"])
                    except (ValueError, TypeError) as exc:
                        raise Hold("unreadable_existing_delivery_identity") from exc
                    if (previous.get("delivery_sha256") != intent["delivery_sha256"]
                            or previous.get("source_sha") != fresh_ref_sha
                            or previous.get("ref") != intent["source_ref"]
                            or previous.get("event") != event_name
                            or previous.get("intent_identity_sha256") !=
                            intent["intent_identity_sha256"]):
                        raise Hold("same_delivery_identity_with_changed_signed_payload")
                existing = db.execute(
                    "SELECT id,ref,state FROM jobs WHERE repo=? AND sha=? "
                    "AND suite=? AND policy=?",
                    (REPO, fresh_ref_sha, SUITE, policy_sha)).fetchone()
                if existing:
                    if existing["ref"] != intent["source_ref"]:
                        raise Hold("existing_suite_queued_under_different_event_ref")
                    if existing["state"] not in ("queued", "running", "completed"):
                        raise Hold("existing_suite_terminal_state_not_replayable")
                    job_id, admission = existing["id"], "already_admitted"
                else:
                    job_id = "local-fleet-" + uuid.uuid4().hex[:12]
                    if not ID.fullmatch(job_id):
                        raise Hold("unsafe_fleet_job_id")
                    now = datetime.now(timezone.utc).isoformat()
                    db.execute(
                        "INSERT INTO jobs (id,repo,sha,suite,policy,ref,created_at,"
                        "updated_at) VALUES (?,?,?,?,?,?,?,?)",
                        (job_id, REPO, fresh_ref_sha, SUITE, policy_sha,
                         intent["source_ref"], now, now))
                    admission = "queued"
                # Existing observations table: no new ledger/table or payload dump.
                summary = {
                    "source_sha": fresh_ref_sha, "ref": intent["source_ref"],
                    "event": event_name,
                    "intent_identity_sha256": intent["intent_identity_sha256"],
                    "suite": SUITE, "job_id": job_id, "state": admission,
                    "job_intents": [x["job"] for x in intent["intents"]],
                    "delivery_sha256": intent["delivery_sha256"],
                    "proof_kind": "authenticated_queue_admission_not_execution",
                }
                db.execute(
                    "INSERT INTO observations(key,value,updated_at) VALUES(?,?,?) "
                    "ON CONFLICT(key) DO NOTHING",
                    (key, json.dumps(summary, sort_keys=True),
                     datetime.now(timezone.utc).isoformat()))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {
            "schema": "clawsweeper.local-ordinary-existing-fleet-claim.v1",
            "repo": REPO, "source_commit": fresh_ref_sha,
            "source_ref": intent["source_ref"], "event": event_name,
            "existing_fleet_job_id": job_id, "suite": SUITE,
            "job_intents": [x["job"] for x in intent["intents"]],
            "admission": admission, "queue_admitted": admission == "queued",
            "job_executed": False, "github_status_published": False,
            "intent_identity_sha256": intent["intent_identity_sha256"],
        }
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
