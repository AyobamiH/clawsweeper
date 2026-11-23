#!/usr/bin/env python3
"""Owner-signed, two-identity local-manual admission to the existing fleet.

Source-only: this file cannot activate the installed controller. The v3 release
must install a verified copy and call the authenticated entry point explicitly.
No GitHub Actions event, second controller, queue or provider status is created.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

import direct_local_manual_auth as auth
import direct_local_distinct_admission as distinct
import direct_local_fleet_claim as fleet
import direct_local_workflow as router
from estate_policy import Hold

SCHEMA = "clawsweeper.owner-signed-local-manual-request.v2-split"
CLAIM_SCHEMA = "clawsweeper.existing-fleet-local-manual-split-claim.v1"
PROOF = "owner_signed_distinct_manual_queue_admission_not_execution"
REF = "local-manual"
REPO = "AyobamiH/clawsweeper"
SUITE = "ordinary-split"
JOBS = tuple(distinct.SPLIT)
FIELDS = frozenset(("schema", "repo", "source_sha", "source_ref", "host",
                    "suite", "job_intents", "purpose", "nonce",
                    "issued_at", "expires_at"))
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
ID = re.compile(r"local-fleet-[a-f0-9]{12}\Z")
PREFIX = "direct-local-manual-split:"

def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

def parse_intent(raw: bytes, now: int) -> dict:
    try:
        doc = json.loads(raw, object_pairs_hook=auth.unique_object)
    except Hold:
        raise
    except (TypeError, UnicodeError, ValueError) as exc:
        raise Hold("invalid_split_manual_intent_json") from exc
    if (not isinstance(doc, dict) or set(doc) != FIELDS
            or doc["schema"] != SCHEMA or doc["repo"] != REPO
            or doc["source_ref"] != "develop"
            or doc["host"] != os.uname().nodename
            or doc["suite"] != SUITE
            or doc["purpose"] != "ordinary-source-validation"
            or not isinstance(doc["source_sha"], str)
            or not router.HEX40.fullmatch(doc["source_sha"])
            or type(doc["job_intents"]) is not list
            or doc["job_intents"] != list(JOBS)
            or type(doc["nonce"]) is not str
            or not HEX32.fullmatch(doc["nonce"])
            or type(doc["issued_at"]) is not int
            or type(doc["expires_at"]) is not int
            or doc["issued_at"] > now + 30
            or now - doc["issued_at"] > 900
            or doc["expires_at"] < now
            or not 0 < doc["expires_at"] - doc["issued_at"] <= 900):
        raise Hold("unapproved_split_manual_scope_or_freshness")
    return doc

def _observed_jobs(db, evidence: dict, policy: dict, expected_sha: str,
                   *, active_id: str | None = None) -> list[dict]:
    specs = distinct._split_policy(policy, [{"job": key} for key in JOBS])
    records = evidence.get("jobs")
    if not isinstance(records, list) or len(records) != 2:
        raise Hold("split_manual_missing_distinct_jobs")
    if set(item.get("suite") for item in specs) != set(
            item.get("suite") for item in records if isinstance(item, dict)):
        raise Hold("split_manual_job_suite_mismatch")
    verified = []
    ids = set()
    for spec, record in zip(specs, records):
        if (not isinstance(record, dict)
                or set(record) != {"workflow_job", "job_id", "suite", "policy"}
                or record["workflow_job"] != spec["workflow_job"]
                or record["suite"] != spec["suite"]
                or record["policy"] != spec["policy"]
                or not isinstance(record["job_id"], str)
                or not ID.fullmatch(record["job_id"])
                or record["job_id"] in ids):
            raise Hold("split_manual_sibling_identity_or_policy_mismatch")
        ids.add(record["job_id"])
        row = db.execute(
            "SELECT repo,sha,ref,suite,policy,state FROM jobs WHERE id=?",
            (record["job_id"],),
        ).fetchone()
        if (row is None or row["repo"] != REPO or row["sha"] != expected_sha
                or row["ref"] != REF or row["suite"] != spec["suite"]
                or row["policy"] != spec["policy"]
                or row["state"] not in ("queued", "claimed", "running", "completed")):
            raise Hold("split_manual_missing_or_changed_queue_row")
        verified.append(record)
    if active_id is not None and active_id not in ids:
        raise Hold("split_manual_job_not_in_signed_claim")
    return verified

def _verify_envelope(key: str, evidence: dict, expected_sha: str) -> None:
    try:
        raw = base64.b64decode(evidence["signed_request_b64"], validate=True)
        signature = base64.b64decode(
            evidence["signed_request_signature_b64"], validate=True)
        seed = json.loads(raw, object_pairs_hook=auth.unique_object)
        if (type(seed.get("issued_at")) is not int
                or len(raw) > 4096 or len(signature) > 8192):
            raise ValueError("invalid size or time")
        # An admitted signed request remains valid for a later queued execution;
        # its original admission expiry cannot be silently extended.
        doc = parse_intent(raw, seed["issued_at"])
    except (ValueError, KeyError, UnicodeError, TypeError, OverflowError) as exc:
        raise Hold("split_manual_signed_envelope_unavailable") from exc
    if (hashlib.sha256(raw).hexdigest() != evidence.get("request_sha256")
            or doc["source_sha"] != expected_sha
            or doc["job_intents"] != list(JOBS)
            or key != PREFIX + hashlib.sha256(
                (REPO + "\n" + doc["nonce"]).encode("ascii")).hexdigest()):
        raise Hold("split_manual_envelope_identity_mismatch")
    auth.verify_owner_signature_bytes(
        raw, signature, auth.owner_allowed_signers())

def verify_existing_split_manual_claim(*, fleet_root: Path,
                                       job_id: str) -> dict:
    """Read-only worker admission proof. Requires both genuine queue rows."""
    if not isinstance(job_id, str) or not ID.fullmatch(job_id):
        raise Hold("untrusted_split_manual_job_id")
    root = fleet.checked_fleet_root(fleet_root)
    policy = json.loads(auth.owner_bytes(
        root / "fleet-policy.json", 262144, private=False))
    cfg = policy.get("repositories", {}).get(REPO, {})
    source = cfg.get("enrolled_head")
    if (not isinstance(source, str) or not router.HEX40.fullmatch(source)
            or policy.get("execution_hosts", {}).get(REPO)
               != os.uname().nodename):
        raise Hold("split_manual_policy_host_or_source_mismatch")
    with sqlite3.connect((root / "fleet.sqlite3").as_uri()+"?mode=ro",
                         uri=True, timeout=3) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        rows = db.execute(
            "SELECT key,value FROM observations WHERE key LIKE ? LIMIT 2049",
            (PREFIX+"%",),
        ).fetchall()
        if len(rows) > 2048:
            raise Hold("split_manual_provenance_limit_exceeded")
        matches = []
        for row in rows:
            try:
                val = json.loads(row["value"])
            except (TypeError, ValueError) as exc:
                raise Hold("invalid_split_manual_ledger_observation") from exc
            if not isinstance(val, dict):
                raise Hold("invalid_split_manual_ledger_observation")
            if any(isinstance(item, dict) and item.get("job_id") == job_id
                   for item in val.get("jobs", []) if isinstance(val.get("jobs"), list)):
                matches.append((row["key"], val))
        if len(matches) != 1:
            raise Hold("split_manual_missing_or_ambiguous_owner_claim")
        key, evidence = matches[0]
        if (evidence.get("proof_kind") != PROOF
                or evidence.get("repo") != REPO
                or evidence.get("source_sha") != source
                or evidence.get("source_ref") != "develop"
                or evidence.get("ref") != REF
                or evidence.get("event") != REF
                or evidence.get("job_intents") != list(JOBS)
                or evidence.get("owner_principal") != auth.PRINCIPAL):
            raise Hold("split_manual_observation_metadata_mismatch")
        _verify_envelope(key, evidence, source)
        _observed_jobs(db, evidence, policy, source, active_id=job_id)
        state = db.execute(
            "SELECT state FROM jobs WHERE id=?", (job_id,)
        ).fetchone()["state"]
        db.rollback()
    return {"schema": CLAIM_SCHEMA, "job_id": job_id,
            "source_sha": source, "ref": REF, "queue_state": state,
            "request_sha256": evidence["request_sha256"],
            "verified_owner_origin": True,
            "provider_status_authorised": False,
            "github_actions_admission_authorised": False}

def claim_owner_signed_split_manual_run(*, checkout: Path, fleet_root: Path,
                                        request_file: Path,
                                        signature_file: Path) -> dict:
    """Production entry point; no injectable clock, source or verifier."""
    root = fleet.checked_fleet_root(fleet_root)
    raw = auth.owner_bytes(request_file, 4096)
    sig = auth.owner_bytes(signature_file, 8192)
    auth.verify_owner_signature_bytes(raw, sig, auth.owner_allowed_signers())
    doc = parse_intent(raw, int(time.time()))
    fresh = auth.read_fresh_develop_sha()
    if fresh != doc["source_sha"]:
        raise Hold("split_manual_develop_changed")
    # Source and workflow contract verification is a prerequisite, not
    # deferred until after SQLite insertion.
    fd = os.open(root/"control.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    locked = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise Hold("split_manual_shared_fleet_busy") from exc
        policy = json.loads(auth.owner_bytes(
            root/"fleet-policy.json", 262144, private=False))
        if (policy["execution_hosts"].get(REPO) != os.uname().nodename
                or policy["repositories"][REPO].get("enrolled_head") != fresh):
            raise Hold("split_manual_unenrolled_source")
        plan = router.compile_plan(checkout, policy, commit=fresh,
                                   hostname=os.uname().nodename)
        if (plan.get("source_verified") is not True
                or len(plan.get("jobs", [])) != 88):
            raise Hold("split_manual_source_plan_unverified")
        specs = distinct._split_policy(
            policy, [{"job": key} for key in JOBS])
        if (set(item["key"] for item in plan["jobs"]
                if item.get("class") == "ordinary"
                and item.get("route") == "existing-local-fleet")
                != set(JOBS)):
            raise Hold("split_manual_unreviewed_ordinary_job_mapping")
        reqhash = hashlib.sha256(raw).hexdigest()
        key = PREFIX + hashlib.sha256(
            (REPO+"\n"+doc["nonce"]).encode("ascii")).hexdigest()
        conn = sqlite3.connect((root/"fleet.sqlite3").as_uri()+"?mode=rw",
                               uri=True, timeout=3, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            fleet._queue_schema(conn)
            conn.execute("BEGIN IMMEDIATE")
            prior = conn.execute(
                "SELECT value FROM observations WHERE key=?", (key,)
            ).fetchone()
            if prior:
                evidence = json.loads(prior["value"])
                if (evidence.get("request_sha256") != reqhash
                        or evidence.get("source_sha") != fresh
                        or evidence.get("proof_kind") != PROOF):
                    raise Hold("split_manual_nonce_collision_or_replay")
                _verify_envelope(key, evidence, fresh)
                records = _observed_jobs(conn, evidence, policy, fresh)
                status = "already_admitted"
            else:
                existing = conn.execute(
                    "SELECT id FROM jobs WHERE repo=? AND sha=? "
                    "AND suite IN (?,?) AND state IN "
                    "('queued','claimed','running','completed')",
                    (REPO, fresh, specs[0]["suite"], specs[1]["suite"]),
                ).fetchone()
                if existing:
                    raise Hold("split_manual_existing_job_not_same_signed_intent")
                timestamp = datetime.now(timezone.utc).isoformat()
                records = []
                for spec in specs:
                    ident = "local-fleet-" + uuid.uuid4().hex[:12]
                    conn.execute(
                        "INSERT INTO jobs(id,repo,sha,suite,policy,ref,"
                        "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        (ident, REPO, fresh, spec["suite"], spec["policy"],
                         REF, timestamp, timestamp))
                    records.append({
                        "workflow_job": spec["workflow_job"],
                        "job_id": ident, "suite": spec["suite"],
                        "policy": spec["policy"]})
                evidence = {
                    "proof_kind": PROOF, "repo": REPO, "source_sha": fresh,
                    "source_ref": "develop", "ref": REF, "event": REF,
                    "job_intents": list(JOBS), "jobs": records,
                    "request_sha256": reqhash,
                    "owner_principal": auth.PRINCIPAL,
                    "signed_request_b64": base64.b64encode(raw).decode("ascii"),
                    "signed_request_signature_b64":
                        base64.b64encode(sig).decode("ascii"),
                }
                conn.execute(
                    "INSERT INTO observations(key,value,updated_at)"
                    " VALUES(?,?,?)",
                    (key, json.dumps(evidence, sort_keys=True), timestamp))
                status = "queued"
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return {"schema": CLAIM_SCHEMA, "admission": status,
            "source_sha": fresh, "ref": REF,
            "job_intents": list(JOBS),
            "jobs": records, "request_sha256": reqhash,
            "runner_started": False, "jobs_executed": 0,
            "github_actions_dispatched": False}
