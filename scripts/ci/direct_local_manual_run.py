#!/usr/bin/env python3
"""Owner-signed local intent to existing fleet queue. NOT a GitHub Actions admission.

Source-only until an independently authorised frozen controller release supports
the new local-manual provenance and source-reference class. No new scheduler,
runner, credential broker or provider status publishing lives in this module.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone

import direct_local_fleet_claim as claims
import direct_local_workflow as routing
from direct_local_event_admission import unique_object
from estate_policy import Hold

REPO = "AyobamiH/clawsweeper"
SCHEMA = "clawsweeper.owner-signed-local-manual-request.v1"
PROOF = "owner_signed_local_manual_queue_admission_not_execution"
REF = "local-manual"
PROVIDER_REF = "develop"
NAMESPACE = "clawsweeper-direct-local-manual-v1"
PRINCIPAL = "heryourbarme@live.com"
JOBS = (
    ".github/workflows/ci.yml#check",
    ".github/workflows/ci.yml#sparse-repair-builds",
)
FIELDS = frozenset((
    "schema", "repo", "source_sha", "source_ref", "host", "suite",
    "job_intents", "purpose", "nonce", "issued_at", "expires_at",
))
HEX32 = re.compile(r"[a-f0-9]{32}\Z")


def owner_bytes(path: Path, limit: int, private: bool = True) -> bytes:
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise Hold("untrusted_manual_file")
    st = p.stat()
    mode = stat.S_IMODE(st.st_mode)
    if (st.st_uid != os.getuid()
            or (private and mode != 0o600)
            or (not private and mode & (stat.S_IWGRP | stat.S_IWOTH))
            or not 0 < st.st_size <= limit):
        raise Hold("unsafe_manual_file_size_or_permissions")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_ino, opened.st_dev) != (st.st_ino, st.st_dev):
            raise Hold("manual_file_replaced")
        data = os.read(fd, limit + 1)
        if len(data) != st.st_size:
            raise Hold("manual_file_changed")
        return data
    finally:
        os.close(fd)


def verify_owner_signature(raw: bytes, signature: Path, signers: Path) -> None:
    sig = owner_bytes(signature, 8192)
    owner_bytes(signers, 8192, private=False)
    if not sig.startswith(b"-----BEGIN SSH SIGNATURE-----"):
        raise Hold("invalid_manual_signature_format")
    try:
        res = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(signers),
             "-I", PRINCIPAL, "-n", NAMESPACE, "-s", str(signature)],
            input=raw, capture_output=True, timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Hold("owner_signature_verifier_unavailable") from exc
    if res.returncode:
        raise Hold("untrusted_owner_signature")


def parse_intent(raw: bytes, now: int) -> dict:
    try:
        doc = json.loads(raw, object_pairs_hook=unique_object)
    except Hold:
        # Preserve the precise duplicate-key fail-closed diagnosis.
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Hold("invalid_manual_json") from exc
    if (not isinstance(doc, dict) or set(doc) != FIELDS
            or doc["schema"] != SCHEMA or doc["repo"] != REPO
            or doc["source_ref"] != PROVIDER_REF
            or doc["host"] != os.uname().nodename
            or doc["suite"] != claims.SUITE
            or doc["purpose"] != "ordinary-source-validation"
            or not isinstance(doc["source_sha"], str)
            or not routing.HEX40.fullmatch(doc["source_sha"])
            or type(doc["job_intents"]) is not list
            or doc["job_intents"] != list(JOBS)
            or type(doc["nonce"]) is not str
            or not HEX32.fullmatch(doc["nonce"])
            or type(doc["issued_at"]) is not int
            or type(doc["expires_at"]) is not int
            or doc["issued_at"] > now + 30 or now - doc["issued_at"] > 900
            or doc["expires_at"] < now
            or not 0 < doc["expires_at"] - doc["issued_at"] <= 900):
        raise Hold("unapproved_manual_scope_or_freshness")
    return doc


def read_fresh_develop_sha() -> str:
    """One read-only GitHub ref GET; never Actions admission or status POST."""
    try:
        res = subprocess.run(
            ["gh", "api", "--method", "GET",
             "repos/AyobamiH/clawsweeper/git/ref/heads/develop"],
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Hold("manual_source_get_unavailable") from exc
    if res.returncode or len(res.stdout) > 32768:
        raise Hold("manual_source_get_unavailable")
    try:
        doc = json.loads(res.stdout, object_pairs_hook=unique_object)
        if (doc["ref"] != "refs/heads/develop"
                or doc["object"]["type"] != "commit"
                or not routing.HEX40.fullmatch(doc["object"]["sha"])):
            raise ValueError("untrusted source")
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise Hold("untrusted_manual_source_get") from exc
    return doc["object"]["sha"]


def claim_owner_signed_manual_run(
    *, checkout: Path, fleet_root: Path, request_file: Path,
    signature_file: Path, allowed_signers_file: Path,
) -> dict:
    """Production entry point: no injectable clock, source readback or verifier."""
    return _claim_verified(
        checkout=checkout, fleet_root=fleet_root, request_file=request_file,
        signature_file=signature_file, allowed_signers_file=allowed_signers_file,
    )


def _claim_verified(
    *, checkout: Path, fleet_root: Path, request_file: Path,
    signature_file: Path, allowed_signers_file: Path,
    fresh_source_sha: str | None = None, signature_verifier=None,
    now: int | None = None,
) -> dict:
    """Internal implementation. Only in-process tests inject dependencies.

    The installed controller must invoke claim_owner_signed_manual_run above,
    never this private test seam. Both entry points retain canonical fleet lock.
    """
    root = claims.checked_fleet_root(fleet_root)
    raw = owner_bytes(request_file, 4096)
    if signature_verifier is None:
        verify_owner_signature(raw, signature_file, allowed_signers_file)
    else:
        signature_verifier(raw, signature_file, allowed_signers_file)
    doc = parse_intent(raw, int(time.time()) if now is None else now)
    fresh = read_fresh_develop_sha() if fresh_source_sha is None else fresh_source_sha
    if fresh != doc["source_sha"]:
        raise Hold("manual_source_moved_or_not_published")
    digest = hashlib.sha256(raw).hexdigest()
    fd = os.open(root / "control.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    locked = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise Hold("manual_existing_fleet_owner_busy") from exc
        policy = json.loads(owner_bytes(
            root / "fleet-policy.json", 262144, private=False))
        if (policy["execution_hosts"].get(REPO) != os.uname().nodename
                or policy["repositories"][REPO].get("enrolled_head") != fresh):
            raise Hold("manual_policy_source_or_host_mismatch")
        plan = routing.compile_plan(
            Path(checkout), policy, commit=fresh,
            hostname=os.uname().nodename,
        )
        eligible = sorted(j["key"] for j in plan["jobs"]
                          if j["class"] == "ordinary"
                          and j["route"] == "existing-local-fleet"
                          and j["suite"] == claims.SUITE)
        if (plan["source_verified"] is not True or len(plan["jobs"]) != 88
                or eligible != sorted(JOBS)):
            raise Hold("manual_two_job_plan_not_source_verified")
        policy_sha = claims.reviewed_policy_hash(policy)
        key = "direct-local-manual:" + hashlib.sha256(
            (REPO + "\n" + doc["nonce"]).encode("ascii")).hexdigest()
        uri = (root / "fleet.sqlite3").as_uri() + "?mode=rw"
        with sqlite3.connect(uri, uri=True, isolation_level=None, timeout=3) as db:
            db.row_factory = sqlite3.Row
            claims._queue_schema(db)
            try:
                db.execute("BEGIN IMMEDIATE")
                prior = db.execute(
                    "SELECT value FROM observations WHERE key=?", (key,)
                ).fetchone()
                stored = json.loads(prior["value"]) if prior else None
                if prior and (not isinstance(stored, dict)
                              or stored.get("request_sha256") != digest
                              or stored.get("source_sha") != fresh
                              or stored.get("proof_kind") != PROOF):
                    raise Hold("manual_nonce_collision_or_replay")
                existing = db.execute(
                    "SELECT id,ref,state FROM jobs WHERE repo=? AND sha=?"
                    " AND suite=? AND policy=?",
                    (REPO, fresh, claims.SUITE, policy_sha),
                ).fetchone()
                if existing:
                    if (stored is None or stored.get("job_id") != existing["id"]
                            or existing["ref"] != REF
                            or existing["state"] not in (
                                "queued", "claimed", "running", "completed")):
                        raise Hold("manual_existing_job_not_same_signed_intent")
                    ident, admission = existing["id"], "already_admitted"
                else:
                    if stored is not None:
                        raise Hold("manual_orphan_observation")
                    ident = "local-fleet-" + uuid.uuid4().hex[:12]
                    timestamp = datetime.now(timezone.utc).isoformat()
                    db.execute(
                        "INSERT INTO jobs(id,repo,sha,suite,policy,ref,"
                        "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        (ident, REPO, fresh, claims.SUITE, policy_sha,
                         REF, timestamp, timestamp),
                    )
                    observation = {
                        "proof_kind": PROOF, "repo": REPO,
                        "source_sha": fresh, "source_ref": PROVIDER_REF,
                        "ref": REF, "suite": claims.SUITE, "job_id": ident,
                        "job_intents": list(JOBS), "event": "local-manual",
                        "request_sha256": digest,
                        "owner_principal": PRINCIPAL,
                        "nonce_sha256": hashlib.sha256(
                            doc["nonce"].encode("ascii")).hexdigest(),
                    }
                    db.execute(
                        "INSERT INTO observations(key,value,updated_at)"
                        " VALUES(?,?,?)",
                        (key, json.dumps(observation, sort_keys=True), timestamp),
                    )
                    admission = "queued"
                db.commit()
            except BaseException:
                db.rollback()
                raise
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return {
        "schema": "clawsweeper.existing-fleet-local-manual-claim.v1",
        "source_sha": fresh, "source_ref": REF,
        "existing_fleet_job_id": ident, "suite": claims.SUITE,
        "job_intents": list(JOBS), "admission": admission,
        "request_sha256": digest, "runner_started": False,
        "job_executed": False, "github_actions_dispatched": False,
        "github_status_published": False,
    }
