#!/usr/bin/env python3
"""Review a third, separately authenticated offline replay job without effects.

This is intentionally NOT a queue writer or an installer. The existing two
accepted jobs have different identities. A protected-main integration, a
signed single-job intent, exact release installation and worker integration
are mandatory before any genuine new fleet execution.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

import direct_local_manual_auth as auth
import direct_local_offline_replay as replay
import direct_local_offline_replay_suite as suite
import direct_local_workflow as estate
from estate_policy import Hold

INTENT_SCHEMA = "clawsweeper.owner-signed-offline-replay-request.v1"
RELEASE_SCHEMA = "clawsweeper.third-replay-release-candidate.v1"
INTENT_NAMESPACE = "clawsweeper-third-offline-replay-v1"
PROOF = "owner_signed_single_replay_intent_not_admission"
REF = "local-manual-replay"
JOB = replay.JOB
FIELDS = frozenset((
    "schema", "repo", "source_sha", "source_ref", "host", "suite",
    "job_intents", "purpose", "nonce", "issued_at", "expires_at",
))
HEX32 = re.compile(r"[a-f0-9]{32}\Z")
HEX40 = re.compile(r"[a-f0-9]{40}\Z")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_intent(raw: bytes, *, now: int | None = None) -> dict:
    """Reject old split requests, broad scopes, duplicate keys and stale intents."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4096:
        raise Hold("invalid_replay_intent_size")
    try:
        doc = json.loads(raw, object_pairs_hook=auth.unique_object)
    except Hold:
        raise
    except (TypeError, ValueError, UnicodeError) as exc:
        raise Hold("invalid_replay_intent_json") from exc
    now = int(time.time()) if now is None else now
    if (
        not isinstance(doc, dict) or set(doc) != FIELDS
        or doc["schema"] != INTENT_SCHEMA or doc["repo"] != estate.REPO
        or doc["source_ref"] != "main" or doc["host"] != "web"
        or doc["suite"] != suite.SUITE
        or doc["job_intents"] != [JOB]
        or doc["purpose"] != "effect-free-offline-replay-validation"
        or not isinstance(doc["source_sha"], str)
        or not HEX40.fullmatch(doc["source_sha"])
        or not isinstance(doc["nonce"], str)
        or not HEX32.fullmatch(doc["nonce"])
        or type(doc["issued_at"]) is not int
        or type(doc["expires_at"]) is not int
        or doc["issued_at"] > now + 30
        or now - doc["issued_at"] > 900
        or doc["expires_at"] < now
        or not 0 < doc["expires_at"] - doc["issued_at"] <= 900
    ):
        raise Hold("replay_intent_scope_or_freshness_invalid")
    return doc


def verify_owner_intent(raw: bytes, signature: bytes) -> None:
    """Use a dedicated SSH signing namespace; never reuse original two-job intent."""
    if (
        not isinstance(signature, bytes) or not 0 < len(signature) <= 8192
        or not signature.startswith(b"-----BEGIN SSH SIGNATURE-----")
    ):
        raise Hold("replay_signature_missing_or_invalid")
    signers = auth.owner_allowed_signers()
    auth.owner_bytes(signers, 8192, private=False)
    try:
        fd = os.memfd_create("claw-replay-intent", flags=0)
    except (OSError, AttributeError) as exc:
        raise Hold("replay_signature_verifier_unavailable") from exc
    try:
        if os.write(fd, signature) != len(signature):
            raise Hold("replay_signature_short_write")
        os.lseek(fd, 0, os.SEEK_SET)
        result = subprocess.run([
            auth._trusted_system_binary("ssh-keygen"), "-Y", "verify",
            "-f", str(signers), "-I", auth.PRINCIPAL,
            "-n", INTENT_NAMESPACE, "-s", f"/proc/self/fd/{fd}",
        ], input=raw, pass_fds=(fd,), capture_output=True, check=False,
            timeout=8, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Hold("replay_signature_verifier_unavailable") from exc
    finally:
        os.close(fd)
    if result.returncode:
        raise Hold("replay_owner_signature_mismatch")


def proposed_policy(root: Path, installed: dict) -> dict:
    """Return an immutable-input-derived candidate only; never write the fleet."""
    proposal = suite.prepare(root, installed)
    candidate = copy.deepcopy(installed)
    candidate["repositories"][estate.REPO]["suites"][suite.SUITE] = copy.deepcopy(
        proposal["suite"])
    # Future successor policy must enrol the same reviewed source that
    # protected main is required to contain before any signed installation.
    # This is a proposal only: validate_for_admission re-reads real main.
    candidate["repositories"][estate.REPO]["enrolled_head"] = proposal["candidate_source_sha"]
    if (candidate["repositories"][estate.REPO]["enrolled_head"] ==
            installed["repositories"][estate.REPO]["enrolled_head"]):
        raise Hold("replay_source_not_new")
    if candidate["repositories"][estate.REPO]["suites"][suite.SUITE] != (
        proposal["suite"]
    ):
        raise Hold("replay_suite_changed_during_staging")
    return {
        "schema": RELEASE_SCHEMA,
        "source_sha": proposal["candidate_source_sha"],
        "workflow_job": JOB,
        "workflow_sha256": proposal["reviewed_workflow_sha256"],
        "existing_enrolled_sha": proposal["existing_enrolled_source_sha"],
        "existing_policy_sha256": hashlib.sha256(canonical(installed)).hexdigest(),
        "proposed_policy_sha256": hashlib.sha256(canonical(candidate)).hexdigest(),
        "proposed_suite_sha256": proposal["suite_sha256"],
        "policy": candidate,
        "signature_namespace": INTENT_NAMESPACE,
        "intent_schema": INTENT_SCHEMA,
        "intent_ref": REF,
        "intended_job_count": 1,
        "old_job_replays": 0,
        "github_dispatch": False,
        "provider_status": False,
        "new_fleet_controller": False,
        "installed": False,
        "admitted": False,
        "executed": False,
        "safety_gates": (
            "reviewed_protected_main_exact_source",
            "separate_installed_signed_controller_policy_release",
            "live_standing_capacity_and_ram_guard",
            "new_owner_signed_single_replay_intent",
            "single_existing_fleet_queue_admission",
            "real_container_command_log_cleanup_proof",
        ),
    }


def read_fresh_main_sha() -> str:
    """Authenticated, read-only GitHub ref GET; no workflow dispatch or status write."""
    try:
        outcome = subprocess.run([
            auth._trusted_system_binary("gh"), "api", "--hostname", "github.com",
            "--method", "GET", "repos/AyobamiH/clawsweeper/git/ref/heads/main",
        ], capture_output=True, check=False, timeout=15,
            env=auth._trusted_github_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Hold("replay_main_get_unavailable") from exc
    if outcome.returncode or not 0 < len(outcome.stdout) <= 32768:
        raise Hold("replay_main_get_unavailable")
    try:
        doc = json.loads(outcome.stdout, object_pairs_hook=auth.unique_object)
        if (doc["ref"] != "refs/heads/main"
                or doc["object"]["type"] != "commit"
                or not isinstance(doc["object"]["sha"], str)
                or not HEX40.fullmatch(doc["object"]["sha"])):
            raise ValueError("invalid main")
    except (ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise Hold("replay_main_get_untrusted") from exc
    return doc["object"]["sha"]


def validate_for_admission(
    root: Path, installed: dict, signed_raw: bytes, signed_sig: bytes,
    *, now: int | None = None,
) -> dict:
    """Read-only admission preflight; never claims a job or endorses installed code."""
    if os.getuid() != 1000 or os.uname().nodename != "web":
        raise Hold("replay_untrusted_host_identity")
    doc = parse_intent(signed_raw, now=now)
    verify_owner_intent(signed_raw, signed_sig)
    fresh_provider_main = read_fresh_main_sha()
    if doc["source_sha"] != fresh_provider_main:
        raise Hold("replay_signed_intent_not_fresh_main")
    proposal = proposed_policy(root, installed)
    if proposal["source_sha"] != fresh_provider_main:
        raise Hold("replay_workflow_not_on_verified_main")
    # Even when all conditions here pass, the installed worker, frozen
    # release and durable claim are separate higher-authority components.
    return {
        "schema": "clawsweeper.replay-single-job-preflight.v1",
        "source_sha": fresh_provider_main,
        "workflow_job": JOB,
        "intent_sha256": hashlib.sha256(signed_raw).hexdigest(),
        "proposed_policy_sha256": proposal["proposed_policy_sha256"],
        "owner_signed": True,
        "ref": REF,
        "job_count": 1,
        "installed": False,
        "admitted": False,
        "executed": False,
        "github_dispatch": False,
        "provider_effect": False,
    }
