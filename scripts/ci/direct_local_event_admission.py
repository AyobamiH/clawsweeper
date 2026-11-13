#!/usr/bin/env python3
"""Pure, fail-closed GitHub HMAC event -> existing-fleet ordinary job intents.

No GitHub calls, queue operations, runner admission or status publication.
The already-installed webhook delivery ledger must own durable deduplication.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
from estate_policy import Hold

REPO = "AyobamiH/clawsweeper"
ORDINARY = frozenset({
    ".github/workflows/ci.yml#check",
    ".github/workflows/ci.yml#sparse-repair-builds",
})
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
GUID = re.compile(r"[0-9a-fA-F-]{36}\Z")
SIG = re.compile(r"sha256=[0-9a-f]{64}\Z")


def unique_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise Hold("duplicate_webhook_json_key")
        result[k] = v
    return result


def obj(value):
    if not isinstance(value, dict):
        raise Hold("untrusted_webhook_shape")
    return value


def verified_ordinary_intents(plan, *, body, event_name, signature,
                              delivery_id, secret, fresh_ref_sha):
    """Return authenticated SOURCE-ONLY intents; never execute or claim success.

    fresh_ref_sha MUST be read by the caller from a current GitHub ref/PR API
    response, not the webhook payload. This assertion cannot make provider
    readback trustworthy on its own; callers must keep that distinct proof.
    """
    if (not isinstance(secret, bytes) or len(secret) < 32
            or not isinstance(body, bytes) or not 0 < len(body) <= 65536):
        raise Hold("untrusted_secret_or_body_size")
    if (not isinstance(signature, str) or not SIG.fullmatch(signature)
            or not isinstance(delivery_id, str) or not GUID.fullmatch(delivery_id)):
        raise Hold("untrusted_webhook_authentication_headers")
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise Hold("invalid_webhook_hmac")
    try:
        payload = obj(json.loads(body, object_pairs_hook=unique_object))
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise Hold("untrusted_webhook_json") from exc
    if obj(payload.get("repository")).get("full_name") != REPO:
        raise Hold("foreign_repository_event")
    if (plan.get("schema") != "clawsweeper.direct-local-plan.v1"
            or plan.get("repo") != REPO or plan.get("source_verified") is not True):
        raise Hold("untrusted_source_plan")
    sha = plan.get("source_commit")
    if not isinstance(sha, str) or not SHA40.fullmatch(sha):
        raise Hold("untrusted_source_sha")
    if (not isinstance(fresh_ref_sha, str)
            or not SHA40.fullmatch(fresh_ref_sha)
            or fresh_ref_sha != sha):
        raise Hold("fresh_provider_ref_moved_or_absent")

    if event_name == "push":
        if (payload.get("ref") != "refs/heads/main"
                or payload.get("after") != sha
                or payload.get("deleted") is not False
                or payload.get("forced") is not False):
            raise Hold("not_an_exact_safe_main_push")
        ref = "main"
        eligible = {".github/workflows/ci.yml#check"}
    elif event_name == "pull_request":
        if payload.get("action") not in (
                "opened", "reopened", "synchronize", "ready_for_review"):
            raise Hold("unapproved_pr_action")
        pr = obj(payload.get("pull_request"))
        head, base = obj(pr.get("head")), obj(pr.get("base"))
        if (pr.get("state") != "open" or pr.get("draft") is not False
                or obj(pr.get("user")).get("login") != "AyobamiH"
                or obj(head.get("repo")).get("full_name") != REPO
                or obj(base.get("repo")).get("full_name") != REPO
                or base.get("ref") != "main" or head.get("sha") != sha
                or type(pr.get("number")) is not int
                or not 1 <= pr["number"] <= 1000000000):
            raise Hold("untrusted_or_ineligible_pr")
        ref = f"pr/{pr['number']}"
        eligible = ORDINARY
    else:
        # GitHub workflow_dispatch cannot inherit trusted webhook actor proof.
        raise Hold("separate_event_identity_adapter_required")

    jobs = plan.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 88:
        raise Hold("missing_reviewed_job_inventory")
    selected = []
    for job in jobs:
        if job.get("key") not in eligible:
            continue
        if (job.get("class") != "ordinary"
                or job.get("route") != "existing-local-fleet"
                or job.get("suite") != "linux-node24"
                or job.get("execution_observed") is not False
                or job.get("required_step") not in (
                    "pnpm run check", "pnpm run test:workflow-sparse-checkout")):
            raise Hold("ordinary_job_not_source_pinned")
        selected.append({"job": job["key"], "suite": job["suite"],
                         "required_step": job["required_step"]})
    if {j["job"] for j in selected} != eligible:
        raise Hold("missing_or_unreviewed_ordinary_route")
    identity = hashlib.sha256(
        (REPO + "\n" + delivery_id.lower() + "\n" + event_name
         + "\n" + ref + "\n" + sha).encode("ascii")
    ).hexdigest()
    return {
        "schema": "clawsweeper.verified-local-ordinary-intents.v1",
        "repo": REPO, "source_commit": sha, "source_ref": ref,
        "event": event_name, "intent_identity_sha256": identity,
        "delivery_sha256": hashlib.sha256(body).hexdigest(),
        "intents": selected, "candidate_intent_count": len(selected),
        "existing_fleet_delivery_claim_required": True,
        "fresh_provider_readback_required": True,
        "queue_admitted": False, "job_executed": False,
        "github_status_published": False,
    }
