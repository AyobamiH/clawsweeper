#!/usr/bin/env python3
"""Source-only fresh GitHub GET readback for the existing direct-local fleet claim.

Only two narrowly bound, read-only provider endpoints are permitted. This is
not a second webhook receiver, queue or runner. The GitHub response is a
source-identity assertion; it never authorises sensitive effects or claims CI
success. No GitHub Actions API or workflow dispatch is used.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import subprocess
from typing import Callable

import direct_local_event_admission as events
import direct_local_fleet_claim as claims
from estate_policy import Hold

REPO = "AyobamiH/clawsweeper"
MAIN_GET = f"repos/{REPO}/git/ref/heads/main"
PR_GET = re.compile(rf"repos/{REPO}/pulls/[1-9][0-9]{{0,8}}\Z")
MAX_BODY = 65536
MAX_RESPONSE = 131072


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise Hold("untrusted_fresh_github_response")
    return value


def _from_json(data: bytes) -> dict:
    if not isinstance(data, bytes) or len(data) > MAX_RESPONSE:
        raise Hold("oversized_or_missing_fresh_github_response")
    try:
        return _object(json.loads(data, object_pairs_hook=events.unique_object))
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise Hold("untrusted_fresh_github_json") from exc


def read_github_get(path: str) -> dict:
    """One bounded GET with no retries, writes, browser, or credential logging."""
    if path != MAIN_GET and not PR_GET.fullmatch(path):
        raise Hold("unapproved_fresh_github_get_path")
    try:
        result = subprocess.run(
            ["gh", "api", "--method", "GET", path],
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Hold("fresh_github_get_unavailable") from exc
    if result.returncode != 0:
        # stderr can include tokens, headers, remote data; never forward it.
        raise Hold("fresh_github_get_unavailable")
    return _from_json(result.stdout)


def verified_fresh_source_sha(
    *, body: bytes, event_name: str, signature: str,
    delivery_id: str, secret: bytes,
    provider_get: Callable[[str], dict] = read_github_get,
) -> str:
    """Authenticate before GET; read back exact current head or PR identity.

    A signed webhook can be stale. Matching a stale payload against local Git is
    insufficient: independently read current GitHub source state before local
    SQLite admission. A mutable PR metadata change is a HOLD, not a retryable
    authority to run the old head.
    """
    if (not isinstance(body, bytes) or not 0 < len(body) <= MAX_BODY
            or not isinstance(secret, bytes) or len(secret) < 32
            or not isinstance(signature, str) or not events.SIG.fullmatch(signature)
            or not isinstance(delivery_id, str) or not events.GUID.fullmatch(delivery_id)):
        raise Hold("untrusted_webhook_identity_before_provider_get")
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise Hold("bad_webhook_hmac_before_provider_get")
    try:
        payload = _object(json.loads(body, object_pairs_hook=events.unique_object))
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise Hold("invalid_webhook_json_before_provider_get") from exc
    if _object(payload.get("repository")).get("full_name") != REPO:
        raise Hold("foreign_repository_before_provider_get")

    if event_name == "push":
        sha = payload.get("after")
        if (payload.get("ref") != "refs/heads/main"
                or payload.get("deleted") is not False
                or payload.get("forced") is not False
                or not isinstance(sha, str) or not events.SHA40.fullmatch(sha)):
            raise Hold("untrusted_push_before_provider_get")
        live = _object(provider_get(MAIN_GET))
        if (live.get("ref") != "refs/heads/main"
                or _object(live.get("object")).get("type") != "commit"
                or live["object"].get("sha") != sha):
            raise Hold("fresh_main_ref_moved_or_untrusted")
        return sha

    if event_name != "pull_request":
        raise Hold("no_provider_get_for_unreviewed_event")
    if payload.get("action") not in (
            "opened", "reopened", "synchronize", "ready_for_review"):
        raise Hold("untrusted_pr_action_before_provider_get")
    webhook_pr = _object(payload.get("pull_request"))
    number = webhook_pr.get("number")
    if type(number) is not int or not 1 <= number <= 999999999:
        raise Hold("untrusted_pr_number_before_provider_get")
    webhook_head = _object(webhook_pr.get("head"))
    webhook_base = _object(webhook_pr.get("base"))
    webhook_sha = webhook_head.get("sha")
    if not isinstance(webhook_sha, str) or not events.SHA40.fullmatch(webhook_sha):
        raise Hold("untrusted_pr_sha_before_provider_get")

    live = _object(provider_get(f"repos/{REPO}/pulls/{number}"))
    live_head, live_base = _object(live.get("head")), _object(live.get("base"))
    same = (
        live.get("number") == number
        and live.get("state") == webhook_pr.get("state") == "open"
        and live.get("draft") is webhook_pr.get("draft") is False
        and _object(live.get("user")).get("login")
            == _object(webhook_pr.get("user")).get("login") == "AyobamiH"
        and live_head.get("sha") == webhook_sha
        and _object(live_head.get("repo")).get("full_name")
            == _object(webhook_head.get("repo")).get("full_name") == REPO
        and live_base.get("ref") == webhook_base.get("ref") == "main"
        and _object(live_base.get("repo")).get("full_name")
            == _object(webhook_base.get("repo")).get("full_name") == REPO
    )
    if not same:
        raise Hold("fresh_pr_head_or_trust_metadata_moved")
    return webhook_sha


def claim_with_fresh_provider_readback(
    *, checkout, fleet_root, body: bytes, event_name: str,
    signature: str, delivery_id: str, secret: bytes,
    provider_get: Callable[[str], dict] = read_github_get,
) -> dict:
    """Use existing fleet lock + admission, with real GET source authority.

    Never call this from a new receiver. The existing authorised webhook/poller
    integration can invoke it after release/policy pin; tests inject GET only.
    """
    fresh_sha = verified_fresh_source_sha(
        body=body, event_name=event_name, signature=signature,
        delivery_id=delivery_id, secret=secret, provider_get=provider_get,
    )
    result = claims.claim_existing_fleet_delivery(
        checkout=checkout, fleet_root=fleet_root, body=body,
        event_name=event_name, signature=signature,
        delivery_id=delivery_id, secret=secret, fresh_ref_sha=fresh_sha,
    )
    return {**result, "fresh_provider_source_verified": True,
            "provider_get_kind": ("main_ref" if event_name == "push" else "pr"),
            "provider_ci_execution": False}
