#!/usr/bin/env python3
"""Build one non-executable, exact-source replay suite candidate.

This is a source/release review helper, never a policy writer or queue claimant.
A separate owner-signed release and manual job intent are required for activation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import direct_local_offline_replay as replay
import direct_local_workflow as estate
import direct_local_manual_auth as authentication
from estate_policy import Hold

SUITE = "linux-node24-claw-replay"
PINNED_IMAGE = "sha256:dc7e982df33f88146add5c0f00907c355777ca06f0fc56b568c5c9f9a7ce35e2"
ENV_REVISION = "web-docker-v7-dual-path-pnpm-jq"
ACTIONLINT = """actionlint -shellcheck= -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml"""
STEPS = (
    ("Workflow semantic validation", ACTIONLINT, 120),
    ("Pinned pnpm dependency install", "pnpm install --frozen-lockfile", 300),
    ("Offline release replay", "pnpm run test:release-replay", 180),
    ("Static source validation", "pnpm run check:static", 180),
)
SOURCE_REF = "main"
MAX_WORKFLOW_SECONDS = 900


def hold(allowed: bool, reason: str) -> None:
    if not allowed:
        raise Hold(reason)


def source_clean(root: Path) -> None:
    """Never stage a recipe from modified, untracked or unverified source."""
    try:
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=normal"],
            capture_output=True, timeout=6, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Hold("replay_source_cleanliness_unverifiable") from exc
    hold(not result.stdout, "replay_source_has_uncommitted_changes")


def prepare(root: Path, installed_policy: dict) -> dict:
    """Review an additional suite without altering signed installed policy."""
    root = root.resolve(strict=True)
    reviewed = replay.inspect(root)
    source_clean(root)
    hold(isinstance(installed_policy, dict), "replay_missing_installed_policy")
    repos = installed_policy.get("repositories")
    hosts = installed_policy.get("execution_hosts")
    hold(isinstance(repos, dict) and isinstance(hosts, dict),
         "replay_policy_containers_untrusted")
    repo = repos.get(estate.REPO)
    hold(isinstance(repo, dict), "replay_repository_not_enrolled")
    hold(hosts.get(estate.REPO) == "web"
         and repo.get("branch") == "main", "replay_not_web_main_owner")
    hold(repo.get("contract") == estate.sha256(root / ".github/workflows/ci.yml"),
         "replay_existing_ci_source_contract_drift")
    enrolled = repo.get("enrolled_head")
    hold(isinstance(enrolled, str) and bool(re.fullmatch(r"[a-f0-9]{40}", enrolled)),
         "replay_untrusted_prior_enrolment")
    existing = repo.get("suites")
    hold(isinstance(existing, dict) and SUITE not in existing,
         "replay_suite_already_installed_or_untrusted")
    for definition in estate.SPLIT:
        estate.validate_split_suite(installed_policy, definition)
    hold(sum(timeout for _, _, timeout in STEPS) <= MAX_WORKFLOW_SECONDS - 120,
         "replay_step_deadlines_exceed_workflow_budget")
    suite = {
        "node": "24", "image": PINNED_IMAGE,
        "execution_environment_revision": ENV_REVISION,
        "cpus": 1, "memory_mib": 1536, "pids": 256, "writable_mib": 1536,
        "steps": [
            {"name": name, "command": command, "timeout": timeout}
            for name, command, timeout in STEPS
        ],
    }
    payload = json.dumps(suite, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "clawsweeper.offline-replay-suite-staging.v1",
        "workflow_job": reviewed["job"],
        "reviewed_workflow_sha256": reviewed["reviewed_workflow_sha256"],
        "candidate_source_sha": reviewed["catalogue_commit"],
        "required_main_source_sha": reviewed["catalogue_commit"],
        "existing_enrolled_source_sha": enrolled,
        "suite_name": SUITE,
        "suite": suite,
        "suite_sha256": hashlib.sha256(payload).hexdigest(),
        "workflow_total_timeout_seconds": MAX_WORKFLOW_SECONDS,
        "source_clean": True,
        "installed_policy_changed": False,
        "job_admitted": False,
        "job_executed": False,
        "provider_effect": False,
        "requires_fresh_provider_main_readback": True,
        "requires_new_owner_signed_intent": True,
        "requires_separately_verified_signed_installation": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=estate.ROOT)
    parser.add_argument("--fleet-policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = authentication.owner_bytes(args.fleet_policy, 262144, private=False)
        policy = json.loads(raw, object_pairs_hook=authentication.unique_object)
        result = prepare(args.root, policy)
    except (Hold, ValueError, OSError) as exc:
        parser.exit(2, "HOLD: " + str(exc) + "\n")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
