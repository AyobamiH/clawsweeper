#!/usr/bin/env python3
"""Read-only migration bridge: all ClawSweeper jobs -> owner-operated local CI.

This is not a GitHub Actions JIT runner or a second queue. It binds the two
ordinary validation jobs to the EXISTING pinned local-ci fleet suite, which
already owns webhook/poll, SQLite admission, container isolation, retry,
receipts and GitHub commit-status readback. Every other job stays held until
a separate, effect-aware local adapter and real acceptance exist.

No provider calls, workflow execution, runner registration, or mutations.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess

from estate_policy import Hold, job_class, load_manifest

REPO = "AyobamiH/clawsweeper"
ROOT = Path(__file__).resolve().parents[2]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\Z")
ORDINARY = {
    ".github/workflows/ci.yml#check": "pnpm run check",
    ".github/workflows/ci.yml#sparse-repair-builds": "pnpm run test:workflow-sparse-checkout",
}
EXPECTED_CLASS_COUNTS = {
    "ordinary": 2,
    "review": 5,
    "e2e": 2,
    "codeql": 1,
    "windows": 1,
    "privileged": 77,
}
BOUNDARIES = {
    "guarded_sensitive_effects": "requires_effect_aware_local_adapter",
    "isolated_container_required": "requires_isolated_e2e_local_adapter",
    "genuine_windows_required": "requires_genuine_native_windows_local_worker",
    "dedicated_codeql_security": "requires_local_codeql_and_sarif_authority",
    "external_crabbox_ephemeral": "requires_external_crabbox_owner_handoff",
    "local_label_unverified": "requires_explicit_local_job_adapter",
}


def git_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=5
    )
    head = result.stdout.strip()
    if not HEX40.fullmatch(head):
        raise Hold("untrusted_local_git_head")
    return head


def sha256(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise Hold("missing_or_symlinked_source")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_check(manifest: dict, root: Path) -> dict[str, str]:
    """Match all 41 source bytes to the reviewed manifest before any routing."""
    sources = manifest.get("sources", [])
    if len(sources) != 41 or len(manifest.get("jobs", [])) != 88:
        raise Hold("migration_estate_not_exact_41_workflows_88_jobs")
    observed: dict[str, str] = {}
    for record in sources:
        name, expected = record["path"], record["sha256"]
        if not WORKFLOW_PATH.fullmatch(name) or not HEX64.fullmatch(expected):
            raise Hold("unsafe_workflow_path_or_digest")
        path = root / name
        actual = sha256(path)
        if actual != expected or name in observed:
            raise Hold("reviewed_workflow_bytes_changed")
        observed[name] = actual
    actual_names = {
        ".github/workflows/" + file.name
        for file in (root / ".github/workflows").iterdir()
        if file.is_file() and file.suffix in (".yml", ".yaml")
    }
    if actual_names != set(observed):
        raise Hold("new_or_missing_workflow_not_reviewed")
    for job in manifest["jobs"]:
        if observed.get(job["workflow"]) != job["source_sha256"]:
            raise Hold("job_workflow_digest_drift")
    return observed


def dag_check(manifest: dict) -> None:
    """Job-level needs stay local to each workflow; cycles and missing IDs hold."""
    grouped: dict[str, dict[str, dict]] = {}
    for job in manifest["jobs"]:
        key = job["workflow"]
        grouped.setdefault(key, {})
        if job["id"] in grouped[key]:
            raise Hold("duplicate_workflow_job")
        grouped[key][job["id"]] = job
    for jobs in grouped.values():
        finished: set[str] = set()
        visiting: set[str] = set()

        def visit(name: str) -> None:
            if name not in jobs:
                raise Hold("unknown_local_needs")
            if name in visiting:
                raise Hold("cyclic_local_needs")
            if name in finished:
                return
            visiting.add(name)
            needs = jobs[name].get("needs", [])
            if not isinstance(needs, list) or not all(isinstance(n, str) for n in needs):
                raise Hold("unsafe_local_needs")
            for parent in needs:
                visit(parent)
            visiting.remove(name)
            finished.add(name)

        for name in jobs:
            visit(name)


def fleet_contract(policy: dict | None, *, source_digest: str, commit: str,
                   hostname: str) -> tuple[bool, str]:
    """Only the existing fleet can run validation, on exact reviewed source."""
    if not isinstance(policy, dict):
        return False, "existing_fleet_policy_not_supplied"
    if policy.get("execution_hosts", {}).get(REPO) != hostname:
        return False, "wrong_existing_fleet_owner_host"
    repo = policy.get("repositories", {}).get(REPO)
    if not isinstance(repo, dict):
        return False, "repository_not_enrolled_in_existing_fleet"
    if (repo.get("branch") != "main"
            or repo.get("source_workflow", ".github/workflows/ci.yml") != ".github/workflows/ci.yml"):
        return False, "untrusted_existing_fleet_workflow_identity"
    # This is the invariant enforced by the existing fleet's contract_at().
    if repo.get("contract") != source_digest or repo.get("enrolled_head") != commit:
        return False, "source_not_yet_pinned_in_existing_fleet"
    suite = repo.get("suites", {}).get("linux-node24")
    if not isinstance(suite, dict) or suite.get("node") != "24":
        return False, "ordinary_fleet_suite_missing_or_unpinned"
    image = suite.get("image")
    if not isinstance(image, str) or not image.startswith("sha256:") or not HEX64.fullmatch(image[7:]):
        return False, "ordinary_fleet_image_not_immutable"
    steps = suite.get("steps")
    if not isinstance(steps, list) or not all(isinstance(x, dict) for x in steps):
        return False, "ordinary_fleet_steps_not_reviewed"
    commands = [x.get("command") for x in steps]
    if not all(isinstance(c, str) for c in commands) or len(commands) != len(set(commands)):
        return False, "duplicate_or_invalid_ordinary_fleet_commands"
    # This adapter is bound to the existing reviewed fleet suite, not permission
    # to run arbitrary additional workflow commands from mutable YAML.
    expected_commands = (
        """actionlint -shellcheck= -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml""",
        "pnpm install --frozen-lockfile",
        "pnpm run check",
        "pnpm run test:workflow-sparse-checkout",
    )
    if tuple(commands) != expected_commands:
        return False, "ordinary_fleet_command_parity_missing"
    if any(type(step.get("timeout")) is not int or not 1 <= step["timeout"] <= 1800 for step in steps):
        return False, "unbounded_ordinary_fleet_step"
    return True, "ready_for_existing_fleet_admission_not_execution_proof"


def compile_plan(root: Path = ROOT, policy: dict | None = None,
                 *, commit: str | None = None, hostname: str | None = None) -> dict:
    """Read-only, complete 88-job plan. 'ready' is NEVER a passing job status."""
    root = root.resolve(strict=True)
    manifest = load_manifest(root / "config/ci-workflow-estate.json")
    sources = source_check(manifest, root)
    dag_check(manifest)
    classes = Counter(job_class(j) for j in manifest["jobs"])
    if dict(classes) != EXPECTED_CLASS_COUNTS:
        raise Hold("unreviewed_job_class_migration")
    actual_head = git_head(root)
    if commit is not None and commit != actual_head:
        raise Hold("requested_source_sha_not_local_git_head")
    head = actual_head
    if not HEX40.fullmatch(head):
        raise Hold("untrusted_commit_identity")
    host = hostname or socket.gethostname()
    pinned, reason = fleet_contract(
        policy, source_digest=sources[".github/workflows/ci.yml"], commit=head, hostname=host
    )
    jobs = []
    for item in manifest["jobs"]:
        key = item["workflow"] + "#" + item["id"]
        cls = job_class(item)
        boundary = item.get("execution_boundary")
        if boundary not in BOUNDARIES:
            raise Hold("unclassified_local_execution_boundary")
        route = "held"
        why = BOUNDARIES[boundary]
        suite = None
        required_step = None
        if key in ORDINARY:
            if cls != "ordinary" or item["risks"] or item["needs"] or boundary != "local_label_unverified":
                raise Hold("ordinary_direct_local_job_is_not_effect_free")
            if set(item["events"]) != {"push", "pull_request", "workflow_dispatch"}:
                raise Hold("ordinary_local_event_contract_changed")
            required_step = ORDINARY[key]
            if pinned:
                route = "existing-local-fleet"
                suite = "linux-node24"
                why = reason
            else:
                why = reason
        elif cls == "ordinary":
            raise Hold("unmapped_ordinary_job_requires_explicit_adapter")
        jobs.append({
            "key": key, "workflow": item["workflow"], "job": item["id"],
            "class": cls, "needs": item["needs"], "events": item["events"],
            "boundary": boundary, "route": route, "reason": why,
            "suite": suite, "required_step": required_step,
            "execution_observed": False,
        })
    if len(jobs) != 88 or len({j["key"] for j in jobs}) != 88:
        raise Hold("incomplete_direct_local_route_map")
    ready = sum(j["route"] == "existing-local-fleet" for j in jobs)
    return {
        "schema": "clawsweeper.direct-local-plan.v1",
        "repo": REPO, "source_commit": head, "hostname": host,
        "owner": "existing local-ci fleet; no second executor",
        "source_verified": True,
        "provider_actions_dispatched": False,
        "statuses_published": False,
        "job_executions_observed": 0,
        "summary": {
            "workflows": len(sources), "jobs": len(jobs),
            "mapped_to_existing_fleet": ready,
            "held_for_existing_fleet_source_pin": (2 - ready),
            "held_for_class_specific_adapter": 86,
            "classes": dict(sorted(classes.items())),
        },
        "jobs": jobs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--fleet-policy", type=Path,
                        help="Existing owner fleet policy; read-only, never modify")
    parser.add_argument("--source-sha", help="Exact desired local source commit SHA")
    args = parser.parse_args()
    policy = json.loads(args.fleet_policy.read_text()) if args.fleet_policy else None
    result = compile_plan(args.repo_root, policy, commit=args.source_sha)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Hold, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        # Never log secret-bearing underlying subprocess output.
        raise SystemExit("held:" + type(exc).__name__)
