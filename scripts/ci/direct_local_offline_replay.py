#!/usr/bin/env python3
"""Strict source-only typed candidate for offline release replay (job 3).

This reads the exact approved workflow catalogue but never interprets mutable
Actions YAML as host shell, verifies no GitHub event, and grants no execution.
A future distinct owner-signed intent and fresh provider main readback must
precede admission by the existing fleet; old 2/2 intent is not transferable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import direct_local_workflow as estate
from estate_policy import Hold, load_manifest

JOB = ".github/workflows/release-offline-replay.yml#replay"
WORKFLOW = ".github/workflows/release-offline-replay.yml"
EXPECTED_SHA256 = "e0483a0dec0b8bec890923d50afe09185c24aae80330a12d674d3d7f82316875"
EXPECTED_LABELS = (
    "self-hosted", "Linux", "X64",
    "clawsweeper-ci-ops-${{ github.run_id }}-offline-replay",
)
STEPS = (
    {"kind": "trusted_exact_checkout", "source": "owner-approved verified main SHA",
     "credentials": False},
    {"kind": "pinned_dependency_install", "command": "pnpm install --frozen-lockfile",
},
    {"kind": "offline_replay_validation", "command": "pnpm run test:release-replay",
},
    {"kind": "static_validation", "command": "pnpm run check:static",
},
)


def inspect(root: Path = estate.ROOT) -> dict:
    """Produce a non-executable typed contract for exactly reviewed bytes."""
    root = root.resolve(strict=True)
    manifest = load_manifest(root / "config/ci-workflow-estate.json")
    sources = estate.source_check(manifest, root)
    estate.dag_check(manifest)
    if sources.get(WORKFLOW) != EXPECTED_SHA256:
        raise Hold("offline_replay_workflow_not_reviewed_exact_bytes")
    matches = [job for job in manifest["jobs"]
               if job["workflow"] + "#" + job["id"] == JOB]
    if len(matches) != 1:
        raise Hold("offline_replay_job_not_unique")
    job = matches[0]
    if (job.get("execution_boundary") != "local_label_unverified"
            or job.get("kind") != "local_label"
            or job.get("status") != "labelled_local_not_operationally_verified"
            or job.get("risks") != []
            or job.get("needs") != []
            or job.get("events") != ["workflow_dispatch"]
            or job.get("runs_on") != list(EXPECTED_LABELS)
            or job.get("source_sha256") != EXPECTED_SHA256
            or estate.job_class(job) != "privileged"):
        raise Hold("offline_replay_boundary_or_event_contract_changed")
    return {
        "schema": "clawsweeper.offline-replay-source-candidate.v1",
        "job": JOB,
        "reviewed_workflow_sha256": EXPECTED_SHA256,
        "catalogue_commit": estate.git_head(root),
        "typed_steps": list(STEPS),
        "source_and_dag_validated": True,
        "workflow_total_timeout_seconds": 900,
        "eligible_for_live_execution": False,
        "admitted": False,
        "executed": False,
        "terminal_receipt": None,
        "github_provider_accepted": False,
        "external_effect_authority": False,
        "next_required_gate": (
            "distinct_owner_signed_manual_replay_intent_and_fresh_exact_main"
            "_source_readback_then_isolated_existing_fleet_adapter_proof"
        ),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=estate.ROOT)
    opts = p.parse_args()
    try:
        print(json.dumps(inspect(opts.root), indent=2, sort_keys=True))
    except (Hold, OSError, ValueError) as exc:
        p.exit(2, "HOLD: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
