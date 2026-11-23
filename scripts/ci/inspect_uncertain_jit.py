#!/usr/bin/env python3
"""Read-only inspection of a potentially interrupted ClawSweeper JIT intent.

This never creates/deletes a runner, starts/stops a container, retries a job,
changes a receipt or promotes earlier evidence into acceptance. It allows an
owner to see what still requires guarded reconciliation after process death.
"""
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

from self_hosted_executor import RECEIPTS, REPOSITORY, REPO_SLUG, gh, inspect_owned

KEY = re.compile(r"^run-([1-9][0-9]*)-job-([1-9][0-9]*)-attempt-([1-9][0-9]*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def inspect(directory):
    directory = Path(directory)
    if directory.is_symlink() or directory.parent.resolve() != RECEIPTS.resolve():
        raise RuntimeError("unowned_intent_directory")
    match = KEY.fullmatch(directory.name)
    if not match or not directory.is_dir() or stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise RuntimeError("unsafe_intent_directory")
    original = directory / "receipt.json"
    if (original.is_symlink() or not original.is_file()
            or stat.S_IMODE(original.stat().st_mode) != 0o600):
        raise RuntimeError("unsafe_intent_receipt")
    raw = original.read_bytes()
    receipt = json.loads(raw)
    run_id, job_id, attempt = map(int, match.groups())
    name = f"csw-ci-{run_id}-{job_id}-{attempt}"
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "clawsweeper.selfhosted-jit.v1"
            or receipt.get("runner_name") != name
            or [receipt.get("run_id"), receipt.get("job_id"), receipt.get("attempt")]
                != [run_id, job_id, attempt]
            or not isinstance(receipt.get("head_sha"), str)
            or not SHA.fullmatch(receipt["head_sha"])
            or receipt.get("role") not in ("security", "ops", "isolation", "validation")
            or not isinstance(receipt.get("label"), str)
            or not re.fullmatch(
                rf"clawsweeper-ci-{receipt['role']}-{run_id}-[a-z0-9-]+",
                receipt["label"])):
        raise RuntimeError("intent_identity_mismatch")
    if receipt.get("state") not in ("registration_uncertain", "registered", "runner_started", "held"):
        raise RuntimeError("not_an_unresolved_intent")

    runner_id = receipt.get("runner_id")
    if runner_id is not None and (isinstance(runner_id, bool)
                                  or not isinstance(runner_id, int) or runner_id < 1):
        raise RuntimeError("malformed_runner_identity")

    remote_run = gh(f"{REPO_SLUG}/actions/runs/{run_id}")
    remote_job = gh(f"{REPO_SLUG}/actions/jobs/{job_id}")
    if (remote_run.get("id") != run_id
            or remote_run.get("head_sha") != receipt["head_sha"]
            or remote_run.get("run_attempt") != attempt
            or remote_run.get("repository", {}).get("full_name") != REPOSITORY
            or remote_job.get("id") != job_id
            or remote_job.get("run_id") != run_id):
        raise RuntimeError("remote_job_identity_mismatch")
    if remote_job.get("runner_name") not in (None, "", name):
        raise RuntimeError("remote_job_runner_mismatch")

    inventory = gh(f"{REPO_SLUG}/actions/runners?per_page=100")
    runners = inventory.get("runners")
    total = inventory.get("total_count")
    if (not isinstance(runners, list) or not isinstance(total, int)
            or isinstance(total, bool) or total != len(runners)):
        raise RuntimeError("runner_inventory_not_complete")
    matching = [r for r in runners if isinstance(r, dict) and
                (r.get("name") == name or (runner_id is not None and r.get("id") == runner_id))]
    if len(matching) > 1:
        raise RuntimeError("ambiguous_runner_identity")
    if matching:
        found = matching[0]
        if (found.get("name") != name
                or (runner_id is not None and found.get("id") != runner_id)
                or receipt["label"] not in {
                    label.get("name") for label in found.get("labels", [])
                    if isinstance(label, dict)
                }):
            raise RuntimeError("runner_identity_conflict")

    containers = {}
    for suffix in ("-worker", "-net"):
        # inspect_owned demands the exact owner label and refuses a foreign
        # container with the same name. An API error never becomes 'absent'.
        containers[suffix[1:]] = inspect_owned(name + suffix, name) is not None

    return {
        "schema": "clawsweeper.uncertain-jit-inspection.v1",
        "run_id": run_id, "job_id": job_id, "attempt": attempt,
        "source_sha": receipt["head_sha"], "original_state": receipt["state"],
        "original_receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "runner_present": bool(matching), "runner_id_recorded": runner_id is not None,
        "container_present": containers,
        "github_job_status": remote_job.get("status"),
        "github_job_conclusion": remote_job.get("conclusion"),
        "decision": "manual_reconciliation_required",
        "may_retry_registration": False,
        "mutations_performed": False,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected one exact owned JIT receipt directory")
    try:
        print(json.dumps(inspect(sys.argv[1]), sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status": "held", "reason": type(exc).__name__}), file=sys.stderr)
        sys.exit(1)
