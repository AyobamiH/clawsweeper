#!/usr/bin/env python3
"""Owner-only, default-off concurrent JIT estate controller.

This is a staged capability. Workflows must first be independently reviewed,
converted to run-bound labels, accepted at exact source and owner-enabled.
All provider mutations remain behind the existing receipt/reconciliation layer.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from estate_policy import Hold, REPO, DELEGATED_VALIDATION, classify, admit, load_manifest, workflow_digest
from estate_slots import SlotLedger
from estate_fleet_lock import shared_fleet_exclusive, legacy_executor_exclusive
import self_hosted_executor as existing

ROOT = Path.home() / ".local/share/local-ci/clawsweeper-estate"
CONTROLS = ROOT / "controls.json"
LEDGER = ROOT / "slots"
ORDER = {"codeql": 0, "ordinary": 1, "review": 2, "privileged": 3, "e2e": 4, "windows": 5}


def get_controls(path=CONTROLS):
    if not path.exists():
        return {}
    if path.is_symlink() or (path.stat().st_mode & 0o077):
        raise Hold("unsafe_owner_controls")
    controls = json.loads(path.read_text())
    if not isinstance(controls, dict):
        raise Hold("invalid_owner_controls")
    return controls


def git_api(path):
    # Read-only GitHub request via existing authenticated CLI; never retries
    # POSTs, workflow dispatches, or runner registrations.
    return existing.gh(path)


def fetch_workflow_digest(run, main_sha, api=git_api):
    """Bind workflow instructions to trusted main AND the actual PR merge.

    A pull_request run normally executes GitHub's synthetic merge ref, not
    the PR branch checkout. Comparing only main and head misses that source.
    An ambiguous/moving ref is a hold before any non-idempotent JIT POST.
    """
    workflow = run.get("path")
    ref = run.get("head_sha")
    if (not isinstance(workflow, str) or not workflow.startswith(".github/workflows/")
            or not isinstance(ref, str) or not len(ref) == 40
            or not all(ch in "0123456789abcdef" for ch in ref)):
        raise Hold("source_ref_not_immutable")
    refs = [main_sha, ref]
    if run.get("event") == "pull_request":
        prs = run.get("pull_requests")
        if (not isinstance(prs, list) or len(prs) != 1
                or not isinstance(prs[0], dict)
                or type(prs[0].get("number")) is not int
                or prs[0]["number"] <= 0):
            raise Hold("pull_request_merge_identity_unverifiable")
        number = prs[0]["number"]
        # A stacked PR can target another unmerged branch. Authenticate its
        # current exact base/head from GitHub's PR record, rather than
        # assuming every synthetic merge has current main as its first parent.
        # The base's *workflow bytes* must nevertheless match trusted main;
        # an unreviewed branch can never grant new workflow instructions.
        try:
            pr = api(f"repos/{REPO}/pulls/{number}")
            base = pr["base"]
            head = pr["head"]
            base_sha, head_sha = base["sha"], head["sha"]
            base_repo = base["repo"]["full_name"]
            head_repo = head["repo"]["full_name"]
            record = api(f"repos/{REPO}/git/ref/pull/{number}/merge")
            merge_sha = record["object"]["sha"]
            merge = api(f"repos/{REPO}/git/commits/{merge_sha}")
            parents = merge["parents"]
        except (TypeError, KeyError, IndexError) as exc:
            raise Hold("pull_request_merge_identity_unverifiable") from exc
        valid_sha = lambda value: (isinstance(value, str) and len(value) == 40
                                   and all(char in "0123456789abcdef" for char in value))
        if (type(pr.get("number")) is not int or pr["number"] != number
                or pr.get("state") != "open"
                or base_repo != REPO
                or not isinstance(head_repo, str) or not head_repo
                or not valid_sha(base_sha) or not valid_sha(head_sha)
                or not valid_sha(merge_sha) or head_sha != ref
                or not isinstance(parents, list) or len(parents) != 2
                or any(not isinstance(parent, dict) for parent in parents)
                or [p.get("sha") for p in parents] != [base_sha, ref]):
            raise Hold("pull_request_merge_parents_changed")
        refs.extend((base_sha, merge_sha))
    elif run.get("event") in ("pull_request_target", "pull_request_review"):
        # Mutation-bearing events are never permitted to borrow this
        # read-only source-verification path.
        raise Hold("untrusted_workflow_source_event")
    try:
        digests = []
        for commit in refs:
            content = api(f"repos/{REPO}/contents/{workflow}?ref={commit}")
            encoded = content["content"]
            if not isinstance(encoded, str):
                raise Hold("workflow_source_unreadable")
            decoded = base64.b64decode("".join(encoded.split()), validate=True)
            digests.append(workflow_digest(decoded))
    except (KeyError, ValueError, TypeError) as exc:
        raise Hold("workflow_source_unreadable") from exc
    if any(value != digests[0] for value in digests[1:]):
        raise Hold("executed_workflow_differs_from_trusted_main")
    return digests[0]


def verified_run_jobs(run_id, api=git_api, *, max_pages=20):
    """Read all job pages or fail closed before admitting any ephemeral JIT."""
    if type(run_id) is not int or run_id <= 0 or type(max_pages) is not int or not (1 <= max_pages <= 20):
        raise Hold("invalid_github_job_inventory_parameters")
    jobs = []
    seen = set()
    expected_total = None
    for page in range(1, max_pages + 1):
        response = api(f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100&page={page}")
        if not isinstance(response, dict):
            raise Hold("incomplete_github_job_inventory")
        entries, total = response.get("jobs"), response.get("total_count")
        if (not isinstance(entries, list) or type(total) is not int or total < 0
                or total > max_pages * 100 or len(entries) > 100
                or (expected_total is not None and expected_total != total)):
            raise Hold("incomplete_github_job_inventory")
        if expected_total is None:
            expected_total = total
        for entry in entries:
            if (not isinstance(entry, dict) or type(entry.get("id")) is not int
                    or entry["id"] <= 0 or entry["id"] in seen
                    or entry.get("run_id") not in (None, run_id)):
                raise Hold("inconsistent_github_job_inventory")
            seen.add(entry["id"])
            jobs.append(entry)
        if len(jobs) == expected_total:
            return jobs
        if len(entries) != 100 or len(jobs) > expected_total:
            raise Hold("incomplete_github_job_inventory")
    raise Hold("github_job_inventory_page_limit")


def discover(manifest, api=git_api, *, max_pages=4):
    """Inspect queue; never return a partial page set as complete."""
    paths = {s["path"] for s in manifest["sources"]}
    visited = set()
    results = []
    for status in ("queued", "in_progress", "pending"):
        exhausted = False
        for page in range(1, max_pages + 1):
            response = api(f"repos/{REPO}/actions/runs?status={status}&per_page=100&page={page}")
            runs = response.get("workflow_runs")
            if not isinstance(runs, list):
                raise Hold("incomplete_github_run_inventory")
            for run in runs:
                if run.get("path") not in paths or run.get("id") in visited:
                    continue
                visited.add(run.get("id"))
                for job in verified_run_jobs(run["id"], api):
                    try:
                        results.append((classify(manifest, run, job), run, job))
                    except Hold:
                        continue
            if len(runs) < 100:
                exhausted = True
                break
        if not exhausted:
            raise Hold("run_inventory_pagination_limit")
    return sorted(results, key=lambda x: (ORDER[x[0].job_class], x[0].run_id, x[0].job_id))


def host_capacity():
    unit = subprocess.run(["systemctl", "--user", "is-active", "local-ci-fleet.service"],
                          text=True, capture_output=True, timeout=5)
    busy = {"fleet_busy": True, "memory_available_mib": 0, "disk_free_gib": 0}
    if unit.stdout.strip() != "inactive":
        return busy
    # The local fleet dispatches jobs as detached transient units. The
    # scheduler service itself can be inactive while multiple real CI
    # jobs still own CPU, memory and containers; never treat that as idle.
    try:
        units = subprocess.run(
            ["systemctl", "--user", "list-units", "--type=service",
             "--state=active", "--plain", "--no-legend", "--no-pager",
             "local-ci-job-*.service"],
            text=True, capture_output=True, timeout=5)
        if units.returncode != 0 or units.stdout.strip():
            return busy
        # A crashed transient unit can leave a live fleet container. The
        # read-only inventory is a second, independent guard, not access
        # to the Docker socket for a JIT worker.
        containers = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}",
             "--filter", "name=^/local-fleet-"],
            text=True, capture_output=True, timeout=8)
        if containers.returncode != 0 or containers.stdout.strip():
            return busy
    except (OSError, subprocess.TimeoutExpired):
        return busy
    try:
        # Includes SQLite detached_leases reserved BEFORE systemd exposes
        # a job unit. No fleet database or runner mutation from this readback.
        if existing.detached_fleet_quiescent() is not True:
            return busy
    except (existing.AdmissionHold, OSError, RuntimeError, ValueError):
        return busy
    lines = Path("/proc/meminfo").read_text().splitlines()
    available = next(int(l.split()[1]) // 1024 for l in lines if l.startswith("MemAvailable:"))
    disk = shutil.disk_usage(Path.home()).free / 1024**3
    return {"fleet_busy": False, "memory_available_mib": available, "disk_free_gib": disk}


def inspect(manifest=None, controls=None, ledger=None):
    manifest = manifest or load_manifest()
    controls = controls if controls is not None else get_controls()
    ledger = ledger or SlotLedger(LEDGER)
    attempts = ledger.inspect()["attempts"]
    counts = {}
    for item in manifest["jobs"]:
        from estate_policy import job_class
        klass = job_class(item)
        counts[klass] = counts.get(klass, 0) + 1
    return {
        "repo": REPO,
        "controller_enabled": controls.get("enabled") is True,
        "live_mutations_enabled": controls.get("allow_live_mutations") is True,
        "manifest_jobs": len(manifest["jobs"]),
        "delegated_existing_validation_jobs": sorted(DELEGATED_VALIDATION),
        "classes": counts,
        "max_parallel": controls.get("max_parallel", 0),
        "active_or_held_attempts": [
            {"key": k, "state": r["state"], "class": r["job_class"], "slot": r["slot"]}
            for k, r in attempts.items() if r["state"] in ("reserved", "running", "held")
        ],
    }


def work_one(item, controls, ledger, *, worker):
    candidate, _run, _job = item
    # A lease exists before any external registration; a killed process leaves
    # an unreplayable attempt and a held slot, not a duplicate GitHub runner.
    ledger.update(candidate, state="running")
    proof = worker(candidate, controls)
    if not isinstance(proof, dict):
        raise Hold("worker_did_not_return_a_verifiable_receipt")
    return ledger.update(candidate, state="finished", proof=proof)



def reconcile_codeql(ledger, *, api=git_api):
    """Bind BOTH genuine CodeQL jobs, uploads and original JIT receipts.

    Unverifiable scans remain pending without a green check or implicit rerun.
    Original held receipts are retained; reconciliation never creates an
    executor, substitutes SHA, fixes an alert, or marks old failures passed.
    """
    from types import SimpleNamespace
    from verify_codeql_release import verify_release, EvidenceRefused
    attempts = ledger.inspect()["attempts"]
    grouped = {}
    for record in attempts.values():
        if record.get("job_class") == "codeql" and record.get("state") in (
                "awaiting_evidence", "running", "held"):
            grouped.setdefault((record["run_id"], record["head_sha"]), []).append(record)
    results = []
    for (run_id, head_sha), records in grouped.items():
        try:
            run = api(f"repos/{REPO}/actions/runs/{run_id}")
            if run.get("head_sha") != head_sha:
                raise Hold("codeql_run_sha_drift")
            prs = run.get("pull_requests") or []
            pr_number = None
            if run.get("event") == "pull_request":
                if len(prs) != 1 or type(prs[0].get("number")) is not int:
                    raise Hold("codeql_pr_identity_unverifiable")
                pr_number = prs[0]["number"]
            evidence = verify_release(api, run_id, head_sha, pr_number,
                                      existing.RECEIPTS, require_closed_alert=False)
            verified_jobs = {v["id"]: v for v in evidence["jobs"].values()}
            for record in records:
                job_id = record["job_id"]
                entry = verified_jobs.get(job_id)
                if entry is None:
                    raise Hold("codeql_job_not_in_verified_run")
                name = entry["runner"]
                # The independently verified job ID is bound to the same
                # exact one-shot registered runner and immutable log digest.
                existing.runner_absent_verified(
                    int(json.loads((existing.RECEIPTS / f"run-{run_id}-job-{job_id}-attempt-{record['attempt']}" /
                                    "receipt.json").read_text())["runner_id"]), name)
                if any(existing.inspect_owned(name + suffix, name) is not None
                       for suffix in ("-worker", "-net")):
                    raise Hold("codeql_containers_not_cleaned")
                c = SimpleNamespace(run_id=run_id, job_id=job_id, attempt=record["attempt"],
                                    job_key=record["job_key"], job_class="codeql")
                proof = dict(run_id=run_id, job_id=job_id, attempt=record["attempt"],
                             log_sha256=entry["log_sha256"],
                             github_terminal_verified=True, runner_absent_verified=True,
                             containers_absent_verified=True, sarif_upload_verified=True)
                ledger.reconcile_held(c, proof=proof)
                results.append({"run_id": run_id, "job_id": job_id,
                                "state": "reconciled", "sarif_uploaded": True})
        except (EvidenceRefused, Hold, RuntimeError, OSError, KeyError, ValueError) as exc:
            results.append({"run_id": run_id, "state": "held", "reason": type(exc).__name__})
    return results

def preflight_runtime_inventory(ledger, *, api=git_api, list_containers=None,
                               legacy_controls=existing.CONTROLS):
    """Detect competing controllers, runners or containers before any JIT POST.

    This inspection does not release or delete another controller's effects.
    Unknown ownership is a refusal until an independent reconciliation.
    """
    if legacy_controls.exists():
        if legacy_controls.is_symlink() or (legacy_controls.stat().st_mode & 0o077):
            raise Hold("legacy_controls_unsafe")
        legacy = json.loads(legacy_controls.read_text())
        if legacy.get("enabled") is True:
            raise Hold("legacy_controller_still_enabled")
    record = ledger.inspect()
    expected = set()
    for attempt in record["attempts"].values():
        if attempt.get("state") in ("reserved", "running", "held"):
            expected.add(f"csw-ci-{attempt['run_id']}-{attempt['job_id']}-{attempt['attempt']}")
    stock = api(f"repos/{REPO}/actions/runners?per_page=100")
    runners = stock.get("runners")
    total = stock.get("total_count")
    if not isinstance(runners, list) or type(total) is not int or total != len(runners):
        raise Hold("runner_inventory_incomplete")
    for runner in runners:
        name = runner.get("name")
        if isinstance(name, str) and name.startswith("csw-ci-") and name not in expected:
            raise Hold("competing_or_untracked_jit_runner")
    if list_containers is None:
        def list_containers():
            result = subprocess.run(
                ["docker", "ps", "--all", "--filter",
                 "label=io.ayobamih.clawsweeper.selfhosted",
                 "--format", "{{.Names}}"],
                text=True, capture_output=True, timeout=20)
            if result.returncode:
                raise Hold("container_ownership_inventory_unavailable")
            return result.stdout.splitlines()
    names = list_containers()
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise Hold("container_ownership_inventory_incomplete")
    permitted = {owner + suffix for owner in expected for suffix in ("-net", "-worker")}
    if any(name not in permitted for name in names):
        raise Hold("competing_or_untracked_container")
    return {"runners": len(runners), "owned_containers": len(names),
            "known_active_attempts": len(expected)}

def native_driver(candidate, controls):
    """Strictly separate the accepted CodeQL path from one rootless E2E driver.

    The E2E path stays default-off without exact run/attempt, PR source,
    executable harness, pinned image and independent 28-case readback.
    Privileged, inference/review, native Windows and delegated ordinary jobs
    remain rejected BEFORE any JIT registration or Docker execution.
    """
    if candidate.job_class == "e2e":
        # Only the exact automerge-e2e workflow has a dedicated rootless,
        # owner-run/attempt-pinned implementation. The other E2E workflow
        # provisions privileged Cloudflare compute and is still denied.
        from estate_e2e_driver import execute
        return execute(candidate, controls)
    if candidate.job_class != "codeql":
        raise Hold("dedicated_class_driver_not_accepted")
    from types import SimpleNamespace

    approved = controls.get("approved_jobs", {}).get(candidate.job_key)
    if not isinstance(approved, dict) or approved.get("class") != "codeql":
        raise Hold("codeql_job_approval_missing")
    digest = approved.get("image_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(
            ch not in "0123456789abcdef" for ch in digest):
        raise Hold("codeql_image_digest_unverifiable")
    image = "sha256:" + digest
    if controls.get("security_image_sha256") != image:
        raise Hold("codeql_image_control_mismatch")
    c = SimpleNamespace(run_id=candidate.run_id, job_id=candidate.job_id,
                        run_attempt=candidate.attempt, sha=candidate.sha,
                        workflow=candidate.workflow, event=candidate.event,
                        role="security", label=candidate.label)
    # Independent read-only local Docker image inspection, BEFORE the first
    # non-idempotent GitHub registration POST.
    try:
        if existing.approved_job_image(c, controls) != image:
            raise Hold("codeql_image_inspection_mismatch")
    except (RuntimeError, OSError) as exc:
        raise Hold("codeql_image_inspection_unavailable") from exc
    result = existing.runner_job(c, controls)
    if not isinstance(result, dict) or result.get("state") != "passed":
        raise Hold("codeql_jit_result_unverified")
    raw = result.get("receipt")
    if not isinstance(raw, str):
        raise Hold("codeql_jit_receipt_missing")
    receipt = json.loads(Path(raw).read_text())
    name = receipt.get("runner_name")
    registered_id = receipt.get("runner_id")
    if (receipt.get("image_sha256") != image
            or receipt.get("head_sha") != candidate.sha
            or receipt.get("run_id") != candidate.run_id
            or receipt.get("job_id") != candidate.job_id
            or receipt.get("attempt") != candidate.attempt):
        raise Hold("codeql_jit_receipt_identity_mismatch")
    if not isinstance(name, str) or type(registered_id) is not int:
        raise Hold("registered_runner_identity_missing")
    terminal = git_api(f"repos/{REPO}/actions/jobs/{candidate.job_id}")
    bound = (terminal.get("id") == candidate.job_id and
             terminal.get("run_id") == candidate.run_id and
             terminal.get("status") == "completed" and
             terminal.get("runner_name") == name and
             terminal.get("conclusion") == "success" and
             receipt.get("state") == "passed" and
             not receipt.get("issues"))
    try:
        existing.runner_absent_verified(registered_id, name)
        registered_absent = True
    except Exception:
        registered_absent = False
    containers_absent = all(existing.inspect_owned(name + suffix, name) is None
                            for suffix in ("-worker", "-net"))
    # SARIF remains unverified until the separate exact-source, two-language
    # GitHub code-scanning readback. A passing local worker is insufficient.
    return {
        "run_id": candidate.run_id,
        "job_id": candidate.job_id,
        "attempt": candidate.attempt,
        "log_sha256": receipt.get("log_sha256"),
        "github_terminal_verified": bool(bound),
        "runner_absent_verified": registered_absent,
        "containers_absent_verified": containers_absent,
        "sarif_upload_verified": False,
    }


def cycle(manifest=None, controls=None, ledger=None, *, api=git_api, worker=native_driver):
    controls = controls if controls is not None else get_controls()
    if controls.get("enabled") is not True or controls.get("allow_live_mutations") is not True:
        return {"held": "estate_controller_disabled"}
    # The installed fleet obtains this exact inode lock for every detached
    # admission. Holding it throughout the one-shot JIT execution prevents
    # the gap between source/capacity inspection, reservation and cleanup.
    # A busy fleet is a refusal, never permission to race its controller.
    with shared_fleet_exclusive():
        # Exclude the existing ClawSweeper JIT controller as well as the fleet
        # scheduler. Both locks remain held through registration and cleanup.
        with legacy_executor_exclusive():
            return _cycle_under_shared_lock(manifest, controls, ledger, api=api, worker=worker)


def _cycle_under_shared_lock(manifest, controls, ledger, *, api, worker):
    manifest = manifest or load_manifest()
    ledger = ledger or SlotLedger(LEDGER)
    if controls.get("repo") != REPO:
        raise Hold("controller_repository_mismatch")
    main = api(f"repos/{REPO}/git/ref/heads/main")["object"]["sha"]
    if main != controls.get("trusted_main_sha"):
        raise Hold("unreviewed_main_head")
    if sys.platform != "linux":
        raise Hold("linux_controller_host_required")
    observed = host_capacity()
    if observed["fleet_busy"]:
        return {"held": "shared_fleet_has_priority"}
    preflight_runtime_inventory(ledger, api=api)
    options = []
    for item in discover(manifest, api=api):
        c, run, _job = item
        # These two jobs are owned by the separately accepted validation
        # controller. Never introduce a second JIT registration path.
        if c.job_key in DELEGATED_VALIDATION:
            continue
        try:
            digest = fetch_workflow_digest(run, main, api)
            admit(c, manifest, controls, source_sha256=digest, host_platform="linux")
            # The installed driver can execute only CodeQL. Do not reserve a
            # durable one-shot attempt for another class and then poison its
            # slot with a guaranteed pre-registration driver rejection.
            if worker is native_driver and c.job_class not in ("codeql", "e2e"):
                raise Hold("dedicated_class_driver_not_accepted")
            if c.job_class == "e2e" and c.job_key != ".github/workflows/automerge-e2e.yml#automerge-e2e":
                raise Hold("dedicated_driver_not_proven")
            if c.job_class == "windows":
                raise Hold("dedicated_driver_not_proven")
            options.append(item)
        except Hold:
            continue
    if not options:
        return {"held": "no_approved_queued_jobs", "reconciliation": reconcile_codeql(ledger, api=api)}
    selected = []
    for item in options:
        c = item[0]
        try:
            ledger.reserve(c, controls, **observed)
            selected.append(item)
        except Hold:
            continue
    if not selected:
        return {"held": "fleet_or_class_capacity_not_available"}
    # Multiple workers can register unique JIT identities concurrently.
    # Each distinct durable reservation owns one slot and one attempt.
    outcome = []
    with ThreadPoolExecutor(max_workers=controls["max_parallel"]) as pool:
        futures = {pool.submit(work_one, item, controls, ledger, worker=worker): item[0]
                   for item in selected}
        for future in as_completed(futures):
            c = futures[future]
            try:
                record = future.result()
                outcome.append({"job_id": c.job_id, "state": record["state"],
                                "slot": record["slot"]})
            except Exception as exc:
                # Slot remains running/uncertain. Never release it on exception.
                outcome.append({"job_id": c.job_id, "state": "held",
                                "reason": type(exc).__name__})
    return {"jobs": sorted(outcome, key=lambda x: x["job_id"]),
            "reconciliation": reconcile_codeql(ledger, api=api)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inspect", "cycle"))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        report = inspect() if args.mode == "inspect" else cycle()
        print(json.dumps(report, sort_keys=True, indent=2))
    except (Hold, RuntimeError, KeyError, ValueError) as exc:
        print(json.dumps({"held": type(exc).__name__, "reason": str(exc)}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
