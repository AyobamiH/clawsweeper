#!/usr/bin/env python3
"""Read-only, fail-closed CodeQL release evidence for PR merges and branch heads.

A passing GitHub workflow alone is not security acceptance. Bind each CodeQL
language to its actual successful JIT job and an analysis uploaded during that
job. PR merge SARIF must resolve to an exact two-parent synthetic merge; branch
SARIF must bind to the run's exact branch head. No GitHub writes are performed.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

REPO = "AyobamiH/clawsweeper"
API = f"repos/{REPO}"
SHA = re.compile(r"^[a-f0-9]{40}$")
LANGUAGES = {
    "actions": "Analyze (actions)",
    "javascript-typescript": "Analyze (javascript-typescript)",
}
WORKFLOW = ".github/workflows/codeql.yml"


class EvidenceRefused(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise EvidenceRefused(reason)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def gh_get(path):
    p = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=45)
    require(p.returncode == 0, "github_readback_unavailable")
    try:
        return json.loads(p.stdout)
    except ValueError as exc:
        raise EvidenceRefused("github_invalid_json") from exc


def analyses_pages(get):
    for page in range(1, 21):
        items = get(f"{API}/code-scanning/analyses?per_page=100&page={page}")
        require(isinstance(items, list), "invalid_analysis_page")
        yield from items
        if len(items) < 100:
            return
    raise EvidenceRefused("analysis_pagination_exhausted")


def verify_release(get, run_id, head_sha, pr_number=None, receipts=None, alert_id=3,
                   require_closed_alert=False):
    require(isinstance(run_id, int) and run_id > 0, "invalid_run")
    require(isinstance(head_sha, str) and SHA.fullmatch(head_sha), "invalid_head")
    run = get(f"{API}/actions/runs/{run_id}")
    require(run.get("id") == run_id and run.get("head_sha") == head_sha, "run_head_mismatch")
    require(run.get("path") == WORKFLOW, "untrusted_workflow")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "run_not_passed")
    attempt = run.get("run_attempt")
    require(type(attempt) is int and attempt > 0, "invalid_attempt")
    event = run.get("event")
    require(event in ("pull_request", "workflow_dispatch", "push", "schedule"), "unsupported_event")
    commit = get(f"{API}/commits/{head_sha}")
    require(commit.get("sha") == head_sha and
            commit.get("commit", {}).get("verification", {}).get("verified") is True,
            "head_signature_unverified")

    branch = run.get("head_branch")
    require(isinstance(branch, str) and branch != "" and
            ".." not in branch and not branch.startswith("/") and
            not branch.endswith("/"), "unsafe_branch")
    accepted_identities = {(head_sha, f"refs/heads/{branch}")}
    if event == "pull_request":
        require(type(pr_number) is int and pr_number > 0, "pull_request_not_pinned")
        prs = run.get("pull_requests")
        require(isinstance(prs, list), "pull_requests_unavailable")
        pr = get(f"{API}/pulls/{pr_number}")
        base = pr.get("base") or {}
        head = pr.get("head") or {}
        base_sha = base.get("sha")
        merge_sha = pr.get("merge_commit_sha")
        require(head.get("sha") == head_sha and head.get("ref") == branch and
                SHA.fullmatch(str(base_sha)) and SHA.fullmatch(str(merge_sha)),
                "pull_request_identity_changed")
        require(any(isinstance(p, dict) and p.get("number") == pr_number and
                    (p.get("head") or {}).get("sha") == head_sha and
                    (p.get("base") or {}).get("sha") == base_sha for p in prs),
                "workflow_pull_request_mismatch")
        ref = get(f"{API}/git/ref/pull/{pr_number}/merge")
        require(ref.get("ref") == f"refs/pull/{pr_number}/merge" and
                (ref.get("object") or {}).get("sha") == merge_sha,
                "merge_ref_changed")
        merge = get(f"{API}/commits/{merge_sha}")
        parents = [p.get("sha") for p in merge.get("parents", [])]
        require(parents == [base_sha, head_sha], "merge_parents_mismatch")
        accepted_identities.add((merge_sha, f"refs/pull/{pr_number}/merge"))
    else:
        require(pr_number is None, "pr_supplied_for_non_pr_run")
        ref = get(f"{API}/git/ref/heads/{branch}")
        require((ref.get("object") or {}).get("sha") == head_sha,
                "branch_head_moved")

    jobs = get(f"{API}/actions/runs/{run_id}/jobs?per_page=100")
    jobs = jobs.get("jobs") if isinstance(jobs, dict) else None
    require(isinstance(jobs, list) and len(jobs) == len(LANGUAGES), "job_inventory_mismatch")
    verified_jobs = {}
    for language, expected_name in LANGUAGES.items():
        matching = [j for j in jobs if j.get("name") == expected_name]
        require(len(matching) == 1, "language_job_missing_or_duplicate")
        job = matching[0]
        job_id = job.get("id")
        require(type(job_id) is int and job_id > 0 and
                job.get("status") == "completed" and job.get("conclusion") == "success",
                "language_job_not_passed")
        expected_runner = f"csw-ci-{run_id}-{job_id}-{attempt}"
        require(job.get("runner_name") == expected_runner, "runner_identity_mismatch")
        require(job.get("started_at") and job.get("completed_at") and
                job["started_at"] <= job["completed_at"], "job_timing_unverifiable")
        expected_label = f"clawsweeper-ci-security-{run_id}-{language}"
        require(expected_label in job.get("labels", []), "jit_label_mismatch")
        entry = {"id": job_id, "runner": expected_runner,
                 "started_at": job["started_at"], "completed_at": job["completed_at"]}
        if receipts is not None:
            folder = Path(receipts) / f"run-{run_id}-job-{job_id}-attempt-{attempt}"
            rpath, lpath = folder / "receipt.json", folder / "runner.log"
            require(rpath.is_file() and lpath.is_file() and
                    not rpath.is_symlink() and not lpath.is_symlink(),
                    "runner_receipt_missing")
            receipt = json.loads(rpath.read_text())
            require(receipt.get("schema") == "clawsweeper.selfhosted-jit.v1" and
                    receipt.get("run_id") == run_id and receipt.get("job_id") == job_id and
                    receipt.get("attempt") == attempt and receipt.get("head_sha") == head_sha and
                    receipt.get("runner_name") == expected_runner and
                    receipt.get("state") == "passed" and receipt.get("issues") == [] and
                    receipt.get("runner_exit") == 0 and
                    (receipt.get("github_job") or {}).get("conclusion") == "success" and
                    (receipt.get("github_job") or {}).get("runner_name") == expected_runner and
                    receipt.get("log_bytes") == lpath.stat().st_size and
                    receipt.get("log_sha256") == sha256_file(lpath), "runner_receipt_invalid")
            entry["receipt_sha256"] = sha256_file(rpath)
            entry["log_sha256"] = sha256_file(lpath)
        verified_jobs[language] = entry

    scans = list(analyses_pages(get))
    verified_analyses = {}
    for language in LANGUAGES:
        job = verified_jobs[language]
        matching = [a for a in scans
                    if a.get("tool", {}).get("name") == "CodeQL" and not a.get("error") and
                    a.get("category") == f"/language:{language}" and
                    a.get("analysis_key") == f"{WORKFLOW}:analyze" and
                    (a.get("commit_sha"), a.get("ref")) in accepted_identities and
                    job["started_at"] <= a.get("created_at", "") <= job["completed_at"]]
        require(len(matching) == 1, "language_sarif_missing_or_ambiguous")
        item = matching[0]
        verified_analyses[language] = {
            "id": item["id"], "commit_sha": item["commit_sha"],
            "ref": item["ref"], "created_at": item["created_at"],
        }

    alert = get(f"{API}/code-scanning/alerts/{alert_id}")
    require((alert.get("rule") or {}).get("id") == "js/clear-text-logging",
            "unexpected_security_alert")
    state = alert.get("state")
    require(state in ("open", "dismissed", "fixed"), "security_alert_unverifiable")
    if require_closed_alert:
        require(state == "fixed", "release_security_alert_not_fixed")
    return {
        "schema": "clawsweeper.codeql-evidence.v1",
        "run_id": run_id, "run_attempt": attempt, "event": event,
        "head_sha": head_sha, "pr_number": pr_number,
        "languages": sorted(LANGUAGES), "jobs": verified_jobs,
        "analyses": verified_analyses, "security_alert_3": state,
        "security_alert_3_fixed": state == "fixed",
        "scope": "read-only GitHub source and job proof; no release merge or deployment",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-id", required=True, type=int)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--pr", type=int)
    p.add_argument("--receipt-root", type=Path,
                   default=Path.home()/".local/share/local-ci/clawsweeper-selfhosted/receipts")
    p.add_argument("--require-alert-fixed", action="store_true")
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    try:
        result = verify_release(gh_get, args.run_id, args.head_sha, args.pr,
                                args.receipt_root, require_closed_alert=args.require_alert_fixed)
        result["verified_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with args.output.open("x") as out:
                json.dump(result, out, indent=2, sort_keys=True)
                out.write("\n")
            args.output.chmod(0o600)
        print(json.dumps({"status": "verified", **result}, sort_keys=True))
    except (EvidenceRefused, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "refused", "reason": type(exc).__name__,
                          "detail": str(exc)[:120]}, sort_keys=True))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
