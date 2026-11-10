#!/usr/bin/env python3
"""Reconcile exact-source CI execution evidence; never admit or replay a job.

A successful job, a complete workflow DAG, and a production effect are different
claims. This tool can verify CodeQL and direct-head ordinary validation. Every
other class remains held until its specialised effect/isolation verifier exists.
"""
import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import estate_policy
import verify_codeql_release

REPO = "AyobamiH/clawsweeper"
API = "repos/" + REPO
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\Z")
MAX_PAGES = 10
MAX_JSON = 8 * 1024 * 1024
CODEQL = ".github/workflows/codeql.yml#analyze"
# This adapter examined checkout/ref and command semantics for these exact bytes.
# A changed workflow requires explicit adapter review, not just matching names.
VALIDATION_WORKFLOW_SHA256 = "bebf237146b6d005e08cce433d6ea84525559d9441afa31443b78096c0364526"
VALIDATION = {
    ".github/workflows/ci.yml#check": ("check", "pnpm check", (
        "Set up job", "Run actions/checkout@v7", "Validate workflow semantics",
        "Run ./.github/actions/setup-pnpm", "Run full validation")),
    ".github/workflows/ci.yml#sparse-repair-builds": ("sparse", "sparse repair build smoke", (
        "Set up job", "Run actions/checkout@v7", "Run ./.github/actions/setup-pnpm",
        "Build each sparse repair checkout")),
}
CODEQL_STEPS = ("Set up job", "Run actions/checkout@v7",
                "Run github/codeql-action/init@v4", "Run github/codeql-action/analyze@v4")
MISSING = {
    "ordinary": "exact_job_receipt_steps_and_cleanup_required",
    "codeql": "both_languages_sarif_receipts_and_cleanup_required",
    "privileged": "authenticated_effect_and_recovery_adapter_required",
    "review": "provider_review_and_credential_isolation_proof_required",
    "e2e": "complete_rootless_scenario_and_cleanup_proof_required",
    "windows": "genuine_isolated_windows_execution_proof_required",
}


class Refused(RuntimeError):
    """Only fixed reason codes, never raw provider output, cross this boundary."""


def require(value, code):
    if not value:
        raise Refused(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def positive(value):
    return type(value) is int and value > 0


def github_get(path):
    """Explicit GET and hostname; there is no mutation, URL or method parameter."""
    prefix = re.escape(API) + "/"
    integer = r"[1-9][0-9]{0,18}"
    patterns = (
        r"commits/[0-9a-f]{40}",
        rf"actions/runs/{integer}",
        rf"actions/runs/{integer}/attempts/{integer}/jobs\?per_page=100&page={integer}",
        rf"actions/jobs/{integer}",
        rf"actions/runners\?per_page=100&page={integer}",
        r"contents/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\?ref=[0-9a-f]{40}",
        r"git/ref/heads/[A-Za-z0-9_./-]+",
        rf"git/ref/pull/{integer}/merge",
        rf"pulls/{integer}",
        rf"code-scanning/analyses\?per_page=100&page={integer}",
        r"code-scanning/alerts/3",
    )
    require(isinstance(path, str) and len(path) <= 500 and ".." not in path
            and any(re.fullmatch(prefix + p, path) for p in patterns),
            "github_endpoint_not_allowed")
    try:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET", path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
        require(result.returncode == 0 and len(result.stdout) <= MAX_JSON,
                "github_readback_unavailable")
        value = json.loads(result.stdout)
        require(isinstance(value, (dict, list)), "github_response_invalid")
        return value
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise Refused("github_readback_unavailable") from exc


def _git(checkout, *args):
    try:
        result = subprocess.run(["git", "--no-replace-objects", "-C", str(checkout), *args],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=25, check=False)
        require(result.returncode == 0 and len(result.stdout) <= MAX_JSON,
                "immutable_source_unavailable")
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("immutable_source_unavailable") from exc


def source_manifest(checkout, head_sha):
    require(isinstance(head_sha, str) and SHA.fullmatch(head_sha), "invalid_head_sha")
    require(Path(checkout).is_dir() and not Path(checkout).is_symlink(), "unsafe_checkout")
    require(_git(checkout, "rev-parse", head_sha + "^{commit}").decode().strip() == head_sha,
            "source_commit_mismatch")
    tree = _git(checkout, "rev-parse", head_sha + "^{tree}").decode().strip()
    raw = _git(checkout, "show", head_sha + ":config/ci-workflow-estate.json")
    try:
        manifest = json.loads(raw)
        require(isinstance(manifest, dict), "manifest_invalid")
        sources, jobs, summary = manifest["sources"], manifest["jobs"], manifest["summary"]
        require(manifest.get("schema") == "clawsweeper.workflow-estate.v2"
                and isinstance(sources, list) and isinstance(jobs, list)
                and isinstance(summary, dict) and sources and jobs
                and len(sources) == summary.get("workflows") and len(jobs) == summary.get("jobs")
                and summary.get("github_hosted") == 0
                and summary.get("dynamic_hosted_fallback") == 0, "manifest_invalid")
        source_map = {}
        for item in sources:
            name, expected = item["path"], item["sha256"]
            require(isinstance(name, str) and WORKFLOW.fullmatch(name)
                    and name not in source_map and isinstance(expected, str)
                    and DIGEST.fullmatch(expected), "manifest_source_invalid")
            actual = _git(checkout, "show", head_sha + ":" + name)
            require(digest(actual) == expected, "workflow_source_digest_mismatch")
            source_map[name] = expected
        listed = {}
        for record in _git(checkout, "ls-tree", "-r", "-z", head_sha, ".github/workflows").split(b"\0"):
            if not record:
                continue
            metadata, name = record.split(b"\t", 1)
            name = name.decode()
            if name.endswith((".yml", ".yaml")):
                require(metadata.split()[0] in (b"100644", b"100755"), "unsafe_workflow_object")
                listed[name] = True
        require(set(listed) == set(source_map), "workflow_inventory_incomplete")
        by_key = {}
        for job in jobs:
            require(isinstance(job, dict), "manifest_job_invalid")
            path, ident = job.get("workflow"), job.get("id")
            require(path in source_map and isinstance(ident, str)
                    and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]{0,100}", ident)
                    and job.get("source_sha256") == source_map[path]
                    and isinstance(job.get("events"), list)
                    and all(isinstance(e, str) for e in job["events"]), "manifest_job_invalid")
            key = path + "#" + ident
            require(key not in by_key, "duplicate_manifest_job")
            require(estate_policy.job_class(job) in MISSING, "unsupported_manifest_class")
            by_key[key] = job
        for key, job in by_key.items():
            needs = job.get("needs")
            require(isinstance(needs, list)
                    and all(isinstance(n, str) and job["workflow"] + "#" + n in by_key
                            for n in needs), "manifest_dag_incomplete")
        return {"head_sha": head_sha, "tree_sha": tree, "manifest_sha256": digest(raw),
                "sources": source_map, "jobs": by_key}
    except (KeyError, TypeError, ValueError, UnicodeError, estate_policy.Hold) as exc:
        raise Refused("manifest_invalid") from exc


def _pages(get, endpoint, key):
    result, seen, total = [], set(), None
    for page in range(1, MAX_PAGES + 1):
        response = get(endpoint + f"?per_page=100&page={page}")
        require(isinstance(response, dict), "page_inventory_invalid")
        entries, count = response.get(key), response.get("total_count")
        require(isinstance(entries, list) and len(entries) <= 100
                and type(count) is int and 0 <= count <= MAX_PAGES * 100
                and (total is None or count == total), "page_inventory_invalid")
        total = count
        for entry in entries:
            require(isinstance(entry, dict) and positive(entry.get("id"))
                    and entry["id"] not in seen, "page_identity_duplicate_or_invalid")
            seen.add(entry["id"])
            result.append(entry)
        if len(result) == total:
            return result
        require(len(entries) == 100 and len(result) < total, "page_inventory_truncated")
    raise Refused("page_inventory_limit")


def attempt_jobs(get, run_id, attempt):
    require(positive(run_id) and positive(attempt), "invalid_attempt_identity")
    jobs = _pages(get, f"{API}/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    for job in jobs:
        require(job.get("run_id") == run_id
                and type(job.get("run_attempt", attempt)) is int
                and job.get("run_attempt", attempt) == attempt, "job_attempt_mismatch")
    return jobs


def _directory(path, *, private=False, create=False):
    """Walk with directory descriptors: no symlinked ancestor is followed."""
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        info = os.fstat(fd)
        if private:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "unsafe_private_directory")
        return fd
    except (OSError, Refused):
        os.close(fd)
        raise Refused("unsafe_private_directory")


def _file(fd, name, *, limit=MAX_JSON):
    require(isinstance(name, str) and name not in (".", "..")
            and "/" not in name, "unsafe_evidence_name")
    handle = None
    try:
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        info = os.fstat(handle)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and info.st_size <= limit, "unsafe_evidence_file")
        result = bytearray()
        while True:
            chunk = os.read(handle, min(65536, limit + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            require(len(result) <= limit, "evidence_file_too_large")
        after = os.fstat(handle)
        require(len(result) == info.st_size
                and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "evidence_file_changed")
        return bytes(result)
    except OSError as exc:
        raise Refused("evidence_file_unavailable") from exc
    finally:
        if handle is not None:
            os.close(handle)


def receipt_proof(root, run, job, *, role, label, replacement=False):
    run_id, job_id, attempt = run["id"], job["id"], run["run_attempt"]
    name = f"csw-ci-{run_id}-{job_id}-{attempt}" + ("-replacement-1" if replacement else "")
    require(job.get("runner_name") == name and positive(job.get("runner_id")), "runner_identity_mismatch")
    require(isinstance(job.get("labels"), list)
            and all(isinstance(x, str) for x in job["labels"])
            and {"self-hosted", "Linux", "X64", label} <= set(job["labels"])
            and job["labels"].count(label) == 1, "runner_label_mismatch")
    leaf = f"run-{run_id}-job-{job_id}-attempt-{attempt}" + ("-replacement-1" if replacement else "")
    root_fd = _directory(root, private=True)
    os.close(root_fd)
    fd = _directory(Path(root) / leaf, private=True)
    try:
        raw = _file(fd, "receipt.json")
        receipt = json.loads(raw)
        require(isinstance(receipt, dict)
                and receipt.get("schema") == "clawsweeper.selfhosted-jit.v1"
                and all(positive(receipt.get(k)) for k in ("run_id", "job_id", "attempt", "runner_id"))
                and receipt.get("run_id") == run_id and receipt.get("job_id") == job_id
                and receipt.get("attempt") == attempt and receipt.get("head_sha") == run["head_sha"]
                and receipt.get("workflow") == run["path"] and receipt.get("event") == run["event"]
                and receipt.get("runner_name") == name and receipt.get("runner_id") == job["runner_id"]
                and receipt.get("role") == role and receipt.get("label") == label
                and receipt.get("state") == "passed" and receipt.get("issues") == []
                and type(receipt.get("runner_exit")) is int and receipt["runner_exit"] == 0
                and re.fullmatch(r"sha256:[0-9a-f]{64}", str(receipt.get("image_sha256", ""))),
                "runner_receipt_identity_invalid")
        provider = receipt.get("github_job")
        require(isinstance(provider, dict) and provider.get("id") == job_id
                and provider.get("run_id") == run_id and provider.get("status") == "completed"
                and provider.get("conclusion") == "success" and provider.get("runner_name") == name,
                "runner_receipt_provider_mismatch")
        log = _file(fd, "runner.log", limit=128 * 1024 * 1024)
        require(type(receipt.get("log_bytes")) is int and receipt["log_bytes"] == len(log)
                and receipt.get("log_sha256") == digest(log), "runner_log_digest_mismatch")
        proof = {"runner_name": name, "runner_id": job["runner_id"],
                 "image_sha256": receipt["image_sha256"], "receipt_sha256": digest(raw),
                 "log_sha256": digest(log), "log_bytes": len(log)}
        if replacement:
            require(isinstance(receipt.get("original_receipt_sha256"), str)
                    and DIGEST.fullmatch(receipt["original_receipt_sha256"]),
                    "replacement_original_digest_missing")
            proof["original_receipt_sha256"] = receipt["original_receipt_sha256"]
        return proof
    except (ValueError, TypeError) as exc:
        raise Refused("runner_receipt_invalid") from exc
    finally:
        os.close(fd)


def replacement_cleanup_subject(root, run, job, proof):
    """Refresh the original identity after the existing lineage adapter passes.

    Historical recovery absence is not current cleanup. Bind the original
    private receipt to the replacement's digest and inspect both live identities.
    This record is cleanup-only: it does not claim the interrupted job passed.
    """
    run_id, job_id, attempt = run["id"], job["id"], run["run_attempt"]
    name = f"csw-ci-{run_id}-{job_id}-{attempt}"
    folder = Path(root) / f"run-{run_id}-job-{job_id}-attempt-{attempt}"
    fd = _directory(folder, private=True)
    try:
        raw = _file(fd, "receipt.json")
        require(digest(raw) == proof["original_receipt_sha256"],
                "replacement_original_changed")
        original = json.loads(raw)
        require(isinstance(original, dict)
                and original.get("schema") == "clawsweeper.selfhosted-jit.v1"
                and original.get("run_id") == run_id and original.get("job_id") == job_id
                and original.get("attempt") == attempt and original.get("head_sha") == run["head_sha"]
                and original.get("runner_name") == name and positive(original.get("runner_id"))
                and original["runner_id"] != proof["runner_id"]
                and original.get("role") == "security" and original.get("workflow") == run["path"]
                and original.get("image_sha256") == proof["image_sha256"]
                and original.get("state") in ("registered", "runner_started")
                and original.get("finished_at") is None,
                "replacement_original_cleanup_identity_invalid")
        return {"runner_name": name, "runner_id": original["runner_id"],
                "receipt_sha256": digest(raw), "cleanup_only": True}
    except (ValueError, TypeError) as exc:
        raise Refused("replacement_original_cleanup_identity_invalid") from exc
    finally:
        os.close(fd)


def complete_steps(job, required):
    require(job.get("status") == "completed" and job.get("conclusion") == "success",
            "job_not_successful")
    try:
        start = dt.datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
        end = dt.datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
        require(start.tzinfo is not None and end.tzinfo is not None and start <= end,
                "job_timing_invalid")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise Refused("job_timing_invalid") from exc
    steps = job.get("steps")
    require(isinstance(steps, list) and steps, "job_steps_missing")
    numbers, names = [], []
    for step in steps:
        require(isinstance(step, dict) and positive(step.get("number"))
                and isinstance(step.get("name"), str)
                and step.get("status") == "completed" and step.get("conclusion") == "success",
                "step_missing_skipped_or_failed")
        numbers.append(step["number"])
        names.append(step["name"])
    require(numbers == sorted(set(numbers)) and all(names.count(n) == 1 for n in required),
            "required_steps_missing_or_ambiguous")
    positions = [names.index(n) for n in required]
    require(positions == sorted(positions), "required_step_order_changed")
    return digest(canonical(steps))


def owned_containers_absent(runner_name):
    require(re.fullmatch(r"csw-ci-[1-9][0-9]*-[1-9][0-9]*-[1-9][0-9]*(?:-replacement-1)?",
                         str(runner_name)), "unsafe_runner_name")
    # Reuse the executor's exact ownership label; never inspect/mutate unrelated containers.
    from self_hosted_executor import LABEL
    try:
        result = subprocess.run(["docker", "ps", "--all", "--filter", f"label={LABEL}={runner_name}",
                                 "--format", "{{.ID}}"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=15, check=False)
        require(result.returncode == 0, "container_inventory_unavailable")
        return result.stdout.strip() == b""
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("container_inventory_unavailable") from exc


def cleanup_proof(get, proofs, containers):
    runners = _pages(get, API + "/actions/runners", "runners")
    for proof in proofs:
        require(not any(r.get("id") == proof["runner_id"]
                        or r.get("name") == proof["runner_name"] for r in runners),
                "owned_runner_still_registered")
        require(containers(proof["runner_name"]) is True, "owned_container_cleanup_unverified")


def _run_identity(run):
    return {k: run.get(k) for k in ("id", "head_sha", "path", "run_attempt", "event", "head_branch")}


def _job_identity(job):
    return {k: job.get(k) for k in ("id", "run_id", "head_sha", "run_attempt", "name", "status",
            "conclusion", "started_at", "completed_at", "runner_id", "runner_name", "labels", "steps")}


def verify_run(source, run_id, receipts, get, containers):
    require(positive(run_id), "invalid_run_id")
    run = get(f"{API}/actions/runs/{run_id}")
    require(isinstance(run, dict) and run.get("id") == run_id
            and isinstance(run.get("repository"), dict)
            and run["repository"].get("full_name") == REPO, "run_repository_mismatch")
    require(run.get("head_sha") == source["head_sha"], "run_head_mismatch")
    require(positive(run.get("run_attempt")) and run.get("path") in source["sources"],
            "run_source_or_attempt_invalid")
    path = run["path"]
    obj = get(f"{API}/contents/{path}?ref={source['head_sha']}")
    try:
        require(isinstance(obj, dict) and obj.get("encoding") == "base64"
                and isinstance(obj.get("content"), str), "provider_workflow_unverifiable")
        workflow = base64.b64decode(obj["content"].replace("\n", ""), validate=True)
        require(digest(workflow) == source["sources"][path], "provider_workflow_digest_mismatch")
    except (ValueError, TypeError) as exc:
        raise Refused("provider_workflow_unverifiable") from exc
    jobs = attempt_jobs(get, run_id, run["run_attempt"])
    for job in jobs:
        require(job.get("head_sha", source["head_sha"]) == source["head_sha"], "job_head_mismatch")
    accepted, proofs, observed_jobs, recovered_originals = {}, [], [], []
    if path == ".github/workflows/codeql.yml":
        require(len(jobs) == 2 and CODEQL in source["jobs"], "codeql_job_inventory_invalid")
        pr_number = None
        if run.get("event") == "pull_request":
            prs = run.get("pull_requests")
            require(isinstance(prs, list) and len(prs) == 1 and positive(prs[0].get("number")),
                    "codeql_pr_identity_invalid")
            pr_number = prs[0]["number"]
        # The existing adapter requests a latest-attempt jobs endpoint. Bind
        # that request to this fully enumerated exact-attempt snapshot instead.
        def bound_get(endpoint):
            if endpoint == f"{API}/actions/runs/{run_id}/jobs?per_page=100":
                return {"total_count": len(jobs), "jobs": jobs}
            return get(endpoint)
        for language, name in verify_codeql_release.LANGUAGES.items():
            matching = [j for j in jobs if j.get("name") == name]
            require(len(matching) == 1, "codeql_language_missing_or_duplicate")
            job = matching[0]
            complete_steps(job, CODEQL_STEPS)
            baseline = f"csw-ci-{run_id}-{job['id']}-{run['run_attempt']}"
            replacement = job.get("runner_name") == baseline + "-replacement-1"
            proofs.append(receipt_proof(receipts, run, job, role="security",
                          label=f"clawsweeper-ci-security-{run_id}-{language}", replacement=replacement))
            observed_jobs.append(job)
        try:
            original = verify_codeql_release.verify_release(bound_get, run_id, source["head_sha"],
                                                            pr_number, receipts)
        except verify_codeql_release.EvidenceRefused as exc:
            raise Refused("codeql_adapter_refused") from exc
        require(original.get("head_sha") == source["head_sha"]
                and original.get("run_attempt") == run["run_attempt"], "codeql_adapter_identity_mismatch")
        for job, proof in zip(observed_jobs, proofs):
            if "original_receipt_sha256" in proof:
                recovered_originals.append(replacement_cleanup_subject(receipts, run, job, proof))
        accepted[CODEQL] = {"run_id": run_id, "attempt": run["run_attempt"],
                            "job_ids": [j["id"] for j in observed_jobs],
                            "adapter": "existing_codeql_release_plus_cleanup",
                            "sarif": original["analyses"], "security_alert_3": original["security_alert_3"]}
    else:
        keys = [key for key in VALIDATION if key in source["jobs"] and key.startswith(path + "#")]
        require(keys, "specialised_effect_adapter_required")
        require(source["sources"][path] == VALIDATION_WORKFLOW_SHA256,
                "validation_workflow_adapter_review_required")
        require(run.get("event") in ("push", "workflow_dispatch"), "executed_pr_merge_attestation_required")
        for key in keys:
            slot, name, required = VALIDATION[key]
            matching = [j for j in jobs if j.get("name") == name]
            if not matching:
                continue
            require(len(matching) == 1, "validation_job_identity_ambiguous")
            job = matching[0]
            if run["event"] not in source["jobs"][key]["events"]:
                # A PR-only sparse job is legitimately skipped on dispatch.
                # This is not sparse acceptance and must not erase the separate
                # full-check job's genuine evidence.
                require(job.get("status") == "completed" and job.get("conclusion") == "skipped",
                        "validation_event_not_allowed")
                continue
            steps_hash = complete_steps(job, required)
            proof = receipt_proof(receipts, run, job, role="validation",
                                   label=f"clawsweeper-ci-validation-{run_id}-{slot}")
            proofs.append(proof)
            observed_jobs.append(job)
            accepted[key] = {"run_id": run_id, "attempt": run["run_attempt"], "job_ids": [job["id"]],
                             "adapter": "direct_head_validation", "steps_sha256": steps_hash}
        require(accepted, "supported_job_evidence_missing")
    cleanup_proof(get, proofs + recovered_originals, containers)
    for job in observed_jobs:
        final_job = get(f"{API}/actions/jobs/{job['id']}")
        require(_job_identity(final_job) == _job_identity(job), "job_changed_during_observation")
    final_run = get(f"{API}/actions/runs/{run_id}")
    require(_run_identity(final_run) == _run_identity(run), "run_changed_during_observation")
    for value in accepted.values():
        value["workflow_sha256"] = source["sources"][path]
        value["runner_proofs"] = [p for p in proofs if any(
            p["runner_name"].startswith(f"csw-ci-{run_id}-{j}-") for j in value["job_ids"])]
        value["recovered_originals"] = recovered_originals
        value["owned_runners_absent"] = True
        value["owned_containers_absent"] = True
    return accepted


def build_report(checkout, head_sha, run_ids, receipts, *, get=github_get,
                 containers=owned_containers_absent):
    require(isinstance(run_ids, (list, tuple)) and len(run_ids) <= 12
            and all(positive(r) for r in run_ids) and len(set(run_ids)) == len(run_ids), "invalid_run_selection")
    source = source_manifest(checkout, head_sha)
    commit = get(f"{API}/commits/{head_sha}")
    require(isinstance(commit, dict) and commit.get("sha") == head_sha
            and isinstance(commit.get("commit"), dict)
            and isinstance(commit["commit"].get("verification"), dict)
            and isinstance(commit["commit"].get("tree"), dict)
            and commit["commit"]["verification"].get("verified") is True
            and commit.get("commit", {}).get("tree", {}).get("sha") == source["tree_sha"],
            "github_source_signature_or_tree_unverified")
    rows = {}
    for key, job in source["jobs"].items():
        kind = estate_policy.job_class(job)
        rows[key] = {"job_key": key, "class": kind, "status": "held",
                     "missing": [MISSING[kind]], "execution_proofs": [],
                     "production_effect_verified": False}
    attempts = []
    for run_id in run_ids:
        try:
            verified = verify_run(source, run_id, receipts, get, containers)
            for key, proof in verified.items():
                rows[key]["status"] = "execution_verified"
                rows[key]["missing"] = []
                rows[key]["execution_proofs"].append(proof)
            attempts.append({"run_id": run_id, "state": "execution_verified", "job_keys": sorted(verified)})
        except (Refused, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
            reason = str(exc) if isinstance(exc, Refused) else "evidence_readback_unavailable"
            attempts.append({"run_id": run_id, "state": "held", "reason": reason})
    verified_count = sum(r["status"] == "execution_verified" for r in rows.values())
    return {"schema": "clawsweeper.estate-execution-evidence.v1", "repo": REPO,
            "head_sha": head_sha, "tree_sha": source["tree_sha"],
            "manifest_sha256": source["manifest_sha256"],
            "verifier_sha256": digest(Path(__file__).read_bytes()),
            "workflows": len(source["sources"]), "job_definitions": len(rows),
            "execution_verified_jobs": verified_count, "held_jobs": len(rows) - verified_count,
            "workflow_dag_accepted": False, "production_release_accepted": False,
            "provider_mutations": 0,
            "readback_complete": all(a["state"] == "execution_verified" for a in attempts),
            "attempts": attempts, "jobs": [rows[k] for k in sorted(rows)]}


def _write_private(fd, name, raw, *, create_only=False):
    # Write and fsync a private temporary inode before publishing it. Never
    # replace a content-addressed report, and never follow an existing link.
    tmp = f".writing-{os.getpid()}-{os.urandom(8).hex()}"
    handle = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            old = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None:
            require(stat.S_ISREG(old.st_mode) and old.st_nlink == 1 and old.st_uid == os.getuid()
                    and stat.S_IMODE(old.st_mode) == 0o600, "unsafe_existing_report")
        if create_only:
            if old is not None:
                require(_file(fd, name) == raw, "content_addressed_report_conflict")
            else:
                os.link(tmp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        else:
            os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(tmp, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.fsync(fd)


def observe(checkout, head_sha, run_ids, receipts, output_dir, *, get=github_get,
            containers=owned_containers_absent):
    fd = _directory(output_dir, private=True, create=True)
    lock = None
    stamp = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        lock = os.open("owner.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, "unsafe_observation_lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("another_observer_owns_output") from exc
        base = {"observed_at": stamp, "production_release_accepted": False, "provider_mutations": 0}
        # Invalidate the previous observation BEFORE reads; interruption cannot
        # leave an old green pointer presented as the current attempt.
        _write_private(fd, "latest.json", canonical({**base, "state": "observing"}))
        try:
            report = build_report(checkout, head_sha, run_ids, receipts, get=get, containers=containers)
            raw = canonical(report)
            identity = digest(raw)
            _write_private(fd, identity + ".json", raw, create_only=True)
            outcome = {**base, "state": "partial", "head_sha": head_sha,
                       "report": identity + ".json", "report_sha256": identity,
                       "job_definitions": report["job_definitions"],
                       "execution_verified_jobs": report["execution_verified_jobs"],
                       "held_jobs": report["held_jobs"]}
            _write_private(fd, "latest.json", canonical(outcome))
            return outcome
        except (Refused, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
            reason = str(exc) if isinstance(exc, Refused) else "observation_unverifiable"
            outcome = {**base, "state": "unverified", "reason": reason}
            _write_private(fd, "latest.json", canonical(outcome))
            return outcome
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--run-id", type=int, action="append", default=[])
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        outcome = observe(args.checkout, args.head_sha, args.run_id, args.receipt_root, args.output_dir)
    except (Refused, OSError, ValueError) as exc:
        outcome = {"state": "unverified", "reason": str(exc) if isinstance(exc, Refused) else "output_unavailable",
                   "production_release_accepted": False, "provider_mutations": 0}
    print(json.dumps(outcome, sort_keys=True))
    # This first adapter set deliberately cannot certify the complete estate.
    return 2 if outcome["state"] == "partial" else 1


if __name__ == "__main__":
    sys.exit(main())
