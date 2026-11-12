"""Dedicated, default-denied rootless E2E driver for ONE exact workflow.

Reuses the already guarded isolation JIT, not CodeQL/ops or the host Docker
socket. Both estate and legacy admissions must independently agree. No
automatic runner registration happens absent explicit run/job/image/source
authority and installed owner controls. A lost POST response is never retried.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from estate_policy import Hold, REPO
import self_hosted_executor as legacy

E2E_KEY = ".github/workflows/automerge-e2e.yml#automerge-e2e"
SHA64 = re.compile(r"^[a-f0-9]{64}$")
SHA40 = re.compile(r"^[a-f0-9]{40}$")


def _exact_identity(candidate, controls):
    approved = controls.get("approved_jobs", {}).get(E2E_KEY)
    if not isinstance(approved, dict):
        raise Hold("e2e_dedicated_approval_missing")
    record = {
        "run_id": candidate.run_id, "job_id": candidate.job_id,
        "attempt": candidate.attempt, "head_sha": candidate.sha,
        "job_name": candidate.name,
    }
    if (candidate.job_key != E2E_KEY or candidate.job_class != "e2e"
            or candidate.workflow != ".github/workflows/automerge-e2e.yml"
            or candidate.name != "production automerge flow"
            or candidate.event != "pull_request"
            or candidate.label != f"clawsweeper-ci-isolation-{candidate.run_id}-e2e"
            or candidate.branch in ("", "main")
            or not isinstance(candidate.sha, str) or not SHA40.fullmatch(candidate.sha)):
        raise Hold("e2e_not_exact_isolated_pr_job")
    if (controls.get("enabled_classes") != ["e2e"]
            or controls.get("operations_accepted") is not False
            or controls.get("model_inference_permitted") is not False
            or controls.get("isolation_accepted") is not True
            or controls.get("rootless_nested_container_proven") is not True
            or controls.get("e2e_dedicated_driver_accepted") is not True
            or controls.get("enabled_roles") != ["isolation"]
            or controls.get("allowed_run_ids") != [candidate.run_id]
            or approved.get("class") != "e2e"
            or approved.get("run_ids") != [candidate.run_id]
            or approved.get("head_shas") != [candidate.sha]
            or approved.get("approved_attempts") != [record]
            or approved.get("no_host_docker_socket") is not True
            or approved.get("full_scenarios") is not True):
        raise Hold("e2e_isolation_scope_not_exclusive")
    pinned_image = controls.get("isolation_image_sha256")
    if (not isinstance(pinned_image, str) or not pinned_image.startswith("sha256:")
            or not SHA64.fullmatch(pinned_image[7:])
            or approved.get("image_sha256") != pinned_image[7:]):
        raise Hold("e2e_rootless_image_not_pinned")
    digest = approved.get("source_sha256")
    if (not isinstance(digest, str) or not SHA64.fullmatch(digest)
            or controls.get("isolation_workflow_sha256") != digest
            or controls.get("isolation_head_sha") != candidate.sha):
        raise Hold("e2e_workflow_source_not_pinned")
    harness = controls.get("isolation_harness_sha256")
    if (not isinstance(harness, dict)
            or set(harness) != set(legacy.ISOLATION_HARNESS_FILES)
            or any(not isinstance(x, str) or not SHA64.fullmatch(x)
                   for x in harness.values())):
        raise Hold("e2e_harness_source_not_pinned")
    return pinned_image


def _receipt(path):
    if not isinstance(path, Path):
        raise Hold("e2e_receipt_path_invalid")
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 256 * 1024):
            raise Hold("e2e_receipt_unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            body = os.read(fd, 256 * 1024 + 1)
            identity = os.fstat(fd)
            if (identity.st_ino != info.st_ino or identity.st_dev != info.st_dev
                    or identity.st_size != len(body)):
                raise Hold("e2e_receipt_changed")
        finally:
            os.close(fd)
        result = json.loads(body)
        if not isinstance(result, dict):
            raise Hold("e2e_receipt_invalid")
        return result
    except (OSError, ValueError, TypeError) as exc:
        raise Hold("e2e_receipt_unreadable") from exc


def _verified_log_digest(path, expected_digest, expected_bytes):
    """Rehash the sealed, owned worker log independently of its own receipt.

    Never follow symlinks or read an unbounded log. A digest supplied by the
    process that created the file is a claim, not independent verification.
    """
    limit = 128 * 1024 * 1024
    if (not isinstance(path, Path)
            or not isinstance(expected_digest, str) or not SHA64.fullmatch(expected_digest)
            or type(expected_bytes) is not int
            or expected_bytes < 0 or expected_bytes > limit):
        raise Hold("e2e_runner_log_metadata_invalid")
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size != expected_bytes):
            raise Hold("e2e_runner_log_unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or opened.st_size != expected_bytes):
                raise Hold("e2e_runner_log_changed")
            digest, count = hashlib.sha256(), 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > limit:
                    raise Hold("e2e_runner_log_too_large")
                digest.update(chunk)
            after = os.fstat(fd)
            if (count != expected_bytes or
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                     opened.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                     after.st_ctime_ns)):
                raise Hold("e2e_runner_log_changed")
        finally:
            os.close(fd)
    except OSError as exc:
        raise Hold("e2e_runner_log_unreadable") from exc
    actual = digest.hexdigest()
    if actual != expected_digest:
        raise Hold("e2e_runner_log_digest_mismatch")
    return actual


def execute(candidate, controls, *, api=None):
    """One irreversible JIT attempt, after *two* exact policy admissions.

    The caller owns the shared fleet/executor locks and has already persisted
    its one-shot SlotLedger reservation. No retries here or by this controller.
    """
    image = _exact_identity(candidate, controls)
    api = api or legacy.gh
    run = api(f"repos/{REPO}/actions/runs/{candidate.run_id}")
    job = api(f"repos/{REPO}/actions/jobs/{candidate.job_id}")
    if not isinstance(run, dict) or not isinstance(job, dict):
        raise Hold("e2e_live_run_job_unreadable")
    pulls = run.get("pull_requests")
    if (run.get("id") != candidate.run_id or run.get("head_sha") != candidate.sha
            or run.get("run_attempt") != candidate.attempt
            or run.get("event") != candidate.event
            or run.get("head_branch") != candidate.branch
            or run.get("path") != candidate.workflow
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("full_name") != REPO
            or (candidate.actor_login is not None
                and candidate.actor_login !=
                (run.get("actor") or {}).get("login"))
            or not isinstance(pulls, list) or len(pulls) != 1
            or type(pulls[0].get("number")) is not int
            or pulls[0]["number"] <= 0
            or job.get("id") != candidate.job_id
            or job.get("run_id") != candidate.run_id
            or job.get("name") != candidate.name
            or job.get("status") != "queued"
            or job.get("runner_id") not in (None, 0)
            or job.get("runner_name") not in (None, "")):
        raise Hold("e2e_live_run_job_identity_changed")
    number = pulls[0]["number"]
    pr = api(f"repos/{REPO}/pulls/{number}")
    if not isinstance(pr, dict):
        raise Hold("e2e_pr_unreadable")
    if (pr.get("number") != number or pr.get("state") != "open"
            or pr.get("head", {}).get("sha") != candidate.sha
            or pr.get("head", {}).get("ref") != candidate.branch
            or pr.get("head", {}).get("repo", {}).get("full_name") != REPO
            or pr.get("base", {}).get("repo", {}).get("full_name") != REPO):
        raise Hold("e2e_pr_provenance_changed")
    # No synthetic fields are trusted: the repository, head and base are all
    # authenticated live GitHub objects, then legacy.classify rechecks them.
    enriched = dict(run)
    enriched["pull_requests"] = [{"number": number, "head": pr["head"], "base": pr["base"]}]
    legacy_candidate = legacy.classify(enriched, job)
    if (legacy_candidate.role != "isolation" or legacy_candidate.slot != "e2e"
            or legacy_candidate.run_id != candidate.run_id
            or legacy_candidate.job_id != candidate.job_id
            or legacy_candidate.run_attempt != candidate.attempt
            or legacy_candidate.sha != candidate.sha
            or legacy_candidate.label != candidate.label):
        raise Hold("e2e_legacy_isolation_contract_mismatch")
    if (controls.get("isolation_pr_number") != number
            or controls.get("isolation_base_sha") != legacy_candidate.trusted_base_sha
            or controls.get("isolation_base_ref") != pr["base"]["ref"]):
        raise Hold("e2e_isolation_base_not_owner_pinned")
    # The legacy layer independently checks the signed PR source, synthetic
    # merge parents, exact executable harness and rootless image digest.
    try:
        legacy.category_enabled(legacy_candidate, controls)
        legacy.source_authorised(legacy_candidate, controls)
        if legacy.approved_job_image(legacy_candidate, controls) != image:
            raise Hold("e2e_isolation_image_drift")
    except legacy.AdmissionHold as exc:
        raise Hold("e2e_legacy_admission_refused") from exc
    result = legacy.runner_job(legacy_candidate, controls)  # ONE JIT POST at most
    expected = legacy.RECEIPTS / (
        f"run-{candidate.run_id}-job-{candidate.job_id}-attempt-{candidate.attempt}"
    ) / "receipt.json"
    if (not isinstance(result, dict) or result.get("state") != "passed"
            or result.get("receipt") != str(expected)):
        raise Hold("e2e_jit_result_unverified")
    receipt = _receipt(expected)
    proof = receipt.get("e2e_proof")
    if (receipt.get("state") != "passed" or receipt.get("role") != "isolation"
            or receipt.get("issues") != []
            or type(receipt.get("runner_exit")) is not int
            or receipt["runner_exit"] != 0
            or receipt.get("run_id") != candidate.run_id
            or receipt.get("job_id") != candidate.job_id
            or receipt.get("attempt") != candidate.attempt
            or receipt.get("head_sha") != candidate.sha
            or receipt.get("image_sha256") != image
            or receipt.get("label") != candidate.label
            or not isinstance(proof, dict)
            or proof.get("verdict") != "INDEPENDENT_E2E_VAULT_PASS"
            or proof.get("cases") != 28
            or any(not isinstance(proof.get(k), str) or not SHA64.fullmatch(proof[k])
                   for k in ("manifest_sha256", "receipt_sha256"))):
        raise Hold("e2e_28_case_or_runner_receipt_invalid")
    name, runner_id = receipt.get("runner_name"), receipt.get("runner_id")
    if (not isinstance(name, str) or not name
            or type(runner_id) is not int or runner_id <= 0):
        raise Hold("e2e_runner_identity_missing")
    # Independent provider readback after the JIT action and cleanup. Never
    # use a runner-provided boolean to prove provider success or deregistration.
    terminal = api(f"repos/{REPO}/actions/jobs/{candidate.job_id}")
    if not isinstance(terminal, dict):
        raise Hold("e2e_terminal_job_unreadable")
    terminal_ok = (terminal.get("id") == candidate.job_id
                   and terminal.get("run_id") == candidate.run_id
                   and terminal.get("runner_name") == name
                   and type(terminal.get("runner_id")) is int
                   and terminal["runner_id"] == runner_id
                   and terminal.get("status") == "completed"
                   and terminal.get("conclusion") == "success")
    try:
        legacy.runner_absent_verified(runner_id, name)
        runner_absent = True
        containers_absent = all(
            legacy.inspect_owned(name + suffix, name) is None
            for suffix in ("-worker", "-net"))
    except Exception:
        runner_absent = containers_absent = False
    digest = _verified_log_digest(expected.parent / "runner.log",
                                  receipt.get("log_sha256"),
                                  receipt.get("log_bytes"))
    return {
        "run_id": candidate.run_id, "job_id": candidate.job_id,
        "attempt": candidate.attempt, "log_sha256": digest,
        "github_terminal_verified": terminal_ok,
        "runner_absent_verified": runner_absent,
        "containers_absent_verified": containers_absent,
        "all_scenarios_verified": True,
        "rootless_runtime_verified": True,
        "e2e_manifest_sha256": proof["manifest_sha256"],
        "e2e_seal_sha256": proof["receipt_sha256"],
    }
