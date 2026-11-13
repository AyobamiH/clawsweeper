#!/usr/bin/env python3
"""Bounded, exclusive ClawSweeper ephemeral GitHub Actions JIT executor.

One queued job per invocation. Defaults to inspect-only; mutations require an
owner-only 0600 controls file. No GH-hosted runner, personal host mounts, host
Docker socket or model inference is exposed to executable workflow code.
"""
import argparse
import binascii
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import sys
import time

from self_hosted_policy import AdmissionHold, ISOLATION_HARNESS_FILES, REPOSITORY, REVIEW_EVENTS, SHA, WORKFLOWS, category_enabled, classify, is_release_preview
from e2e_evidence_vault import (EvidenceHold, MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES,
                                VOLUME_BYTES, VOLUME_INODES, VOLUME_OPTIONS,
                                _relative, create_vault, mount_args, verify_vault, volume_name)

HOME = Path.home()
ROOT = HOME / ".local/share/local-ci/clawsweeper-selfhosted"
CONTROLS = ROOT / "controls.json"
OWNER_CODEQL_LOCK = ROOT / "owner-codeql-acceptance.lock"
LOCK = ROOT / "executor.lock"
FLEET_DB = HOME / ".local/share/local-ci/fleet.sqlite3"
FLEET_CONTROL_LOCK = HOME / ".local/share/local-ci/control.lock"
FLEET_OWNER_MARKER = HOME / ".local/share/local-ci/OWNED_BY_LOCAL_CI"
# Existing canonical test-owner lock: runner JIT and full-source CI must
# share this inode until all owner launchers use one durable admission API.
CANONICAL_TEST_LOCK = HOME / ".local/share/local-ci/evidence/clawsweeper-closeout-20261107/review-p1-exact-full-20261107.lock"
RECEIPTS = ROOT / "receipts"
IMAGE = "sha256:c1f057b23404d71586056d3333e333099c3301e84cc2583c592907a8b56597d3"
SECURITY_IMAGE_NAME = "clawsweeper-codeql-runner:node24-codeql-2.27.4"
# A disposable rootless Podman image; never the generic CI runner or the
# host's Docker daemon. Its immutable digest must be owner-approved per run.
ISOLATION_IMAGE_NAME = "clawsweeper-jit-isolated-web:pr109-20261108"
NETWORK_IMAGE = "sha256:f9e6f27cf17460dfb82250c5ac94f5a829956692c2e47615a870a4ec9312b802"
LABEL = "io.ayobamih.clawsweeper.selfhosted"
REPO_SLUG = "repos/" + REPOSITORY
MAX_SECONDS = 42 * 60
# The full 14 tiny + 14 OpenClaw-shaped scenarios exceed 70 minutes on the
# rootless owner fleet. GitHub's workflow permits 120 minutes; terminate
# by 115 minutes to reserve five minutes for verified cleanup and deregistration.
# Never extend the privileged/security role deadlines.
ISOLATION_MAX_SECONDS = 115 * 60
# Kernel-enforced isolation Docker CLI output limit; verification alone is too late.
ISOLATION_MAX_LOG_BYTES = 128 * 1024 * 1024
# Per-job Docker-local tmpfs quota covers the entire Actions Runner home,
# including JIT helper state, workspace and rootless Podman vfs. Docker's
# overlay2 on ext4 cannot enforce a writable-root size: it MUST be read-only.
ISOLATION_HOME_VOLUME_BYTES = 3 * 1024 * 1024 * 1024
ISOLATION_HOME_VOLUME_INODES = 262144
ISOLATION_HOME_OPTIONS = (
    f"size={ISOLATION_HOME_VOLUME_BYTES},nr_inodes={ISOLATION_HOME_VOLUME_INODES},"
    "uid=1001,gid=1001,mode=0750"
)
ISOLATION_WORKER_TMPFS = (
    "/tmp:rw,nosuid,nodev,size=256m,nr_inodes=32768,mode=1777",
    "/var/tmp:rw,nosuid,nodev,size=64m,nr_inodes=8192,mode=1777",
    "/run:rw,nosuid,nodev,size=64m,nr_inodes=8192,mode=0755",
)


def runner_limits(candidate):
    if candidate.role == "isolation":
        return ISOLATION_MAX_SECONDS, "4g"
    return MAX_SECONDS, "4g" if candidate.role == "security" else "2g"


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or (path.stat().st_mode & 0o077):
        raise RuntimeError("unsafe_state_permissions")


def atomic(path, record):
    private_dir(path.parent)
    tmp = path.with_name(path.name + f".{os.getpid()}.new")
    content = json.dumps(record, sort_keys=True, indent=2).encode() + b"\n"
    with tmp.open("xb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# Diagnostic values are deliberately closed vocabularies. Raw subprocess output,
# command arguments, exception messages and JIT credentials never enter receipts.
FAILURE_PHASES = frozenset({"registration_request", "registration_response",
                            "network_preparation", "runner_execution",
                            "github_job_readback", "isolation_evidence"})
FAILURE_CODES = frozenset({"command_timeout", "external_command_refused",
                          "github_response_invalid", "jit_registration_response_incomplete"})
TRANSPORT_HINTS = {
    "network_unreachable": ("network is unreachable", "no route to host"),
    "dns_lookup_failed": ("no such host", "temporary failure in name resolution"),
    "tls_failure": ("tls:", "x509:"),
    "connection_refused": ("connection refused",),
    "connection_reset": ("connection reset by peer",),
    "timeout": ("i/o timeout", "context deadline exceeded"),
}


def cli_failure(code, args, *, returncode=None, stderr=None):
    """Keep safe metadata without changing the existing RuntimeError contract."""
    error = RuntimeError(code)
    metadata = {"cli_exit_code": returncode if type(returncode) is int and -255 <= returncode <= 255 else None,
                "http_status": None, "transport_hint": "timeout" if code == "command_timeout" else None}
    is_github = (len(args) >= 2 and isinstance(args[0], str)
                 and Path(args[0]).name == "gh" and args[1] == "api")
    if is_github and isinstance(stderr, str):
        # Inspect only a bounded suffix. HTTP metadata must be the CLI's final
        # status-shaped line; an arbitrary embedded '(HTTP ...)' is not enough.
        tail = stderr[-8192:].rstrip()
        last = tail.splitlines()[-1] if tail else ""
        match = re.fullmatch(r"gh: [^\r\n]*\(HTTP ([45][0-9]{2})\)", last)
        if match:
            metadata["http_status"] = int(match.group(1))
        elif metadata["transport_hint"] is None:
            lowered = tail.lower()
            metadata["transport_hint"] = next(
                (name for name, phrases in TRANSPORT_HINTS.items()
                 if any(phrase in lowered for phrase in phrases)), None)
    error.safe_cli_diagnostic = metadata
    return error


def execution_failure_diagnostic(exc, phase):
    """Return fixed diagnostic fields, never authority to retry registration."""
    args = getattr(exc, "args", ())
    code = args[0] if type(args) is tuple and args else None
    if type(code) is not str or code not in FAILURE_CODES:
        code = "unclassified_failure"
    source = getattr(exc, "safe_cli_diagnostic", {})
    if type(source) is not dict:
        source = {}
    status = source.get("http_status")
    exit_code = source.get("cli_exit_code")
    hint = source.get("transport_hint")
    return {
        "schema": "clawsweeper.execution-failure.v1",
        "phase": phase if type(phase) is str and phase in FAILURE_PHASES else "unclassified",
        "code": code,
        "cli_exit_code": exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None,
        "http_status": status if type(status) is int and 400 <= status <= 599 else None,
        "transport_hint": hint if type(hint) is str and hint in TRANSPORT_HINTS else None,
        "registration_replay_allowed": False,
    }


def run_cli(args, data=None, timeout=25):
    try:
        p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise cli_failure("command_timeout", args) from exc
    if p.returncode:
        raise cli_failure("external_command_refused", args, returncode=p.returncode, stderr=p.stderr)
    return p.stdout


def gh(path, method="GET", body=None):
    args = ["gh", "api", "--method", method, path]
    data = None
    if body is not None:
        args += ["--input", "-"]
        data = json.dumps(body)
    tries = 2 if method == "GET" else 1
    for i in range(tries):
        try:
            payload = run_cli(args, data, timeout=30)
            return json.loads(payload) if payload.strip() else {}
        except ValueError as exc:
            if i + 1 == tries:
                raise cli_failure("github_response_invalid", args) from exc
        except RuntimeError:
            if i + 1 == tries:
                raise
        time.sleep(1)


def discover():
    """Only inspect bounded queued/in-progress run inventory, never arbitrary actions."""
    candidates = []
    workflow_paths = {path for path, _ in WORKFLOWS.values()}
    visited = set()
    # Some queued JIT jobs belong to runs GitHub still reports as pending.
    for status in ("queued", "in_progress", "pending"):
        runs = gh(f"{REPO_SLUG}/actions/runs?status={status}&per_page=100").get("workflow_runs", [])
        for item in runs[:100]:
            if item.get("path") not in workflow_paths or item.get("id") in visited:
                continue
            run_id = item["id"]
            if not isinstance(run_id, int) or run_id <= 0:
                continue
            visited.add(run_id)
            if item.get("status") not in ("queued", "in_progress", "pending"):
                continue
            jobs = gh(f"{REPO_SLUG}/actions/runs/{run_id}/jobs?per_page=100").get("jobs", [])
            for job in jobs[:100]:
                try:
                    candidates.append(classify(item, job))
                except AdmissionHold:
                    continue
    return sorted(candidates, key=lambda c: (c.run_id, c.job_id))


def load_controls():
    if not CONTROLS.exists():
        return {}
    if CONTROLS.is_symlink() or CONTROLS.stat().st_mode & 0o077:
        raise RuntimeError("controls_not_owner_only")
    x = json.loads(CONTROLS.read_text())
    if not isinstance(x, dict):
        raise RuntimeError("invalid_controls")
    return x


def source_authorised(candidate, controls):
    if candidate.role == "isolation":
        # A PR workflow can execute its synthetic merge revision, not only
        # the reported head. Both immutable sources must match reviewed bytes.
        import base64
        if (candidate.event != "pull_request" or type(candidate.pr_number) is not int
                or not SHA.fullmatch(str(candidate.trusted_base_sha or ""))):
            raise AdmissionHold("isolation_pr_merge_unverifiable")
        expected = controls.get("isolation_workflow_sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise AdmissionHold("isolation_workflow_not_pinned")
        harness = controls.get("isolation_harness_sha256")
        if (not isinstance(harness, dict)
                or set(harness) != set(ISOLATION_HARNESS_FILES)
                or any(not isinstance(harness[name], str)
                       or not re.fullmatch(r"[a-f0-9]{64}", harness[name])
                       for name in ISOLATION_HARNESS_FILES)):
            raise AdmissionHold("isolation_harness_not_pinned")
        try:
            pr = gh(f"{REPO_SLUG}/pulls/{candidate.pr_number}")
            if (pr.get("state") != "open"
                    or pr["head"]["sha"] != candidate.sha
                    or pr["head"]["ref"] != candidate.branch
                    or pr["head"]["repo"]["full_name"] != REPOSITORY
                    or pr["base"]["sha"] != candidate.trusted_base_sha
                    or pr["base"]["repo"]["full_name"] != REPOSITORY):
                raise AdmissionHold("isolation_pr_head_or_base_moved")
            base_ref = pr["base"].get("ref")
            if (not isinstance(base_ref, str)
                    or not re.fullmatch(r"[A-Za-z0-9._/-]{1,160}", base_ref)
                    or ".." in base_ref or "//" in base_ref
                    or controls.get("isolation_base_ref") != base_ref):
                raise AdmissionHold("isolation_base_ref_not_pinned")
            # GitHub can retain an older PR/event base SHA while refs/pull/N/merge
            # is regenerated against the *latest* base branch. Do not admit a
            # runner against that ambiguous history. Reconcile source first.
            base_now = gh(f"{REPO_SLUG}/git/ref/heads/{base_ref}")
            if base_now["object"]["sha"] != candidate.trusted_base_sha:
                raise AdmissionHold("isolation_base_branch_drift")
            head_now = gh(f"{REPO_SLUG}/git/ref/heads/{candidate.branch}")
            if head_now["object"]["sha"] != candidate.sha:
                raise AdmissionHold("isolation_head_branch_drift")
            commit = gh(f"{REPO_SLUG}/commits/{candidate.sha}")
            if (commit.get("sha") != candidate.sha
                    or commit["commit"]["verification"]["verified"] is not True):
                raise AdmissionHold("isolation_commit_signature_unverified")
            merge_ref = gh(f"{REPO_SLUG}/git/ref/pull/{candidate.pr_number}/merge")
            merge_sha = merge_ref["object"]["sha"]
            if not SHA.fullmatch(str(merge_sha)):
                raise AdmissionHold("isolation_merge_identity_unverifiable")
            merge = gh(f"{REPO_SLUG}/git/commits/{merge_sha}")
            if [p.get("sha") for p in merge.get("parents", [])] != [
                candidate.trusted_base_sha, candidate.sha
            ]:
                raise AdmissionHold("isolation_merge_parents_changed")
            for ref in (candidate.sha, merge_sha):
                obj = gh(f"{REPO_SLUG}/contents/{candidate.workflow}?ref={ref}")
                if hashlib.sha256(base64.b64decode(obj["content"])).hexdigest() != expected:
                    raise AdmissionHold("isolation_workflow_source_drift")
                # Workflow-only pinning is insufficient: the same PR can leave
                # the YAML unchanged while replacing the test runner or seal
                # implementation with fabricated 28/28 outputs. Pin the actual
                # executed harness at the head AND synthetic merge revision.
                for path in ISOLATION_HARNESS_FILES:
                    file = gh(f"{REPO_SLUG}/contents/{path}?ref={ref}")
                    if (not isinstance(file, dict)
                            or file.get("type") != "file"
                            or file.get("encoding") != "base64"
                            or not isinstance(file.get("content"), str)):
                        raise AdmissionHold("isolation_harness_source_unverifiable")
                    try:
                        # GitHub REST content fields are base64 folded with
                        # LF separators. Accept only that standard folding,
                        # never arbitrary whitespace or invalid encoded bytes.
                        blob = base64.b64decode(
                            file["content"].replace("\n", ""), validate=True)
                    except (ValueError, binascii.Error) as exc:
                        raise AdmissionHold("isolation_harness_source_unverifiable") from exc
                    if hashlib.sha256(blob).hexdigest() != harness[path]:
                        raise AdmissionHold("isolation_harness_source_drift")
        except (AttributeError, KeyError, ValueError, TypeError, RuntimeError) as exc:
            if isinstance(exc, AdmissionHold):
                raise
            raise AdmissionHold("isolation_source_readback_unavailable") from exc
        return True
    if candidate.role == "validation":
        # Execute untrusted PR code ONLY with immutable trusted CI instructions.
        # The workflow source and its approved hash are verified independently.
        import base64
        main = gh(f"{REPO_SLUG}/git/ref/heads/main")["object"]["sha"]
        if main != controls.get("trusted_main_sha"):
            raise AdmissionHold("validation_main_changed")
        baseline = controls.get("trusted_workflow_sha256", {})
        expected = baseline.get(candidate.workflow) if isinstance(baseline, dict) else None
        if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise AdmissionHold("validation_baseline_missing")
        approved = gh(f"{REPO_SLUG}/contents/{candidate.workflow}?ref={main}")
        actual_main = hashlib.sha256(base64.b64decode(approved["content"])).hexdigest()
        if actual_main != expected:
            raise AdmissionHold("validation_baseline_changed")
        if candidate.event == "pull_request":
            # A GitHub workflow run's head_sha is the PR branch, but the
            # actual pull_request execution may use refs/pull/N/merge. Verify
            # the synthetic merge's exact parents before granting a JIT runner.
            if (not isinstance(candidate.pr_number, int)
                    or not SHA.fullmatch(str(candidate.trusted_base_sha or ""))):
                raise AdmissionHold("validation_merge_identity_missing")
            merge_ref = gh(f"{REPO_SLUG}/git/ref/pull/{candidate.pr_number}/merge")
            merge_sha = merge_ref.get("object", {}).get("sha")
            if not isinstance(merge_sha, str) or not re.fullmatch(r"[a-f0-9]{40}", merge_sha):
                raise AdmissionHold("validation_merge_identity_missing")
            merge = gh(f"{REPO_SLUG}/git/commits/{merge_sha}")
            parents = [p.get("sha") for p in merge.get("parents", []) if isinstance(p, dict)]
            if parents != [candidate.trusted_base_sha, candidate.sha]:
                raise AdmissionHold("validation_merge_parents_changed")
            sources = (candidate.sha, merge_sha)
        elif candidate.event == "workflow_dispatch" and candidate.branch == "develop":
            # Verify the signed private develop head and exact workflow bytes.
            # Passing on a different feature branch, stale head, or unsigned
            # commit is never authority to execute on the owner's machine.
            scope = controls.get("validation_private_preview")
            if not isinstance(scope, dict) or scope.get("head_sha") != candidate.sha:
                raise AdmissionHold("validation_private_preview_not_accepted")
            develop = gh(f"{REPO_SLUG}/git/ref/heads/develop")["object"]["sha"]
            if develop != candidate.sha:
                raise AdmissionHold("validation_private_preview_head_drift")
            commit = gh(f"{REPO_SLUG}/commits/{candidate.sha}")
            if (commit.get("sha") != candidate.sha
                    or commit.get("commit", {}).get("verification", {}).get("verified") is not True):
                raise AdmissionHold("validation_private_preview_signature_unverified")
            sources = (candidate.sha,)
        else:
            if candidate.sha != main:
                raise AdmissionHold("validation_default_branch_sha_changed")
            sources = (candidate.sha,)
        preview = controls.get("validation_candidate_sha256")
        approved_hash = preview if preview is not None else expected
        if not isinstance(approved_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", approved_hash):
            raise AdmissionHold("validation_candidate_workflow_drift")
        for ref in sources:
            obj = gh(f"{REPO_SLUG}/contents/{candidate.workflow}?ref={ref}")
            digest = hashlib.sha256(base64.b64decode(obj["content"])).hexdigest()
            if digest != approved_hash:
                raise AdmissionHold("validation_candidate_workflow_drift"
                                    if preview is not None else "validation_workflow_drift")
        return True
    if candidate.role != "ops":
        return True
    # GitHub Actions REST run/check-suite metadata can report a PR head SHA
    # while the executed GITHUB_SHA was a synthetic PR merge revision. A
    # matching current main and PR head workflow is not proof of historical
    # executed merge bytes. Never register a privileged JIT worker on that
    # incomplete provenance: use a verified owner-dispatch/default-branch
    # event or a separately reviewed, run-bound merge attestation instead.
    if candidate.event in ("pull_request", "pull_request_review",
                           "pull_request_review_comment"):
        raise AdmissionHold("executed_pr_merge_workflow_unverifiable")
    main = gh(f"{REPO_SLUG}/git/ref/heads/main")["object"]["sha"]
    if is_release_preview(candidate, controls):
        # Explicitly approved, source-pinned candidate can prove the Cloudflare
        # provision/cleanup chain *before* landing on main. This does not grant
        # authority to dispatch, notify, other runs, or production operations.
        scope = controls["release_preview"]
        if main != controls.get("trusted_main_sha"):
            raise AdmissionHold("release_preview_main_changed")
        try:
            branch = gh(f"{REPO_SLUG}/git/ref/heads/{candidate.branch}")
            if branch["object"]["sha"] != candidate.sha:
                raise AdmissionHold("release_preview_branch_moved")
            commit = gh(f"{REPO_SLUG}/commits/{candidate.sha}")
            if (commit["sha"] != candidate.sha
                    or commit["commit"]["verification"]["verified"] is not True
                    or commit["commit"]["tree"]["sha"] != scope["tree_sha"]):
                raise AdmissionHold("release_preview_commit_unverified")
            file = gh(f"{REPO_SLUG}/contents/{candidate.workflow}?ref={candidate.sha}")
            import base64
            digest = hashlib.sha256(base64.b64decode(file["content"])).hexdigest()
        except (KeyError, ValueError, RuntimeError, TypeError) as exc:
            if isinstance(exc, AdmissionHold):
                raise
            raise AdmissionHold("release_preview_source_unverifiable") from exc
        if digest != scope["workflow_sha256"]:
            raise AdmissionHold("release_preview_workflow_mismatch")
        return True
    review_source = candidate.slot == "notify" and candidate.event in REVIEW_EVENTS
    owner_pr_source = candidate.slot in ("provision", "cleanup") and candidate.event == "pull_request"
    if candidate.event in ("pull_request_target", "pull_request"):
        if candidate.trusted_base_sha != main:
            raise AdmissionHold("target_base_sha_changed")
    elif candidate.event != "pull_request" and not review_source and candidate.sha != main:
        # Non-review callbacks must use pinned main. Review callbacks are
        # allowed only after separate exact workflow-byte equality below.
        raise AdmissionHold("default_branch_source_drift")
    if main != controls.get("trusted_main_sha"):
        raise AdmissionHold("trusted_workflow_head_changed")
    if candidate.slot == "notify":
        # The workflow must check out exactly the owner's independently
        # accepted commit, not the mutable default branch or a PR merge SHA.
        # Missing or unreadable repository variables fail closed.
        try:
            approved = gh(f"{REPO_SLUG}/actions/variables/CLAWSWEEPER_TRUSTED_MAIN_SHA")
            approved_sha = approved.get("value")
        except (RuntimeError, AttributeError, ValueError) as exc:
            raise AdmissionHold("notification_checkout_pin_unverifiable") from exc
        if approved_sha != main:
            raise AdmissionHold("notification_checkout_pin_mismatch")
    # A source hash mismatch is an authority change, not a reason to auto-update
    # the owner's accepted baseline or execute the unreviewed revision.
    manifest = controls.get("trusted_workflow_sha256", {})
    expected = manifest.get(candidate.workflow) if isinstance(manifest, dict) else None
    if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise AdmissionHold("trusted_workflow_not_pinned")
    obj = gh(f"{REPO_SLUG}/contents/{candidate.workflow}?ref={main}")
    import base64
    digest = hashlib.sha256(base64.b64decode(obj["content"])).hexdigest()
    if digest != expected:
        raise AdmissionHold("trusted_workflow_drift")
    if review_source or owner_pr_source:
        # GitHub review callbacks point at PR revisions. Privileged same-repo
        # PRs can edit the workflow BEFORE the checkout step. Both must prove
        # exact reviewed workflow bytes at their reported SHA and pinned main.
        kind = "review" if review_source else "privileged_pr"
        try:
            head_obj = gh(f"{REPO_SLUG}/contents/{candidate.workflow}?ref={candidate.sha}")
            head_digest = hashlib.sha256(base64.b64decode(head_obj["content"])).hexdigest()
        except (RuntimeError, KeyError, ValueError) as exc:
            raise AdmissionHold(kind + "_workflow_source_unverifiable") from exc
        if head_digest != expected:
            raise AdmissionHold(kind + "_workflow_source_drift")
    return True


def approved_job_image(candidate, controls):
    if candidate.role == "isolation":
        pinned = controls.get("isolation_image_sha256")
        if not isinstance(pinned, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", pinned):
            raise AdmissionHold("isolation_image_not_pinned")
        current = run_cli(["docker", "image", "inspect", ISOLATION_IMAGE_NAME,
                           "--format", "{{.Id}}"], timeout=15).strip()
        if current != pinned:
            raise AdmissionHold("isolation_image_drift")
        return pinned
    if candidate.role != "security":
        return IMAGE
    pinned = controls.get("security_image_sha256")
    if not isinstance(pinned, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", pinned):
        raise AdmissionHold("codeql_image_not_pinned")
    current = run_cli(["docker", "image", "inspect", SECURITY_IMAGE_NAME,
                       "--format", "{{.Id}}"], timeout=15).strip()
    if current != pinned:
        raise AdmissionHold("codeql_image_drift")
    return pinned


def detached_fleet_quiescent():
    """Fail closed on independently active local CI work and stale owned containers.

    The parent fleet unit being inactive does NOT prove detached job units
    or isolated CI containers are idle. Never mutate or clean up another
    controller's resources from the admission path.
    """
    try:
        units = run_cli(
            ["systemctl", "--user", "list-units", "--all", "--type=service",
             "--plain", "--no-legend", "local-ci-job-*.service"], timeout=10)
        for row in units.splitlines():
            parts = row.lstrip("● ").split()
            if not parts or not parts[0].startswith("local-ci-job-"):
                continue
            if len(parts) < 3 or not parts[0].endswith(".service"):
                raise AdmissionHold("detached_ci_unit_unverifiable")
            if parts[2] not in ("inactive", "failed"):
                raise AdmissionHold("detached_ci_unit_busy")
        pending = run_cli(
            ["systemctl", "--user", "list-jobs", "--plain", "--no-legend"],
            timeout=10)
        if "local-ci-job-" in pending:
            raise AdmissionHold("detached_ci_unit_transition")
        # The fleet reserves detached capacity in SQLite *before* systemd-run
        # exposes its unit. Unit/container absence alone is not authoritative.
        # Read only, refuse missing/unsafe inventory, never adjust fleet leases.
        if FLEET_DB.is_symlink() or not FLEET_DB.is_file():
            raise AdmissionHold("detached_ci_lease_inventory_unavailable")
        metadata = FLEET_DB.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise AdmissionHold("detached_ci_lease_inventory_unverifiable")
        database = sqlite3.connect(FLEET_DB.as_uri() + "?mode=ro",
                                   timeout=5, uri=True)
        try:
            database.execute("PRAGMA query_only=ON")
            row = database.execute("SELECT COUNT(*) FROM detached_leases").fetchone()
        finally:
            database.close()
        if not row or type(row[0]) is not int:
            raise AdmissionHold("detached_ci_lease_inventory_unverifiable")
        if row[0] > 0:
            raise AdmissionHold("detached_ci_lease_reserved")
        containers = run_cli(
            ["docker", "ps", "--all", "--format", "{{.Names}}|{{.State}}"],
            timeout=15)
        for row in containers.splitlines():
            fields = row.split("|", 1)
            if len(fields) != 2:
                raise AdmissionHold("detached_ci_container_unverifiable")
            name, state = fields
            if name.startswith(("local-ci-job-", "csw-ci-", "local-fleet-", "clawsweeper-ci-")):
                # Even an exited orphan needs ownership-checked reconciliation
                # rather than treating it as evidence of an idle fleet.
                raise AdmissionHold("detached_ci_container_present")
    except AdmissionHold:
        # Distinct policy refusals must retain their actionable reason.
        raise
    except (RuntimeError, subprocess.TimeoutExpired, ValueError,
            sqlite3.Error, OSError) as exc:
        raise AdmissionHold("detached_ci_inventory_unavailable") from exc
    return True


@contextmanager
def shared_fleet_admission_lock():
    """Use the existing, private fleet inode across admission AND execution.

    The shared local fleet owns control.lock and uses its exact inode. The
    canonical owner full-source suite currently holds a separate private lock;
    acquire that existing inode first, then control.lock, and retain BOTH
    through runner cleanup. Neither lock may be created or replaced here.
    """
    parent = FLEET_CONTROL_LOCK.parent
    fd = None
    canonical_fd = None
    try:
        canonical_parent = CANONICAL_TEST_LOCK.parent
        if (canonical_parent.is_symlink() or not canonical_parent.is_dir()
                or canonical_parent.stat().st_uid != os.getuid()
                or canonical_parent.stat().st_mode & 0o077):
            raise AdmissionHold("canonical_test_lock_owner_unverified")
        if CANONICAL_TEST_LOCK.is_symlink() or not CANONICAL_TEST_LOCK.is_file():
            raise AdmissionHold("canonical_test_lock_unavailable")
        canonical_fd = os.open(CANONICAL_TEST_LOCK, os.O_RDWR | os.O_NOFOLLOW |
                               getattr(os, "O_CLOEXEC", 0))
        canonical_meta = os.fstat(canonical_fd)
        canonical_latest = CANONICAL_TEST_LOCK.stat()
        if (canonical_meta.st_dev, canonical_meta.st_ino) != (
                canonical_latest.st_dev, canonical_latest.st_ino):
            raise AdmissionHold("canonical_test_lock_replaced")
        if (not stat.S_ISREG(canonical_meta.st_mode)
                or canonical_meta.st_uid != os.getuid()
                or canonical_meta.st_mode & 0o077
                or canonical_meta.st_nlink != 1):
            raise AdmissionHold("canonical_test_lock_unsafe")
        try:
            fcntl.flock(canonical_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AdmissionHold("canonical_test_lock_busy") from exc
        except OSError as exc:
            raise AdmissionHold("canonical_test_lock_unavailable") from exc
        canonical_after = CANONICAL_TEST_LOCK.stat()
        if (canonical_meta.st_dev, canonical_meta.st_ino) != (
                canonical_after.st_dev, canonical_after.st_ino):
            raise AdmissionHold("canonical_test_lock_replaced")
        if (parent.is_symlink() or not parent.is_dir()
                or parent.stat().st_uid != os.getuid()
                or parent.stat().st_mode & 0o077
                or FLEET_OWNER_MARKER.is_symlink()
                or not FLEET_OWNER_MARKER.is_file()
                or FLEET_OWNER_MARKER.read_bytes() != b"local-ci-v1\n"):
            raise AdmissionHold("shared_fleet_lock_owner_unverified")
        if FLEET_CONTROL_LOCK.is_symlink() or not FLEET_CONTROL_LOCK.is_file():
            raise AdmissionHold("shared_fleet_lock_unavailable")
        fd = os.open(FLEET_CONTROL_LOCK, os.O_RDWR | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0))
        meta = os.fstat(fd)
        # Check the path identity before the hard-link metadata: an inode
        # replaced during open may have nlink=0, and that is source drift.
        latest = FLEET_CONTROL_LOCK.stat()
        if (meta.st_dev, meta.st_ino) != (latest.st_dev, latest.st_ino):
            raise AdmissionHold("shared_fleet_lock_replaced")
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077 or meta.st_nlink != 1):
            raise AdmissionHold("shared_fleet_lock_unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AdmissionHold("shared_fleet_lock_busy") from exc
        except OSError as exc:
            raise AdmissionHold("shared_fleet_lock_unavailable") from exc
        # A trusted same-UID controller might have replaced the path between
        # the first identity check and lock admission; fail closed if so.
        after = FLEET_CONTROL_LOCK.stat()
        if (meta.st_dev, meta.st_ino) != (after.st_dev, after.st_ino):
            raise AdmissionHold("shared_fleet_lock_replaced")
        yield
    except AdmissionHold:
        raise
    except OSError as exc:
        raise AdmissionHold("shared_fleet_lock_unavailable") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if canonical_fd is not None:
            os.close(canonical_fd)


def capacity(candidate, controls):
    # A detached fleet may still hold leases or orphaned containers even when
    # its scheduler reports inactive. Fail closed on a failed/unknown service.
    try:
        fleet = subprocess.run(
            ["systemctl", "--user", "is-active", "local-ci-fleet.service"],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdmissionHold("shared_fleet_inventory_unavailable") from exc
    if fleet.stdout.strip() != "inactive":
        raise AdmissionHold("shared_fleet_busy")
    detached_fleet_quiescent()
    available = next(int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")) // 1024
    required = 5500 if candidate.role in ("security", "isolation") else 3200
    if available < required:
        raise AdmissionHold("memory_reserve")
    if shutil.disk_usage(HOME).free < 20 * 1024**3:
        raise AdmissionHold("physical_disk_reserve")
    if run_cli(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=15).strip() == "":
        raise AdmissionHold("container_engine_unavailable")
    image_id = run_cli(["docker", "image", "inspect", "clawsweeper-selfhost-runner:node24-gh245", "--format", "{{.Id}}"], timeout=15).strip()
    if image_id != IMAGE:
        raise AdmissionHold("runner_image_drift")
    approved_job_image(candidate, controls)
    return True


def inspect_owned(name, owner):
    result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=15)
    if result.returncode:
        if "no such" in result.stderr.lower():
            return None
        raise RuntimeError("container_inspection_unavailable")
    objs = json.loads(result.stdout)
    if len(objs) != 1 or objs[0].get("Config", {}).get("Labels", {}).get(LABEL) != owner:
        raise RuntimeError("container_ownership_mismatch")
    return objs[0]


def stop_owned(name, owner):
    # Docker --rm containers can still be visible to inspect just after their
    # process exits. A transient inspect failure is not a reason to claim
    # cleanup; give it bounded time and demand independently observed absence.
    stop_requested = False
    for attempt in range(5):
        try:
            obj = inspect_owned(name, owner)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            # An ownership mismatch is a security refusal, not transient API
            # unavailability. Never retry it or accidentally stop that name.
            if isinstance(exc, RuntimeError) and str(exc) != "container_inspection_unavailable":
                raise
            if attempt == 4:
                raise RuntimeError("owned_container_identity_unverified") from exc
            time.sleep(2)
            continue
        if obj is None:
            return
        if not stop_requested:
            run_cli(["docker", "stop", "--time", "8", name], timeout=25)
            stop_requested = True
        time.sleep(2)
    if inspect_owned(name, owner) is not None:
        raise RuntimeError("owned_container_cleanup_incomplete")


def runner_absent_verified(runner_id, name):
    # GitHub automatically deregisters ephemeral JIT runners. A DELETE may
    # return not-found *after success*, but the status is only benign if the
    # complete inventory independently proves the exact runner absent.
    result = gh(f"{REPO_SLUG}/actions/runners?per_page=100")
    runners = result.get("runners")
    total = result.get("total_count")
    if not isinstance(runners, list) or not isinstance(total, int) or total != len(runners):
        raise RuntimeError("runner_inventory_unbounded")
    if any(r.get("id") == runner_id or r.get("name") == name for r in runners):
        raise RuntimeError("runner_deregistration_unverified")
    return True


def lookup_owned_runner(name, label, known_id=None, *, allow_busy=False):
    """Exact named runner in COMPLETE GitHub inventory, with immutable label binding.

    A missing registration is safe; an ambiguous/partial inventory is not.
    Never use a name-only match to delete a foreign or replacement runner.
    """
    inventory = gh(f"{REPO_SLUG}/actions/runners?per_page=100")
    runners = inventory.get("runners")
    total = inventory.get("total_count")
    if (not isinstance(runners, list) or not isinstance(total, int)
            or isinstance(total, bool) or total != len(runners)):
        raise RuntimeError("runner_inventory_unbounded")
    matches = [r for r in runners if r.get("name") == name or (
        isinstance(known_id, int) and r.get("id") == known_id)]
    if len(matches) > 1:
        raise RuntimeError("ambiguous_owned_runner_identity")
    if not matches:
        return None
    runner = matches[0]
    if (runner.get("name") != name or not isinstance(runner.get("id"), int)
            or isinstance(runner.get("id"), bool)
            or (known_id is not None and runner["id"] != known_id)):
        raise RuntimeError("runner_identity_mismatch")
    labels = runner.get("labels", [])
    if (not isinstance(labels, list) or not all(isinstance(x, dict) for x in labels)
            or not {"self-hosted", "Linux", "X64", label}.issubset(
                {item.get("name") for item in labels})):
        raise RuntimeError("runner_label_mismatch")
    if runner.get("busy") is not False and not allow_busy:
        raise RuntimeError("runner_still_busy_unverified")
    return runner["id"]


def prepare_network(name, owner):
    image = run_cli(["docker", "image", "inspect", "poststeward-ops-net:1", "--format", "{{.Id}}"], timeout=15).strip()
    if image != NETWORK_IMAGE:
        raise AdmissionHold("network_image_drift")
    firewall = "\n".join((
        "set -eu", "ip6tables -P OUTPUT DROP",
        "for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4; do",
        'iptables -A OUTPUT -d "$cidr" -j REJECT', "done",
        "touch /tmp/network-ready", "sleep 2000",
    ))
    run_cli(["docker", "run", "--rm", "--detach", "--name", name, "--label", LABEL+"="+owner,
             "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges",
             "--pids-limit", "50", "--memory", "96m", "--cpus", "0.25", "--dns", "1.1.1.1",
             image, "sh", "-ec", firewall], timeout=30)
    for _ in range(12):
        result = subprocess.run(["docker", "exec", name, "test", "-f", "/tmp/network-ready"], capture_output=True, timeout=10)
        if result.returncode == 0:
            return image
        time.sleep(1)
    raise RuntimeError("network_firewall_not_ready")


def expected_isolation_checkout(candidate, controls):
    """Resolve an E2E job's checkout from live GitHub, not the runner receipt.

    PRs execute a synthetic merge with exact [base, head] parents. Main push
    and workflow_dispatch events execute the exact owner-pinned default head.
    Unknown events and mutable branch tips never acquire evidence authority.
    """
    if candidate.event == "pull_request":
        if not isinstance(candidate.pr_number, int) or not isinstance(
                candidate.trusted_base_sha, str):
            raise EvidenceHold("e2e_pr_identity_missing")
        merge_ref = gh(f"{REPO_SLUG}/git/ref/pull/{candidate.pr_number}/merge")
        merge_sha = merge_ref["object"]["sha"]
        merge_commit = gh(f"{REPO_SLUG}/git/commits/{merge_sha}")
        parents = [x.get("sha") for x in merge_commit.get("parents", [])]
        if parents != [candidate.trusted_base_sha, candidate.sha]:
            raise EvidenceHold("e2e_merge_ancestry_changed")
        return merge_sha
    if candidate.event not in ("push", "workflow_dispatch") or candidate.branch != "main":
        raise EvidenceHold("e2e_unapproved_event_or_branch")
    main = gh(f"{REPO_SLUG}/git/ref/heads/main")["object"]["sha"]
    if main != candidate.sha or main != controls.get("trusted_main_sha"):
        raise EvidenceHold("e2e_default_head_not_pinned")
    return main


def select_runner_intent(candidate):
    """One distinct CodeQL replacement only after immutable, provider-proven cleanup.

    Old JIT registration is never replayed. This read-only selector runs under
    the executor's exclusive admission lock and fails closed on any mismatch.
    """
    key = f"run-{candidate.run_id}-job-{candidate.job_id}-attempt-{candidate.run_attempt}"
    name = f"csw-ci-{candidate.run_id}-{candidate.job_id}-{candidate.run_attempt}"
    old = RECEIPTS / key
    if old.is_symlink():
        raise AdmissionHold("unsafe_prior_intent")
    if not old.exists():
        return old, name, None
    if candidate.role == "isolation":
        # Selection remains read-only. Recovery has its own exclusive, scoped
        # entrypoint and never grants a new registration for this identity.
        raise AdmissionHold("existing_or_uncertain_isolation_intent")
    if (candidate.role != "security"
            or candidate.workflow != ".github/workflows/codeql.yml"
            or not old.is_dir() or old.stat().st_uid != os.getuid()
            or old.stat().st_mode & 0o077):
        raise AdmissionHold("replacement_role_or_source_not_approved")
    paths = (old / "receipt.json", old / "interrupted-recovery-proof.json",
             old / "interrupted-recovery-intent.json")
    if any(not f.is_file() or f.is_symlink() or f.stat().st_uid != os.getuid()
           or f.stat().st_mode & 0o077 for f in paths):
        raise AdmissionHold("existing_or_uncertain_runner_intent")
    raw, proof_raw, intent_raw = [f.read_bytes() for f in paths]
    prior, proof, intent = (json.loads(raw), json.loads(proof_raw), json.loads(intent_raw))
    digest = hashlib.sha256(raw).hexdigest()
    expected = {"run_id": candidate.run_id, "job_id": candidate.job_id,
                "attempt": candidate.run_attempt}
    source = {"head_sha": candidate.sha, "workflow": candidate.workflow,
              "event": candidate.event, "role": candidate.role,
              "label": candidate.label, "runner_name": name}
    original_id = prior.get("runner_id")
    if (any(prior.get(k) != v for k, v in {**expected, **source}.items())
            or prior.get("schema") != "clawsweeper.selfhosted-jit.v1"
            or prior.get("state") not in ("registered", "runner_started")
            or prior.get("finished_at") is not None
            or not isinstance(original_id, int) or isinstance(original_id, bool)
            or original_id <= 0
            or proof.get("schema") != "clawsweeper.jit-interrupted-recovery.v1"
            or proof.get("decision") != "cleanup_verified_no_replay"
            or any(proof.get(k) != v for k, v in
                   {**expected, "head_sha": candidate.sha, "runner_name": name,
                    "original_receipt_sha256": digest,
                    "original_state": prior["state"],
                    "runner_absent": True, "owned_containers_absent": True,
                    "new_registration_attempted": False,
                    "release_acceptance": False}.items())
            or proof.get("github_job", {}).get("status") != "queued"
            or proof.get("github_job", {}).get("conclusion") is not None
            or intent.get("schema") != "clawsweeper.jit-interrupted-intent.v1"
            or any(intent.get(k) != v for k, v in
                   {**expected, "head_sha": candidate.sha, "runner_name": name,
                    "original_receipt_sha256": digest,
                    "replay_registration": False}.items())):
        raise AdmissionHold("recovered_runner_binding_mismatch")
    for child in (name + "-worker", name + "-net"):
        if inspect_owned(child, name) is not None:
            raise AdmissionHold("recovered_runner_container_present")
    runner_absent_verified(original_id, name)
    run = gh(f"{REPO_SLUG}/actions/runs/{candidate.run_id}")
    job = gh(f"{REPO_SLUG}/actions/jobs/{candidate.job_id}")
    if (any(run.get(k) != v for k, v in
            {"id": candidate.run_id, "run_attempt": candidate.run_attempt,
             "head_sha": candidate.sha, "path": candidate.workflow}.items())
            or run.get("repository", {}).get("full_name") != REPOSITORY
            or job.get("id") != candidate.job_id
            or job.get("run_id") != candidate.run_id
            or job.get("status") != "queued" or job.get("conclusion") is not None
            or job.get("runner_name") not in (None, "")):
        raise AdmissionHold("recovered_github_job_changed")
    replacement = RECEIPTS / (key + "-replacement-1")
    if replacement.exists() or replacement.is_symlink():
        raise AdmissionHold("existing_or_uncertain_replacement_intent")
    return replacement, name + "-replacement-1", {
        "replacement_for": name, "original_receipt_sha256": digest,
        "replacement_proof_sha256": hashlib.sha256(proof_raw).hexdigest(),
        "original_image_sha256": prior.get("image_sha256"),
    }



PRE_JIT_PREPARATION_SCHEMA = "clawsweeper.isolation-pre-jit-preparation.v1"


def isolation_preparation_record(candidate, name, image_id):
    """Durable exact identity BEFORE any Docker volume/holder is allocated."""
    return {
        "schema": PRE_JIT_PREPARATION_SCHEMA, "state": "preparing",
        "run_id": candidate.run_id, "job_id": candidate.job_id,
        "attempt": candidate.run_attempt, "head_sha": candidate.sha,
        "workflow": candidate.workflow, "event": candidate.event,
        "role": "isolation", "label": candidate.label,
        "runner_name": name, "image_sha256": image_id,
        "evidence_volume": volume_name(name),
        "home_volume": isolation_home_volume_name(name),
        "holder": name + "-vault-holder", "seed": name + "-home-seed",
        "jit_post_may_have_started": False, "created_at": now(),
    }


def _private_preparation_file(path):
    if path.is_symlink() or not path.is_file():
        raise AdmissionHold("unsafe_isolation_preparation_intent")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 8192):
        raise AdmissionHold("unsafe_isolation_preparation_intent")
    try:
        record = json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as exc:
        raise AdmissionHold("invalid_isolation_preparation_intent") from exc
    if not isinstance(record, dict):
        raise AdmissionHold("invalid_isolation_preparation_intent")
    return record


def reconcile_isolation_preparation(target, candidate, name):
    """Reclaim ONLY a proven pre-JIT owner resource; never retry registration.

    The fsynced transition to registration_may_have_started precedes POST.
    Earlier states therefore prove NO POST from this executor. A later state
    always holds for separate JIT reconciliation, including after a crash.
    """
    expected_dir = RECEIPTS / (
        f"run-{candidate.run_id}-job-{candidate.job_id}-attempt-{candidate.run_attempt}")
    if (target != expected_dir or target.is_symlink() or not target.is_dir()
            or target.stat().st_uid != os.getuid()
            or stat.S_IMODE(target.stat().st_mode) != 0o700
            or candidate.role != "isolation"):
        raise AdmissionHold("isolation_preparation_owner_or_path_mismatch")
    path = target / "preparation-intent.json"
    record = _private_preparation_file(path)
    expected = isolation_preparation_record(candidate, name, record.get("image_sha256"))
    expected.pop("created_at")
    expected.pop("state")
    expected.pop("jit_post_may_have_started")
    if (not isinstance(record.get("image_sha256"), str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", record["image_sha256"])
            or any(record.get(k) != v for k, v in expected.items())
            or type(record.get("jit_post_may_have_started")) is not bool):
        raise AdmissionHold("isolation_preparation_binding_invalid")
    state = record.get("state")
    post_possible = state in ("registration_may_have_started",
                              "cleanup_verified_terminal")
    if state not in ("preparing", "resources_prepared", "cleanup_verified",
                     "registration_may_have_started", "cleanup_verified_terminal"):
        raise AdmissionHold("isolation_preparation_state_invalid")
    if record["jit_post_may_have_started"] != post_possible:
        raise AdmissionHold("isolation_preparation_phase_mismatch")
    receipt = target / "receipt.json"
    if receipt.exists() or receipt.is_symlink():
        saved = _private_preparation_file(receipt)
        fields = {"schema": "clawsweeper.selfhosted-jit.v1",
                  "run_id": candidate.run_id, "job_id": candidate.job_id,
                  "attempt": candidate.run_attempt, "head_sha": candidate.sha,
                  "workflow": candidate.workflow, "event": candidate.event,
                  "role": "isolation", "label": candidate.label,
                  "runner_name": name, "image_sha256": record["image_sha256"],
                  "state": "registration_uncertain"}
        if any(saved.get(k) != v for k, v in fields.items() if k != "state"):
            raise AdmissionHold("isolation_preparation_receipt_uncertain")
        if saved.get("state") == "registration_uncertain":
            if (state not in ("resources_prepared", "registration_may_have_started",
                              "cleanup_verified_terminal")
                    or "runner_id" in saved):
                raise AdmissionHold("isolation_preparation_receipt_uncertain")
        elif saved.get("state") in ("passed", "held"):
            rid = saved.get("runner_id")
            if (not post_possible or not isinstance(saved.get("finished_at"), str)
                    or not isinstance(saved.get("issues"), list)
                    or (saved["state"] == "passed" and saved["issues"])
                    or (rid is not None and (type(rid) is not int or rid <= 0))):
                raise AdmissionHold("isolation_terminal_receipt_invalid")
        else:
            raise AdmissionHold("isolation_preparation_receipt_uncertain")
    elif post_possible:
        raise AdmissionHold("isolation_post_boundary_receipt_missing")
    if post_possible:
        # A submitted JIT POST may have been lost. Do not clean up a running
        # job, infer non-registration from a missing response, or retry POST.
        try:
            run = gh(f"{REPO_SLUG}/actions/runs/{candidate.run_id}")
            job = gh(f"{REPO_SLUG}/actions/jobs/{candidate.job_id}")
            if (run.get("id") != candidate.run_id
                    or run.get("run_attempt") != candidate.run_attempt
                    or run.get("head_sha") != candidate.sha
                    or run.get("path") != candidate.workflow
                    or job.get("id") != candidate.job_id
                    or job.get("run_id") != candidate.run_id
                    or job.get("status") != "completed"
                    or job.get("conclusion") not in ("success", "failure", "cancelled")
                    or job.get("runner_name") not in (None, "", name)):
                raise AdmissionHold("isolation_post_boundary_job_not_terminal")
            rid = saved.get("runner_id")
            if saved["state"] == "passed":
                if (job.get("conclusion") != "success"
                        or job.get("runner_name") != name
                        or type(rid) is not int or job.get("runner_id") != rid):
                    raise AdmissionHold("isolation_terminal_passed_binding_mismatch")
            if rid is not None and job.get("runner_id") not in (None, 0, rid):
                raise AdmissionHold("isolation_terminal_runner_identity_drift")
            logged = saved.get("github_job")
            if logged is not None:
                if not isinstance(logged, dict) or any(
                        logged.get(k) is not None and logged.get(k) != job.get(k)
                        for k in ("id", "run_id", "status", "conclusion", "runner_name")):
                    raise AdmissionHold("isolation_terminal_receipt_job_drift")
            if lookup_owned_runner(name, candidate.label, rid, allow_busy=True) is not None:
                raise AdmissionHold("isolation_post_boundary_runner_present")
            runner_absent_verified(rid, name)
        except AdmissionHold:
            raise
        except (RuntimeError, KeyError, TypeError, OSError) as exc:
            raise AdmissionHold("isolation_post_boundary_provider_unverified") from exc
        # Cleanup is safe only after an authenticated terminal job and two
        # bounded full-inventory reads. Preserve the durable source phase:
        # post-possible cleanup MUST remain idempotent on later invocation.
    # Before terminal GitHub proof, never stop a potentially running job.
    # Afterwards remove ONLY exact-owned/label-verified worker/net children.
    for child in (name + "-worker", name + "-net"):
        if inspect_owned(child, name) is not None:
            if not post_possible:
                raise AdmissionHold("isolation_pre_jit_worker_unexpected")
            stop_owned(child, name)
            if inspect_owned(child, name) is not None:
                raise AdmissionHold("isolation_terminal_worker_cleanup_unverified")
    if state not in ("cleanup_verified", "cleanup_verified_terminal"):
        try:
            remove_isolation_holder(record["seed"], name)
            cleanup_isolation_volume(record["evidence_volume"],
                                     record["holder"], name)
        except BaseException as exc:
            raise AdmissionHold("isolation_pre_jit_cleanup_unverified") from exc
    if (inspect_owned(record["seed"], name) is not None
            or inspect_owned(record["holder"], name) is not None
            or inspect_isolation_volume(record["evidence_volume"], name) is not None
            or inspect_isolation_volume(record["home_volume"], name,
                                        options=ISOLATION_HOME_OPTIONS) is not None):
        raise AdmissionHold("isolation_pre_jit_cleanup_unverified")
    if state not in ("cleanup_verified", "cleanup_verified_terminal"):
        atomic(path, dict(record,
                          state=("cleanup_verified_terminal" if post_possible
                                 else "cleanup_verified"),
                          jit_post_may_have_started=post_possible,
                          cleanup_verified_at=now(), registration_replayed=False,
                          registration_outcome=("terminal_provider_reconciled" if post_possible
                                                else "no_post_possible")))
    return {"state": "cleanup_verified_no_registration_retry", "run_id": candidate.run_id,
            "job_id": candidate.job_id, "attempt": candidate.run_attempt,
            "runner_name": name, "registration_replayed": False}


def isolation_log_limiter():
    """Require a trusted kernel RLIMIT_FSIZE launcher BEFORE a JIT POST.

    The Docker CLI writes directly into the owner-private runner.log.
    A post-run 128-MiB digest check alone does not bound host disk or memory.
    """
    launcher = Path("/usr/bin/prlimit")
    try:
        meta = launcher.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0
                or meta.st_mode & 0o022 or not os.access(launcher, os.X_OK)):
            raise AdmissionHold("isolation_log_limit_unavailable")
    except OSError as exc:
        raise AdmissionHold("isolation_log_limit_unavailable") from exc
    return str(launcher)


def isolation_bounded_command(cmd, limiter):
    """Cap both the Docker daemon's persisted logs and its attached CLI output.

    The host currently uses the JSON-file logging driver; absent explicit
    rotation it is unlimited even if the foreground Docker CLI has RLIMIT_FSIZE.
    Only isolation receives these flags; the accepted CodeQL command is unchanged.
    """
    if (not isinstance(cmd, list) or cmd[:2] != ["docker", "run"]
            or not isinstance(limiter, str) or limiter != "/usr/bin/prlimit"):
        raise AdmissionHold("isolation_log_command_invalid")
    if ("--read-only" not in cmd or not any(
            isinstance(arg, str) and arg.startswith("type=volume,src=")
            and arg.endswith(",dst=/home/runner") for arg in cmd)):
        raise AdmissionHold("isolation_worker_storage_unbounded")
    return [limiter, f"--fsize={ISOLATION_MAX_LOG_BYTES}", "--",
            "docker", "run", "--log-driver=json-file",
            "--log-opt=max-size=16m", "--log-opt=max-file=2", *cmd[2:]]


def isolation_log_digest(path, *, limit=ISOLATION_MAX_LOG_BYTES):
    """Stream a sealed isolation logfile; never materialise all bytes in RAM."""
    if type(limit) is not int or limit < 1 or limit > ISOLATION_MAX_LOG_BYTES:
        raise AdmissionHold("isolation_log_limit_invalid")
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > limit):
            raise AdmissionHold("isolation_log_unsafe_or_oversized")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                    before.st_dev, before.st_ino, before.st_size):
                raise AdmissionHold("isolation_log_changed")
            digest, n = hashlib.sha256(), 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                n += len(chunk)
                if n > limit:
                    raise AdmissionHold("isolation_log_unsafe_or_oversized")
                digest.update(chunk)
            after = os.fstat(fd)
            if (n != before.st_size
                    or (opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns, opened.st_ctime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)):
                raise AdmissionHold("isolation_log_changed")
        finally:
            os.close(fd)
        return digest.hexdigest(), n
    except OSError as exc:
        raise AdmissionHold("isolation_log_unreadable") from exc



def isolation_home_volume_name(owner):
    """A separate disposable quota home for each exact runner identity."""
    return volume_name(owner) + "-home"


def isolation_worker_storage_args(owner):
    """No writable host-backed overlay or bind inside untrusted E2E workers."""
    home = isolation_home_volume_name(owner)
    flags = ["--read-only"]
    for entry in ISOLATION_WORKER_TMPFS:
        flags.extend(["--tmpfs", entry])
    return [*flags, "--mount", f"type=volume,src={home},dst=/home/runner"]


def inspect_isolation_volume(volume, owner, *, options=VOLUME_OPTIONS):
    """Inspect the exact Docker-local tmpfs identity; never adopt an alien name."""
    try:
        result = subprocess.run(["docker", "volume", "inspect", volume],
                                capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdmissionHold("isolation_volume_inspection_unavailable") from exc
    if result.returncode:
        if "no such volume" in result.stderr.lower():
            return None
        raise AdmissionHold("isolation_volume_inspection_unavailable")
    try:
        payload = json.loads(result.stdout)
        if (len(payload) != 1 or payload[0].get("Name") != volume
                or payload[0].get("Driver") != "local"
                or payload[0].get("Options") != {"type": "tmpfs", "device": "tmpfs",
                                                    "o": options}
                or payload[0].get("Labels", {}).get(LABEL) != owner):
            raise AdmissionHold("isolation_volume_ownership_or_quota_mismatch")
        return payload[0]
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise AdmissionHold("isolation_volume_identity_unverifiable") from exc


def remove_isolation_holder(holder, owner):
    """Remove only a container whose exact private owner label we can prove."""
    if inspect_owned(holder, owner) is not None:
        run_cli(["docker", "rm", "--force", holder], timeout=25)
    if inspect_owned(holder, owner) is not None:
        raise AdmissionHold("isolation_holder_cleanup_unverified")


def cleanup_isolation_volume(volume, holder, owner):
    """Clean both independently quota-bound volumes; prove identities absent."""
    remove_isolation_holder(holder, owner)
    errors = []
    for name, options in (
            (volume, VOLUME_OPTIONS),
            (isolation_home_volume_name(owner), ISOLATION_HOME_OPTIONS)):
        try:
            if inspect_isolation_volume(name, owner, options=options) is not None:
                run_cli(["docker", "volume", "rm", name], timeout=25)
            if inspect_isolation_volume(name, owner, options=options) is not None:
                errors.append("volume_remains")
        except Exception:
            errors.append("volume_cleanup_unverified")
    if errors:
        raise AdmissionHold("isolation_volume_cleanup_unverified")


def prepare_isolation_volume(owner, image_id):
    """Bound bytes AND inodes by a kernel tmpfs quota before any JIT POST.

    An isolated, read-only holder preserves the tmpfs across the runner's exit.
    The worker gets only the volume, never the host's receipt or Docker socket.
    """
    volume = volume_name(owner)
    home = isolation_home_volume_name(owner)
    holder = owner + "-vault-holder"
    seed = owner + "-home-seed"
    if (inspect_isolation_volume(volume, owner) is not None
            or inspect_isolation_volume(home, owner,
                                        options=ISOLATION_HOME_OPTIONS) is not None
            or inspect_owned(holder, owner) is not None
            or inspect_owned(seed, owner) is not None):
        raise AdmissionHold("isolation_volume_identity_already_exists")
    try:
        created = run_cli(["docker", "volume", "create", "--driver", "local",
            "--opt", "type=tmpfs", "--opt", "device=tmpfs",
            "--opt", "o=" + VOLUME_OPTIONS, "--label", LABEL + "=" + owner,
            volume], timeout=25).strip()
        if created != volume or inspect_isolation_volume(volume, owner) is None:
            raise AdmissionHold("isolation_volume_creation_unverified")
        created_home = run_cli(["docker", "volume", "create", "--driver", "local",
            "--opt", "type=tmpfs", "--opt", "device=tmpfs",
            "--opt", "o=" + ISOLATION_HOME_OPTIONS,
            "--label", LABEL + "=" + owner, home], timeout=25).strip()
        if (created_home != home or inspect_isolation_volume(
                home, owner, options=ISOLATION_HOME_OPTIONS) is None):
            raise AdmissionHold("isolation_home_volume_creation_unverified")
        run_cli(["docker", "create", "--name", holder,
            "--label", LABEL + "=" + owner,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "128m",
            "--pids-limit", "24",
            "--mount", f"type=volume,src={home},dst=/bounded-home",
            "--mount", f"type=volume,src={volume},dst=/e2e-evidence,readonly",
            image_id, "bash", "-ec", "sleep 7500"], timeout=25)
        if inspect_owned(holder, owner) is None:
            raise AdmissionHold("isolation_holder_identity_unverified")
        run_cli(["docker", "start", holder], timeout=25)
        live = inspect_owned(holder, owner)
        if live is None or live.get("State", {}).get("Running") is not True:
            raise AdmissionHold("isolation_holder_not_running")
        # Keep BOTH tmpfs volumes mounted through the existing trusted holder.
        # The pinned-image seed copies bootstrap files into its writable quota
        # home, never a host directory. If any phase fails, no JIT POST occurs.
        seed_cmd = [
            "docker", "run", "--rm", "--name", seed,
            "--label", LABEL + "=" + owner, "--network", "none",
            "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--memory", "2g",
            "--pids-limit", "64", "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=32m,nr_inodes=4096,mode=1777",
            "--mount", f"type=volume,src={home},dst=/bounded-home",
            image_id, "bash", "-ec",
            "cp -a --no-preserve=ownership /home/runner/. /bounded-home/; "
            "test -x /bounded-home/run.sh; "
            "test -x /bounded-home/bin/Runner.Listener; "
            "test -w /bounded-home; echo RUNNER_HOME_SEEDED",
        ]
        if run_cli(seed_cmd, timeout=90).strip() != "RUNNER_HOME_SEEDED":
            raise AdmissionHold("isolation_home_pre_jit_seed_unverified")
        if inspect_owned(seed, owner) is not None:
            raise AdmissionHold("isolation_home_seed_cleanup_unverified")
        for params, expected in (
                (["-B1", "/bounded-home"], ISOLATION_HOME_VOLUME_BYTES),
                (["-i", "/bounded-home"], ISOLATION_HOME_VOLUME_INODES)):
            listing = run_cli(["docker", "exec", holder, "df", *params], timeout=25)
            try:
                actual = int(listing.strip().splitlines()[-1].split()[1])
            except (IndexError, ValueError) as exc:
                raise AdmissionHold("isolation_home_kernel_quota_unverified") from exc
            if actual != expected:
                raise AdmissionHold("isolation_home_kernel_quota_unverified")
        run_cli(["docker", "exec", holder, "test", "-x",
                 "/bounded-home/run.sh"], timeout=25)
        # Docker engine, not a post-run Python validator, must enforce this.
        # This probe executes only the trusted pinned image; never PR code.
        checked = run_cli(["docker", "exec", holder, "bash", "-ec",
            'test "$(stat -c %a /e2e-evidence)" = "1777"; '
            "test \"$(df -B1 /e2e-evidence | tail -n 1 | awk '{print $2}')\" "
            f'= "{VOLUME_BYTES}"; '
            "test \"$(df -i /e2e-evidence | tail -n 1 | awk '{print $2}')\" "
            f'= "{VOLUME_INODES}"; '
            'printf "BOUNDED_TMPFS_CONFIRMED\n"'], timeout=25)
        if checked.strip() != "BOUNDED_TMPFS_CONFIRMED":
            raise AdmissionHold("isolation_kernel_quota_unverified")
        return volume, holder
    except BaseException:
        # No JIT POST has happened; never retry a possibly ambiguous create.
        try:
            remove_isolation_holder(seed, owner)
            cleanup_isolation_volume(volume, holder, owner)
        except BaseException as exc:
            raise AdmissionHold("isolation_volume_pre_jit_cleanup_unverified") from exc
        raise


class _BoundedTarInput:
    """Limit transport bytes as well as declared files. Docker cp emits raw tar."""

    def __init__(self, stream):
        self.stream = stream
        # Budget for tar headers, PAX records and directory entries; no
        # unlimited stream even when the archive carries zero file contents.
        self.limit = MAX_TOTAL_BYTES + MAX_FILES * 8192
        self.total = 0

    def read(self, size=-1):
        if size is None or size < 0:
            size = 1024 * 1024
        remaining = self.limit - self.total
        if remaining < 0:
            raise AdmissionHold("isolation_export_stream_oversized")
        # One byte beyond the limit makes the refusal unambiguous.
        data = self.stream.read(min(size, remaining + 1))
        self.total += len(data)
        if self.total > self.limit:
            raise AdmissionHold("isolation_export_stream_oversized")
        return data


def _bounded_tar_evidence_export(stream, vault):
    """Extract only bounded regular bytes from Docker's untrusted tar stream.

    A tmpfs quota limits allocated blocks, NOT sparse file logical length:
    truncate -s 1T uses almost no tmpfs blocks. Never use docker cp directly
    into a host directory before inspecting each declared logical file size.
    This reader rejects oversize tar headers before writing their payload.
    """
    if not vault.is_dir() or vault.is_symlink() or any(vault.iterdir()):
        raise AdmissionHold("isolation_export_destination_unsafe")
    seen = set()
    file_count = directory_count = total_bytes = 0
    try:
        with tarfile.open(fileobj=_BoundedTarInput(stream), mode="r|") as archive:
            for member in archive:
                name = member.name
                if name.startswith("./"):
                    name = name[2:]
                if name.startswith("e2e-evidence/"):
                    name = name[len("e2e-evidence/"):]
                # Docker cp of a directory may include the archive root.
                if name in ("", ".", "e2e-evidence"):
                    if not member.isdir():
                        raise AdmissionHold("isolation_export_unsafe_root")
                    continue
                try:
                    rel = _relative(name)
                except EvidenceHold as exc:
                    raise AdmissionHold("isolation_export_unsafe_path") from exc
                if rel in seen:
                    raise AdmissionHold("isolation_export_duplicate_path")
                seen.add(rel)
                if len(seen) > MAX_FILES * 4:
                    raise AdmissionHold("isolation_export_excessive_entries")
                if (getattr(member, "sparse", None)
                        or any(key.startswith("GNU.sparse")
                               for key in member.pax_headers)):
                    raise AdmissionHold("isolation_export_sparse_entry")
                target = vault.joinpath(*rel.split("/"))
                # The destination has private 0700 ancestors, and only this
                # owner process creates entries. Never honour archive modes.
                if member.isdir():
                    directory_count += 1
                    if directory_count > MAX_FILES * 3:
                        raise AdmissionHold("isolation_export_excessive_directories")
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    meta = target.lstat()
                    if (not stat.S_ISDIR(meta.st_mode)
                            or meta.st_uid != os.getuid() or meta.st_mode & 0o022):
                        raise AdmissionHold("isolation_export_unsafe_directory")
                    continue
                if not member.isfile() or type(member.size) is not int:
                    raise AdmissionHold("isolation_export_special_file_refused")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise AdmissionHold("isolation_export_file_oversized")
                file_count += 1
                total_bytes += member.size
                if file_count > MAX_FILES + 3 or total_bytes > MAX_TOTAL_BYTES:
                    raise AdmissionHold("isolation_export_total_oversized")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                for parent in (target.parent, *list(target.parents)[1:-1]):
                    if parent == vault:
                        break
                    meta = parent.lstat()
                    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid()
                            or meta.st_mode & 0o022):
                        raise AdmissionHold("isolation_export_unsafe_parent")
                body = archive.extractfile(member)
                if body is None:
                    raise AdmissionHold("isolation_export_file_unreadable")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, "wb", closefd=False) as output:
                        remaining = member.size
                        while remaining:
                            chunk = body.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise AdmissionHold("isolation_export_truncated_file")
                            output.write(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    os.close(fd)
    except AdmissionHold:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        raise AdmissionHold("isolation_export_archive_unverifiable") from exc
    if file_count == 0:
        raise AdmissionHold("isolation_export_empty_archive")
    return {"file_count": file_count, "logical_bytes": total_bytes}


def export_isolation_volume(volume, holder, owner, vault):
    """Stream a Docker-local tmpfs through pre-write size and path guards."""
    if (inspect_isolation_volume(volume, owner) is None
            or (live := inspect_owned(holder, owner)) is None
            or live.get("State", {}).get("Running") is not True):
        raise AdmissionHold("isolation_evidence_holder_unverifiable")
    meta = vault.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid()
            or stat.S_IMODE(meta.st_mode) != 0o1777 or any(vault.iterdir())):
        raise AdmissionHold("isolation_evidence_export_destination_unsafe")
    limiter = Path("/usr/bin/timeout")
    info = limiter.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or not os.access(limiter, os.X_OK)):
        raise AdmissionHold("isolation_export_timeout_untrusted")
    try:
        process = subprocess.Popen(
            [str(limiter), "--kill-after=5s", "120s",
             "docker", "cp", holder + ":/e2e-evidence/.", "-"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            evidence = _bounded_tar_evidence_export(process.stdout, vault)
            if process.wait(timeout=8) != 0:
                raise AdmissionHold("isolation_export_copy_failed")
            return evidence
        finally:
            if process.poll() is None:
                # The timeout wrapper may have spawned a Docker CLI child.
                # Kill only this newly-created session, never shared CI jobs.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=8)
            process.stdout.close()
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdmissionHold("isolation_export_process_unverifiable") from exc


def runner_job(candidate, controls):
    private_dir(RECEIPTS)
    target, name, lineage = select_runner_intent(candidate)
    worker = name + "-worker"
    net = name + "-net"
    image_id = approved_job_image(candidate, controls)
    # Refuse isolation *before* an irreversible JIT POST if bounded host log
    # capture cannot be guaranteed. CodeQL/ops command paths are unchanged.
    limiter = isolation_log_limiter() if candidate.role == "isolation" else None
    storage_args = (isolation_worker_storage_args(name)
                    if candidate.role == "isolation" else [])
    if lineage is not None and lineage["original_image_sha256"] != image_id:
        raise AdmissionHold("recovered_runner_image_drift")
    private_dir(target)
    preparation = None
    preparation_path = target / "preparation-intent.json"
    if candidate.role == "isolation":
        # No Docker resource may exist until this exact identity is fsynced.
        preparation = isolation_preparation_record(candidate, name, image_id)
        atomic(preparation_path, preparation)
    volume = holder = vault = None
    try:
        # Only isolation receives a fresh leaf; security never shares a vault.
        vault = create_vault(target) if candidate.role == "isolation" else None
        # Quota volumes and holder are under the same pre-JIT cleanup guard.
        if vault is not None:
            volume, holder = prepare_isolation_volume(name, image_id)
            atomic(preparation_path, dict(preparation, state="resources_prepared"))
        receipt = {
            "schema": "clawsweeper.selfhosted-jit.v1", "run_id": candidate.run_id,
            "job_id": candidate.job_id, "attempt": candidate.run_attempt,
            "head_sha": candidate.sha, "workflow": candidate.workflow, "event": candidate.event,
            "role": candidate.role, "label": candidate.label, "runner_name": name,
            "image_sha256": image_id, "state": "registration_uncertain", "created_at": now(),
        }
        if lineage is not None:
            receipt.update({k: v for k, v in lineage.items() if k != "original_image_sha256"})
        atomic(target / "receipt.json", receipt)
        if preparation is not None:
            # This durable fence MUST precede the first non-idempotent JIT POST.
            # Recovery never assumes registration did not occur beyond it.
            atomic(preparation_path, dict(preparation,
                   state="registration_may_have_started",
                   jit_post_may_have_started=True))
    except BaseException:
        if preparation is not None:
            # Even receipt write/rename and pre-JIT journal failures require
            # independently verified owner-only cleanup, without registration.
            try:
                # We are still synchronously BEFORE the POST, even if the
                # post-possible journal write had reached disk before failing.
                # Clean exact locally named resources without trusting a
                # partial receipt, then durably mark the no-POST resolution.
                remove_isolation_holder(name + "-home-seed", name)
                cleanup_isolation_volume(volume_name(name),
                                         name + "-vault-holder", name)
                saved = _private_preparation_file(preparation_path)
                atomic(preparation_path, dict(saved, state="cleanup_verified",
                       jit_post_may_have_started=False,
                       cleanup_verified_at=now(), registration_replayed=False,
                       registration_outcome="no_post_possible"))
            except BaseException as cleanup_exc:
                raise AdmissionHold("isolation_pre_jit_cleanup_unverified") from cleanup_exc
        raise
    # Registration is non-idempotent. Enter cleanup protection BEFORE the POST.
    # Persist an uncertain intent first; a crash leaves recovery an exact identity
    # to reconcile, but never permission to submit the POST again.
    registered_id = None
    process = None
    issues = []
    job_success_verified = False
    interruption = None
    failure_phase = "registration_request"

    def record_cleanup_error(exc, reason):
        nonlocal interruption
        issues.append(reason)
        if not isinstance(exc, Exception) and interruption is None:
            interruption = exc

    try:
        response = gh(f"{REPO_SLUG}/actions/runners/generate-jitconfig", "POST", {
            "name": name, "runner_group_id": 1,
            "labels": ["self-hosted", "Linux", "X64", candidate.label],
            "work_folder": "_work",
        })
        failure_phase = "registration_response"
        if not isinstance(response, dict):
            raise RuntimeError("jit_registration_response_incomplete")
        encoded = response.pop("encoded_jit_config", None)
        runner = response.get("runner")
        registered_id = runner.get("id") if isinstance(runner, dict) else None
        if isinstance(registered_id, bool) or not isinstance(registered_id, int) or registered_id <= 0:
            registered_id = None
        if registered_id is not None:
            # Persist the identity as soon as it is known, including when
            # GitHub supplied an incomplete config which must never execute.
            receipt.update(state="registered", runner_id=registered_id, registered_at=now())
            atomic(target / "receipt.json", receipt)
        if not isinstance(encoded, str) or not encoded or registered_id is None:
            raise RuntimeError("jit_registration_response_incomplete")
        failure_phase = "network_preparation"
        prepare_network(net, name)
        failure_phase = "runner_execution"
        log_path = target / "runner.log"
        with log_path.open("xb") as logfile:
            os.fchmod(logfile.fileno(), 0o600)
            cmd = ["docker", "run", "--rm", "--interactive", "--init", "--name", worker,
                   "--label", LABEL+"="+name, "--network", "container:"+net,
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "500",
                   "--memory", runner_limits(candidate)[1], "--cpus", "2",
                   *storage_args, *(mount_args(volume) if vault is not None else []), image_id,
                   "bash", "-ec", 'IFS= read -r config; exec ./run.sh --jitconfig "$config"']
            if limiter is not None:
                # prlimit execs Docker with a per-process kernel file-size cap.
                # Excess output terminates the CLI and invokes existing JIT
                # cleanup/fencing; there is no host-socket mount in the runner.
                cmd = isolation_bounded_command(cmd, limiter)
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=logfile, stderr=subprocess.STDOUT, text=True)
            process.stdin.write(encoded + "\n")
            process.stdin.close()
            receipt.update(state="runner_started", runner_started_at=now())
            atomic(target / "receipt.json", receipt)
            try:
                process.wait(timeout=runner_limits(candidate)[0])
            except subprocess.TimeoutExpired:
                issues.append("runner_time_limit")
            receipt["runner_exit"] = process.poll()
        if candidate.role == "isolation":
            receipt["log_sha256"], receipt["log_bytes"] = isolation_log_digest(log_path)
        else:
            # Retain the already-accepted CodeQL/runtime path unchanged.
            receipt["log_sha256"] = hashlib.sha256(log_path.read_bytes()).hexdigest()
            receipt["log_bytes"] = log_path.stat().st_size
        failure_phase = "github_job_readback"
        result = {}
        for _ in range(6):
            result = gh(f"{REPO_SLUG}/actions/jobs/{candidate.job_id}")
            if result.get("status") == "completed":
                break
            time.sleep(5)
        receipt["github_job"] = {k: result.get(k) for k in ("id", "run_id", "status", "conclusion", "runner_name", "started_at", "completed_at")}
        if not (result.get("id") == candidate.job_id and result.get("run_id") == candidate.run_id
                and result.get("runner_name") == name and result.get("status") == "completed"):
            issues.append("job_identity_or_terminal_state_unverified")
        if result.get("conclusion") != "success":
            issues.append("github_job_not_successful")
        if process.poll() != 0:
            issues.append("runner_exit_not_zero")
        if candidate.role == "isolation":
            # A green GitHub job is not proof: validate all 28 sealed scenarios
            # from the owner-private mount AFTER the runner has exited. The
            # synthetic-merge SHA and exact ancestry come from fresh GitHub
            # reads, not from the untrusted runner's receipt or environment.
            try:
                # The volume remains mounted in the trusted read-only holder
                # until the bounded transfer completes after runner exit.
                export_isolation_volume(volume, holder, name, vault)
                checkout = expected_isolation_checkout(candidate, controls)
                receipt["e2e_proof"] = verify_vault(
                    vault, run_id=candidate.run_id, attempt=candidate.run_attempt,
                    source_head=candidate.sha, checkout_sha=checkout)
            except Exception:
                # Never echo attacker-controlled file paths or receipt bytes.
                issues.append("isolation_evidence_not_independently_verified")
        # A successful job still requires subsequent independently verified
        # cleanup; unexpected process interruption is durably held.
        job_success_verified = not issues
    except BaseException as exc:
        receipt["failure_diagnostic"] = execution_failure_diagnostic(exc, failure_phase)
        issues.append(("execution_interrupted_" if not isinstance(exc, Exception)
                       else "execution_error_") + type(exc).__name__)
        if not isinstance(exc, Exception):
            interruption = exc
    finally:
        # A known runner identity is necessary to deregister; only owned Docker
        # labels may be touched. Cleanup errors always prevent a passing receipt.
        for child in (worker, net):
            try:
                stop_owned(child, name)
            except BaseException as exc:
                record_cleanup_error(exc, "owned_cleanup_unverified")
        if volume is not None:
            try:
                cleanup_isolation_volume(volume, holder, name)
            except BaseException as exc:
                record_cleanup_error(exc, "isolation_volume_cleanup_unverified")
        if process is not None:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                issues.append("worker_process_reaping_unverified")
            except BaseException as exc:
                record_cleanup_error(exc, "worker_process_reaping_unverified")
        try:
            # The POST may have succeeded without returning a complete response.
            # Resolve ONLY this exact owned name+labels, then independently prove
            # absence. Cleanup is a hold when identity or inventory is ambiguous.
            current_id = lookup_owned_runner(name, candidate.label, registered_id,
                                             allow_busy=True)
            if registered_id is None:
                # An uncertain POST is never repeated. Retain independently
                # observed identity/absence to support later reconciliation,
                # without treating safe cleanup as job success.
                if current_id is None:
                    receipt["uncertain_registration_absent"] = True
                else:
                    registered_id = current_id
                    receipt["runner_id"] = current_id
                    receipt["uncertain_registration_matched"] = True
            if current_id is not None:
                try:
                    gh(f"{REPO_SLUG}/actions/runners/{current_id}", "DELETE")
                except Exception:
                    pass  # Need independent absence readback, not DELETE success.
            runner_absent_verified(registered_id or current_id, name)
        except BaseException as exc:
            record_cleanup_error(exc, "runner_deregistration_unverified")
        receipt["issues"] = issues
        receipt["state"] = ("passed" if job_success_verified and not issues
                            and interruption is None else "held")
        receipt["finished_at"] = now()
        atomic(target / "receipt.json", receipt)
        if interruption is not None:
            # Preserve the original interruption after its durable held receipt.
            raise interruption
    return {"run_id": candidate.run_id, "job_id": candidate.job_id,
            "state": receipt["state"], "issues": issues, "receipt": str(target / "receipt.json")}


def existing_security_held_receipt(candidate):
    """Fence a terminal security receipt, including a failed replacement.

    This is detection, never replacement registration. A tampered receipt or
    private receipt-root ownership is a hold, not an absence observation.
    """
    if candidate.role != "security":
        return None
    if RECEIPTS.is_symlink():
        raise AdmissionHold("unsafe_prior_receipt_root")
    if RECEIPTS.exists() and (not RECEIPTS.is_dir()
                              or RECEIPTS.stat().st_uid != os.getuid()
                              or stat.S_IMODE(RECEIPTS.stat().st_mode) != 0o700):
        raise AdmissionHold("unsafe_prior_receipt_root")
    base = f"run-{candidate.run_id}-job-{candidate.job_id}-attempt-{candidate.run_attempt}"
    observed = []
    for suffix in ("", "-replacement-1"):
        directory = RECEIPTS / (base + suffix)
        if directory.is_symlink():
            raise AdmissionHold("unsafe_prior_intent")
        if not directory.exists():
            continue
        if (not directory.is_dir() or directory.stat().st_uid != os.getuid()
                or stat.S_IMODE(directory.stat().st_mode) != 0o700):
            raise AdmissionHold("unsafe_prior_receipt_directory")
        receipt = directory / "receipt.json"
        if receipt.is_symlink() or not receipt.is_file():
            raise AdmissionHold("unsafe_prior_receipt")
        info = receipt.stat()
        if (info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise AdmissionHold("unsafe_prior_receipt")
        try:
            original = json.loads(receipt.read_bytes())
        except (ValueError, UnicodeError) as exc:
            raise AdmissionHold("unverifiable_prior_receipt") from exc
        if original.get("state") != "held":
            continue
        binding = {
            "schema": "clawsweeper.selfhosted-jit.v1",
            "run_id": candidate.run_id,
            "job_id": candidate.job_id,
            "attempt": candidate.run_attempt,
            "head_sha": candidate.sha,
            "workflow": candidate.workflow,
            "event": candidate.event,
            "role": candidate.role,
            "label": candidate.label,
            "runner_name": f"csw-ci-{candidate.run_id}-{candidate.job_id}-{candidate.run_attempt}" + suffix,
        }
        if (any(original.get(k) != v for k, v in binding.items())
                or not original.get("finished_at")
                or not isinstance(original.get("issues"), list)
                or not original["issues"]):
            raise AdmissionHold("held_receipt_source_or_terminal_drift")
        observed.append(receipt)
    if len(observed) > 1:
        raise AdmissionHold("multiple_held_security_intents")
    return observed[0] if observed else None


def disarm_security_after_held(candidate, controls, receipt_path):
    """Close ONLY the failed run's owner security scope; never replay a JIT POST.

    Caller already holds the exclusive JIT executor lock. An independent owner
    lock serialises control-file approvals. The original held receipt is never
    overwritten, and an interrupted controls write leaves a durable intent.
    """
    if candidate.role != "security" or not isinstance(controls, dict):
        raise AdmissionHold("held_scope_role_not_supported")
    if (controls.get("enabled") is not True
            or controls.get("enabled_roles") != ["security"]
            or controls.get("allowed_run_ids") != [candidate.run_id]
            or controls.get("allowed_branches") != [candidate.branch]
            or controls.get("operations_accepted") is not False
            or controls.get("max_jobs_per_cycle") != 1):
        raise AdmissionHold("held_scope_not_exclusively_owned")
    directory = Path(receipt_path).parent
    base = f"run-{candidate.run_id}-job-{candidate.job_id}-attempt-{candidate.run_attempt}"
    if (directory not in (RECEIPTS / base, RECEIPTS / (base + "-replacement-1"))
            or directory.is_symlink() or not directory.is_dir()
            or directory.stat().st_uid != os.getuid()
            or stat.S_IMODE(directory.stat().st_mode) != 0o700):
        raise AdmissionHold("held_scope_receipt_directory_invalid")
    receipt_path = directory / "receipt.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise AdmissionHold("held_scope_receipt_invalid")
    info = receipt_path.stat()
    if (info.st_uid != os.getuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise AdmissionHold("held_scope_receipt_invalid")
    original_raw = receipt_path.read_bytes()
    try:
        receipt = json.loads(original_raw)
    except (ValueError, UnicodeError) as exc:
        raise AdmissionHold("held_scope_receipt_invalid") from exc
    expected = {
        "schema": "clawsweeper.selfhosted-jit.v1",
        "run_id": candidate.run_id, "job_id": candidate.job_id,
        "attempt": candidate.run_attempt, "head_sha": candidate.sha,
        "workflow": candidate.workflow, "role": "security",
        "label": candidate.label, "event": candidate.event,
        "runner_name": f"csw-ci-{candidate.run_id}-{candidate.job_id}-{candidate.run_attempt}"
                       + ("-replacement-1" if directory.name.endswith("-replacement-1") else ""),
    }
    if (any(receipt.get(k) != v for k, v in expected.items())
            or receipt.get("state") != "held" or not receipt.get("finished_at")
            or not isinstance(receipt.get("issues"), list) or not receipt["issues"]):
        raise AdmissionHold("held_scope_receipt_binding_invalid")
    intent = directory / "held-scope-disarm-intent.json"
    result_file = directory / "held-scope-disarm-result.json"
    if (intent.exists() or intent.is_symlink()
            or result_file.exists() or result_file.is_symlink()):
        raise AdmissionHold("held_scope_disarm_intent_already_exists")
    if OWNER_CODEQL_LOCK.is_symlink():
        raise AdmissionHold("unsafe_security_owner_lock")
    fd = os.open(OWNER_CODEQL_LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        owner = os.fstat(fd)
        if (not stat.S_ISREG(owner.st_mode) or owner.st_uid != os.getuid()
                or owner.st_nlink != 1 or stat.S_IMODE(owner.st_mode) != 0o600):
            raise AdmissionHold("unsafe_security_owner_lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AdmissionHold("security_owner_controls_busy") from exc
        if (owner.st_dev, owner.st_ino) != (
                OWNER_CODEQL_LOCK.stat().st_dev, OWNER_CODEQL_LOCK.stat().st_ino):
            raise AdmissionHold("security_owner_lock_replaced")
        if CONTROLS.is_symlink() or not CONTROLS.is_file():
            raise AdmissionHold("unsafe_security_controls")
        state = CONTROLS.stat()
        if (state.st_uid != os.getuid() or state.st_nlink != 1
                or stat.S_IMODE(state.st_mode) != 0o600):
            raise AdmissionHold("unsafe_security_controls")
        before = CONTROLS.read_bytes()
        if json.loads(before) != controls:
            raise AdmissionHold("security_controls_changed_since_admission")
        disabled = dict(controls, enabled=False, enabled_roles=[],
                        allowed_run_ids=[], allowed_branches=[])
        after = json.dumps(disabled, sort_keys=True, indent=2).encode() + b"\n"
        record = {
            "schema": "clawsweeper.held-security-scope-disarm.v1",
            "at": now(), "run_id": candidate.run_id, "job_id": candidate.job_id,
            "attempt": candidate.run_attempt, "head_sha": candidate.sha,
            "original_receipt_sha256": hashlib.sha256(original_raw).hexdigest(),
            "before_sha256": hashlib.sha256(before).hexdigest(),
            "after_sha256": hashlib.sha256(after).hexdigest(),
            "registration_replayed": False, "production_accepted": False,
        }
        atomic(intent, record)
        if CONTROLS.read_bytes() != before:
            raise AdmissionHold("security_controls_changed_during_disarm")
        atomic(CONTROLS, disabled)
        if CONTROLS.read_bytes() != after:
            raise AdmissionHold("security_scope_disarm_unverified")
        atomic(result_file, dict(record, state="security_scope_disarmed"))
        return {"state": "security_scope_disarmed", "run_id": candidate.run_id,
                "job_id": candidate.job_id, "registration_replayed": False,
                "controls_sha256": record["after_sha256"]}
    finally:
        os.close(fd)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inspect", "cycle", "reconcile-pre-jit"))
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--job-id", type=int)
    parser.add_argument("--attempt", type=int)
    parser.add_argument("--expected-sha")
    args = parser.parse_args()
    private_dir(ROOT)
    if args.mode == "reconcile-pre-jit":
        # Explicit exact-job resource recovery, even when admission is default
        # denied. It cannot dispatch/register or touch foreign-labelled objects.
        if (not all(type(i) is int and i > 0 for i in (
                args.run_id, args.job_id, args.attempt))
                or not isinstance(args.expected_sha, str)
                or not re.fullmatch(r"[0-9a-f]{40}", args.expected_sha)):
            raise AdmissionHold("pre_jit_recovery_exact_identity_required")
        with LOCK.open("a+") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise AdmissionHold("existing_executor_owns_lock") from exc
            with shared_fleet_admission_lock():
                target = RECEIPTS / (f"run-{args.run_id}-job-{args.job_id}"
                                     f"-attempt-{args.attempt}")
                record = _private_preparation_file(
                    target / "preparation-intent.json")
                if (record.get("run_id") != args.run_id
                        or record.get("job_id") != args.job_id
                        or record.get("attempt") != args.attempt
                        or record.get("head_sha") != args.expected_sha):
                    raise AdmissionHold("pre_jit_recovery_source_identity_mismatch")
                from types import SimpleNamespace
                candidate = SimpleNamespace(
                    run_id=args.run_id, job_id=args.job_id,
                    run_attempt=args.attempt, sha=args.expected_sha,
                    workflow=record.get("workflow"), event=record.get("event"),
                    role=record.get("role"), label=record.get("label"))
                # Derive the owner name from explicit numeric IDs, not from
                # potentially tampered journal content.
                name = f"csw-ci-{args.run_id}-{args.job_id}-{args.attempt}"
                print(json.dumps(reconcile_isolation_preparation(
                    target, candidate, name)))
        return
    if args.mode == "inspect":
        controls = load_controls()
        found = discover()
        output = []
        for c in found:
            try:
                category_enabled(c, controls)
                source_authorised(c, controls)
                decision = "eligible"
            except AdmissionHold as exc:
                decision = str(exc)
            output.append({"run_id": c.run_id, "job_id": c.job_id,
                           "role": c.role, "sha": c.sha, "decision": decision})
        print(json.dumps({"at": now(), "candidates": output[:50]}))
        return
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"held": "existing_executor_owns_lock"}))
            return
        controls = load_controls()
        if controls.get("enabled") is not True:
            print(json.dumps({"held": "controller_disabled"}))
            return
        for c in discover():
            try:
                category_enabled(c, controls)
                source_authorised(c, controls)
                if c.role == "security":
                    # An immutable held receipt is an incident, never a signal
                    # to try the same non-idempotent registration again.
                    try:
                        previous = existing_security_held_receipt(c)
                    except AdmissionHold:
                        print(json.dumps({"run_id": c.run_id, "job_id": c.job_id,
                                          "held": "security_prior_receipt_requires_reconciliation"}))
                        return
                    if previous is not None:
                        try:
                            result = disarm_security_after_held(c, controls, previous)
                        except (AdmissionHold, RuntimeError):
                            print(json.dumps({"run_id": c.run_id, "job_id": c.job_id,
                                              "held": "security_scope_restore_requires_reconciliation"}))
                            return
                        print(json.dumps(result))
                        return
                # The detached fleet uses this same durable host lock to
                # reserve/dispatch work. Hold it through cleanup so neither
                # owner can admit a concurrent external effect.
                with shared_fleet_admission_lock():
                    if c.role == "isolation":
                        key = (f"run-{c.run_id}-job-{c.job_id}"
                               f"-attempt-{c.run_attempt}")
                        prior = RECEIPTS / key
                        if prior.exists() or prior.is_symlink():
                            name = f"csw-ci-{c.run_id}-{c.job_id}-{c.run_attempt}"
                            if ((prior / "preparation-intent.json").exists()
                                    or (prior / "preparation-intent.json").is_symlink()):
                                result = reconcile_isolation_preparation(prior, c, name)
                                print(json.dumps(result))
                                return
                            raise AdmissionHold("existing_or_uncertain_isolation_intent")
                    capacity(c, controls)
                    result = runner_job(c, controls)
                    if c.role == "security" and result.get("state") == "held":
                        try:
                            result["scope_recovery"] = disarm_security_after_held(
                                c, controls, result["receipt"])
                        except (AdmissionHold, RuntimeError):
                            print(json.dumps({"run_id": c.run_id, "job_id": c.job_id,
                                              "held": "security_scope_restore_requires_reconciliation"}))
                            return
                print(json.dumps(result))
                return
            except AdmissionHold as exc:
                print(json.dumps({"run_id": c.run_id, "job_id": c.job_id, "held": str(exc)}))
                continue
        print(json.dumps({"at": now(), "status": "no_admitted_work"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "failure", "reason": type(exc).__name__}), file=sys.stderr)
        sys.exit(1)
