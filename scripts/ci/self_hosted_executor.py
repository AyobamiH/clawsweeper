#!/usr/bin/env python3
"""Bounded, exclusive ClawSweeper ephemeral GitHub Actions JIT executor.

One queued job per invocation. Defaults to inspect-only; mutations require an
owner-only 0600 controls file. No GH-hosted runner, personal host mounts, host
Docker socket or model inference is exposed to executable workflow code.
"""
import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time

from self_hosted_policy import AdmissionHold, REPOSITORY, REVIEW_EVENTS, SHA, WORKFLOWS, category_enabled, classify, is_release_preview

HOME = Path.home()
ROOT = HOME / ".local/share/local-ci/clawsweeper-selfhosted"
CONTROLS = ROOT / "controls.json"
LOCK = ROOT / "executor.lock"
FLEET_DB = HOME / ".local/share/local-ci/fleet.sqlite3"
FLEET_CONTROL_LOCK = HOME / ".local/share/local-ci/control.lock"
FLEET_OWNER_MARKER = HOME / ".local/share/local-ci/OWNED_BY_LOCAL_CI"
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


def run_cli(args, data=None, timeout=25):
    try:
        p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("command_timeout") from exc
    if p.returncode:
        raise RuntimeError("external_command_refused")
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
        except (RuntimeError, ValueError):
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

    The shared local fleet owns control.lock and uses its exact inode. Creating
    or accepting a replacement lock, hard link, symlink or public directory
    could leave two concurrent owners thinking they have exclusive admission.
    """
    parent = FLEET_CONTROL_LOCK.parent
    fd = None
    try:
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


def runner_job(candidate, controls):
    key = f"run-{candidate.run_id}-job-{candidate.job_id}-attempt-{candidate.run_attempt}"
    private_dir(RECEIPTS)
    target = RECEIPTS / key
    if target.exists():
        # Once a POST might have succeeded, never blindly repeat it. Operator
        # must reconcile old JIT and GitHub job state before any re-admission.
        raise AdmissionHold("existing_or_uncertain_runner_intent")
    private_dir(target)
    name = f"csw-ci-{candidate.run_id}-{candidate.job_id}-{candidate.run_attempt}"
    worker = name + "-worker"
    net = name + "-net"
    image_id = approved_job_image(candidate, controls)
    receipt = {
        "schema": "clawsweeper.selfhosted-jit.v1", "run_id": candidate.run_id,
        "job_id": candidate.job_id, "attempt": candidate.run_attempt,
        "head_sha": candidate.sha, "workflow": candidate.workflow, "event": candidate.event,
        "role": candidate.role, "label": candidate.label, "runner_name": name,
        "image_sha256": image_id, "state": "registration_uncertain", "created_at": now(),
    }
    atomic(target / "receipt.json", receipt)
    # Registration is non-idempotent. Enter cleanup protection BEFORE the POST.
    # Persist an uncertain intent first; a crash leaves recovery an exact identity
    # to reconcile, but never permission to submit the POST again.
    registered_id = None
    process = None
    issues = []
    job_success_verified = False
    interruption = None

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
        prepare_network(net, name)
        log_path = target / "runner.log"
        with log_path.open("xb") as logfile:
            os.fchmod(logfile.fileno(), 0o600)
            cmd = ["docker", "run", "--rm", "--interactive", "--init", "--name", worker,
                   "--label", LABEL+"="+name, "--network", "container:"+net,
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "500",
                   "--memory", runner_limits(candidate)[1], "--cpus", "2", image_id,
                   "bash", "-ec", 'IFS= read -r config; exec ./run.sh --jitconfig "$config"']
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
        receipt["log_sha256"] = hashlib.sha256(log_path.read_bytes()).hexdigest()
        receipt["log_bytes"] = log_path.stat().st_size
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
        # A successful job still requires subsequent independently verified
        # cleanup; unexpected process interruption is durably held.
        job_success_verified = not issues
    except BaseException as exc:
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


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inspect", "cycle"))
    args = parser.parse_args()
    private_dir(ROOT)
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
                # The detached fleet uses this same durable host lock to
                # reserve/dispatch work. Hold it through cleanup so neither
                # owner can admit a concurrent external effect.
                with shared_fleet_admission_lock():
                    capacity(c, controls)
                    result = runner_job(c, controls)
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
