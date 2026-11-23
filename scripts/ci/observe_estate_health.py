#!/usr/bin/env python3
"""Bounded, read-only Github CI observer. Does not admit, run, or replay jobs.

A successful snapshot means metadata was fetched from the exact accepted
development source. It is NEVER proof that a job actually executed.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

REPOSITORY = "AyobamiH/clawsweeper"
SOURCE_BRANCH = "develop"
DEFAULT_STATE = Path.home() / ".local/share/local-ci/clawsweeper-estate-observer"
SHA = re.compile(r"^[0-9a-f]{40}$")
STATUSES = ("queued", "in_progress", "pending")
# Hard bounds apply to every source file the independent inventory may read.
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_WORKFLOW_BYTES = 16 * 1024 * 1024


class Hold(RuntimeError):
    """Observed failure is not evidence of a healthy CI environment."""


class GithubReadFailure(Hold):
    """Allowlisted GET failure metadata only, never provider stderr/credentials."""

    def __init__(self, failure_class, attempts):
        super().__init__("github_read_unavailable")
        self.failure_class = failure_class
        self.attempts = attempts


def digest(data):
    return hashlib.sha256(data).hexdigest()



def _bounded_stdout(argv, *, max_bytes, timeout_seconds, cwd=None):
    """Bound bytes before allocation; terminate owned children on uncertainty.

    Do not buffer untrusted GitHub output or Git source status into an
    unrestricted subprocess PIPE. A child can inherit stdout after its parent
    exits: kill the entire process group on timeout, not only the leader.
    """
    if not isinstance(argv, (list, tuple)) or not argv or max_bytes <= 0 or timeout_seconds <= 0:
        raise Hold("invalid_bounded_process")
    process = None
    selector = None
    complete = False
    try:
        process = subprocess.Popen(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, start_new_session=True, cwd=cwd)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        deadline = time.monotonic() + timeout_seconds
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise Hold("bounded_process_timeout")
            if not selector.select(min(remain, 1.0)):
                continue
            chunk = os.read(process.stdout.fileno(), min(65536, max_bytes - len(output) + 1))
            if not chunk:
                break
            if len(output) + len(chunk) > max_bytes:
                raise Hold("bounded_process_oversize")
            output.extend(chunk)
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise Hold("bounded_process_failed")
        complete = True
        return bytes(output)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Hold("bounded_process_unavailable") from exc
    finally:
        if process is not None:
            if not complete or process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            if process.stdout is not None:
                process.stdout.close()
        if selector is not None:
            selector.close()


def github_get(path):
    """Allowlisted GET only; retry one transient CLI read within fixed budgets.

    No POST, raw stderr, credentials or attacker-provided path can enter this
    observer. Oversized/invalid responses fail closed without retrying.
    """
    allowed = {
        f"repos/{REPOSITORY}/git/ref/heads/main",
        f"repos/{REPOSITORY}/git/ref/heads/{SOURCE_BRANCH}",
        f"repos/{REPOSITORY}/actions/runners?per_page=30",
        *(f"repos/{REPOSITORY}/actions/runs?status={s}&per_page=30" for s in STATUSES),
    }
    if path not in allowed:
        raise Hold("unapproved_github_endpoint")
    argv = ["gh", "api", "--method", "GET", path]
    categories = {
        "bounded_process_failed": "cli_nonzero_unclassified",
        "bounded_process_timeout": "cli_timeout",
        "bounded_process_unavailable": "cli_spawn_or_io_unavailable",
        "bounded_process_oversize": "response_oversize",
    }
    retryable = frozenset(("bounded_process_failed", "bounded_process_timeout",
                           "bounded_process_unavailable"))
    for attempt, timeout in ((1, 18), (2, 8)):
        try:
            output = _bounded_stdout(
                argv, max_bytes=4 * 1024 * 1024,
                timeout_seconds=timeout)
        except Hold as exc:
            code = str(exc)
            if attempt == 1 and code in retryable:
                # An idempotent GET can be retried; never infer that a prior
                # request did not execute, and never retry any provider POST.
                time.sleep(0.2)
                continue
            raise GithubReadFailure(
                categories.get(code, "bounded_read_refused"), attempt) from exc
        try:
            value = json.loads(output)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise GithubReadFailure("invalid_json", attempt) from exc
        if not isinstance(value, dict):
            raise GithubReadFailure("invalid_response_shape", attempt)
        return value
    raise GithubReadFailure("bounded_read_refused", 2)


def _safe_source_bytes(path):
    """Read a single regular source inode with a hard byte bound.

    A pathname can become a FIFO or oversized file after an earlier stat.
    O_NONBLOCK and descriptor-level validation prevent both hangs and an
    unbounded read; the same descriptor is checked after the bounded read.
    """
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or info.st_size <= 0 or info.st_size > MAX_SOURCE_BYTES):
            raise Hold("consumed_source_oversized_or_nonregular")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != info.st_size or after.st_size != info.st_size
                or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns):
            raise Hold("consumed_source_changed_during_read")
        return raw
    except OSError as exc:
        raise Hold("consumed_source_unverifiable") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _committed_consumed_sources(checkout, head_sha):
    """Reconcile actual consumed bytes against HEAD, not index stat flags.

    Git's assume-unchanged and skip-worktree flags can hide dirty source from
    both status and diff. Each YAML file (including untracked files) is bounded
    before the Node enumerator reads it, then the complete enumerated set is
    checked against HEAD blobs. A hidden or untracked source is a HOLD.
    """
    workflow_dir = checkout / ".github/workflows"
    if workflow_dir.is_symlink() or not workflow_dir.is_dir():
        raise Hold("workflow_directory_untrusted")
    files = sorted(
        entry for entry in workflow_dir.iterdir()
        if entry.suffix in (".yml", ".yaml")
    )
    if not 0 < len(files) <= 100:
        raise Hold("workflow_count_untrusted")
    files += [checkout / "scripts/ci/workflow-estate.mjs",
              checkout / "config/ci-workflow-estate.json"]
    total = 0
    # Immutable verified bytes, never a second pathname read by Node.
    verified = {}
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise Hold("consumed_source_untrusted")
        info = path.stat()
        if info.st_size <= 0 or info.st_size > MAX_SOURCE_BYTES:
            raise Hold("consumed_source_oversized")
        total += info.st_size
        if total > MAX_WORKFLOW_BYTES:
            raise Hold("consumed_source_aggregate_oversized")
        relative = path.relative_to(checkout).as_posix()
        current = _safe_source_bytes(path)
        if len(current) != info.st_size:
            raise Hold("consumed_source_changed")
        try:
            committed = _bounded_stdout(
                ["git", "--no-replace-objects", "-C", str(checkout),
                 "show", head_sha + ":" + relative],
                max_bytes=MAX_SOURCE_BYTES, timeout_seconds=10)
        except Hold as exc:
            raise Hold("consumed_source_unverifiable") from exc
        if current != committed:
            raise Hold("consumed_source_bytes_drift")
        verified[relative] = current
    return verified


def _complete_inventory(checkout, head_sha):
    """Reparse bounded, committed YAML from the actual signed source.

    The manifest cannot self-approve missing jobs. The Node process is kept in
    its own group with bounded output, heap and time; even an untrusted extra
    YAML file is sized before Node opens it.
    """
    verified = _committed_consumed_sources(checkout, head_sha)
    # Node MUST parse only bytes previously compared with immutable Git blobs.
    # Original checkout pathnames may be swapped immediately after validation.
    runtime = Path(f"/run/user/{os.getuid()}")
    try:
        info = runtime.stat()
    except OSError as exc:
        raise Hold("private_inventory_runtime_unavailable") from exc
    if (runtime.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise Hold("private_inventory_runtime_untrusted")
    try:
        with tempfile.TemporaryDirectory(prefix="clawsweeper-estate-source-", dir=runtime) as folder:
            snapshot = Path(folder)
            for relative, raw in verified.items():
                name = Path(relative)
                if (name.is_absolute() or ".." in name.parts
                        or not (relative.startswith(".github/workflows/")
                                or relative in ("scripts/ci/workflow-estate.mjs",
                                                "config/ci-workflow-estate.json"))):
                    raise Hold("inventory_snapshot_source_invalid")
                destination = snapshot / name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                if _safe_source_bytes(destination) != raw:
                    raise Hold("inventory_snapshot_bytes_changed")
            # Installed dependencies remain owner-managed and pinned by the
            # source project's lockfile; only executable/YAML/manifest inputs
            # are copied from the verified commit.
            dependency_root = checkout / "node_modules"
            if not dependency_root.is_dir():
                raise Hold("inventory_dependencies_missing")
            (snapshot / "node_modules").symlink_to(
                dependency_root.resolve(strict=True), target_is_directory=True)
            _bounded_stdout(
                ["node", "--max-old-space-size=128", "scripts/ci/workflow-estate.mjs", "--check"],
                max_bytes=65536, timeout_seconds=45, cwd=snapshot)
        # Reject an untracked YAML addition or persistent original-source
        # replacement introduced while the isolated Node check ran.
        if _committed_consumed_sources(checkout, head_sha) != verified:
            raise Hold("inventory_original_source_changed_during_execution")
    except Hold as exc:
        if str(exc) == "bounded_process_failed":
            raise Hold("independent_workflow_inventory_mismatch") from exc
        raise
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise Hold("independent_workflow_inventory_unavailable") from exc


def current_source(checkout):
    if not checkout.is_dir() or checkout.is_symlink():
        raise Hold("source_checkout_missing_or_unsafe")
    try:
        def git(*args):
            try:
                return _bounded_stdout(
                    ["git", "--no-replace-objects", "-C", str(checkout), *args],
                    max_bytes=1024 * 1024, timeout_seconds=10,
                ).decode("utf-8").strip()
            except Hold as exc:
                raise Hold("source_manifest_unverifiable") from exc
        head = git("rev-parse", "HEAD")
        if not SHA.fullmatch(head):
            raise Hold("source_sha_invalid")
        if git("diff", "--name-only") or git("diff", "--cached", "--name-only"):
            raise Hold("source_tracked_changes_present")
        manifest_file = checkout / "config/ci-workflow-estate.json"
        if manifest_file.is_symlink() or not manifest_file.is_file():
            raise Hold("manifest_missing_or_symlinked")
        if manifest_file.stat().st_size > MAX_SOURCE_BYTES:
            raise Hold("manifest_oversized")
        raw = _safe_source_bytes(manifest_file)
        manifest = json.loads(raw)
        sources, jobs = manifest.get("sources"), manifest.get("jobs")
        if (manifest.get("schema") != "clawsweeper.workflow-estate.v2"
                or not isinstance(sources, list) or not isinstance(jobs, list)
                or not isinstance(manifest.get("summary"), dict)
                or len(sources) != manifest["summary"].get("workflows")
                or len(jobs) != manifest["summary"].get("jobs")):
            raise Hold("manifest_incomplete")
        # A stale or modified manifest cannot falsely certify a source tree.
        paths = set()
        for item in sources:
            name = item.get("path")
            if (not isinstance(name, str) or not name.startswith(".github/workflows/")
                    or ".." in Path(name).parts or name in paths):
                raise Hold("untrusted_manifest_source_path")
            paths.add(name)
            path = checkout / name
            if (path.is_symlink() or not path.is_file()
                    or path.stat().st_size > MAX_SOURCE_BYTES
                    or digest(_safe_source_bytes(path)) != item.get("sha256")):
                raise Hold("workflow_source_digest_mismatch")
        for job in jobs:
            if job.get("workflow") not in paths:
                raise Hold("job_without_workflow_source")
        if manifest["summary"].get("github_hosted") != 0 or manifest["summary"].get("dynamic_hosted_fallback") != 0:
            raise Hold("hosted_fallback_present")
        _complete_inventory(checkout, head)
        # No moving HEAD or new tracked changes may be accepted between the
        # first SHA capture and the final inventory evaluation.
        if git("rev-parse", "HEAD") != head or git("diff", "--name-only") or git("diff", "--cached", "--name-only"):
            raise Hold("source_revision_changed_during_validation")
        return {"sha": head, "manifest_sha256": digest(raw),
                "workflows": len(sources), "jobs": len(jobs)}
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError) as exc:
        if isinstance(exc, Hold):
            raise
        raise Hold("source_manifest_unverifiable") from exc


def _validated_runs(response, status):
    rows = response.get("workflow_runs")
    total = response.get("total_count")
    if (not isinstance(rows, list) or len(rows) > 30 or type(total) is not int
            or total < len(rows)):
        raise Hold("incomplete_run_readback")
    selected = []
    for row in rows:
        if (type(row.get("id")) is not int or row["id"] <= 0
                or not isinstance(row.get("head_sha"), str)
                or not SHA.fullmatch(row["head_sha"])
                or row.get("status") not in ("queued", "in_progress", "pending")
                or row["status"] != status
                or not isinstance(row.get("path"), str)):
            raise Hold("malformed_github_run")
        selected.append({"id": row["id"], "head_sha": row["head_sha"],
                         "path": row["path"], "status": row["status"],
                         "event": row.get("event")})
    if len({x["id"] for x in selected}) != len(selected):
        raise Hold("duplicate_github_run_identity")
    return {"returned": len(selected), "github_total": total,
            "coverage": "latest_30_only" if total > len(selected) else "complete_returned_page",
            "runs": selected}


def snapshot(checkout, reader=github_get):
    """All reads happen before any healthy receipt can be written."""
    source = current_source(checkout)
    main = reader(f"repos/{REPOSITORY}/git/ref/heads/main")
    develop = reader(f"repos/{REPOSITORY}/git/ref/heads/{SOURCE_BRANCH}")
    m_sha = main.get("object", {}).get("sha")
    d_sha = develop.get("object", {}).get("sha")
    if not SHA.fullmatch(str(m_sha)) or not SHA.fullmatch(str(d_sha)):
        raise Hold("unverified_github_refs")
    if d_sha != source["sha"]:
        raise Hold("develop_head_changed_or_checkout_stale")
    runs = {status: _validated_runs(reader(
        f"repos/{REPOSITORY}/actions/runs?status={status}&per_page=30"), status)
        for status in STATUSES}
    registry = reader(f"repos/{REPOSITORY}/actions/runners?per_page=30")
    n = registry.get("total_count")
    rows = registry.get("runners")
    if type(n) is not int or n < 0 or not isinstance(rows, list) or len(rows) > 30 or len(rows) > n:
        raise Hold("invalid_runner_registry")
    # Closing the source-ref window prevents reporting a current-head proof
    # from a checkout superseded while the bounded GitHub reads were running.
    final_main = reader(f"repos/{REPOSITORY}/git/ref/heads/main")
    final_develop = reader(f"repos/{REPOSITORY}/git/ref/heads/{SOURCE_BRANCH}")
    if (final_main.get("object", {}).get("sha") != m_sha
            or final_develop.get("object", {}).get("sha") != d_sha):
        raise Hold("github_ref_changed_during_observation")
    # GitHub refs alone are not enough: the locally verified checkout can
    # change during network reads even when the remote branch does not.
    try:
        final_source = current_source(checkout)
    except Hold as exc:
        raise Hold("checkout_changed_during_observation") from exc
    if final_source != source:
        raise Hold("checkout_changed_during_observation")
    # Runner information is metadata only, never permission for registration.
    return {"schema": "clawsweeper.readonly-estate-observation.v1",
            "repo": REPOSITORY, "develop": source, "main_sha": m_sha,
            "runner_count": n, "run_samples": runs,
            "complete_runner_registry": n == len(rows),
            "workflow_admitted": False, "effect_count": 0,
            "operational_acceptance_claimed": False, "mode": "read_only"}


def _atomic(path, value):
    content = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    temporary = path.with_name("." + path.name + "." + str(os.getpid()) + ".new")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()




def _safe_receipt_bytes(path):
    """Read one owner-private regular inode with bounded, single-descriptor IO."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 4 * 1024 * 1024):
            raise Hold("unsafe_existing_receipt")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(info.st_size + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != info.st_size or after.st_size != info.st_size
                or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns
                or after.st_nlink != 1):
            raise Hold("receipt_modified_during_read")
        return raw
    except OSError as exc:
        raise Hold("unsafe_existing_receipt") from exc
    finally:
        if fd is not None:
            os.close(fd)


def observe(checkout, state=DEFAULT_STATE, reader=github_get, now=None):
    if state.is_symlink():
        raise Hold("unsafe_state_directory")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.stat().st_uid != os.getuid() or stat.S_IMODE(state.stat().st_mode) != 0o700:
        raise Hold("unsafe_state_permissions")
    fd = os.open(state / "owner.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        s = os.fstat(fd)
        if s.st_uid != os.getuid() or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != 0o600:
            raise Hold("unsafe_lock_permissions")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"state": "held_other_observer", "effect_count": 0}
        timestamp = dt.datetime.now(dt.timezone.utc) if now is None else now
        if timestamp.tzinfo is None:
            raise Hold("time_must_be_timezone_aware")
        # Invalidate the previous green view before any network/source reads.
        # Write latest FIRST: a crash between the two invalidations still
        # prevents consumers from treating previous success as current health.
        intent = {"state": "unverified", "at": timestamp.isoformat(),
                  "reason": "observation_in_progress", "effect_count": 0}
        _atomic(state / "latest.json", intent)
        _atomic(state / "last-attempt.json", intent)
        try:
            data = snapshot(checkout, reader)
            slot = int(timestamp.timestamp() // 900)
            core = {"slot": slot, "source": data}
            identity = digest(json.dumps(core, sort_keys=True).encode())
            receipt_dir = state / "receipts"
            receipt_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            if receipt_dir.is_symlink() or stat.S_IMODE(receipt_dir.stat().st_mode) != 0o700:
                raise Hold("unsafe_receipt_directory")
            receipt_path = receipt_dir / (identity + ".json")
            if os.path.lexists(receipt_path):
                existing = json.loads(_safe_receipt_bytes(receipt_path))
                if existing.get("identity") != identity or existing.get("core") != core:
                    raise Hold("receipt_identity_conflict")
                status = "already_observed"
            else:
                receipt = {"identity": identity, "core": core,
                           "observed_at": timestamp.isoformat()}
                file = receipt_path.with_name("." + receipt_path.name + "." + str(os.getpid()) + ".new")
                raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
                handle = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(handle, "wb") as writer:
                        writer.write(raw)
                        writer.flush()
                        os.fsync(writer.fileno())
                    os.link(file, receipt_path)  # create-only; never overwrite a receipt
                finally:
                    file.unlink(missing_ok=True)
                directory = os.open(receipt_dir, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                status = "observed"
            receipt_hash = digest(_safe_receipt_bytes(receipt_path))
            latest = {"state": "observed", "at": timestamp.isoformat(),
                      "identity": identity, "receipt_sha256": receipt_hash,
                      "source_sha": data["develop"]["sha"], "effect_count": 0}
            _atomic(state / "latest.json", latest)
            _atomic(state / "last-attempt.json", latest)
            return {**latest, "state": status, "receipt": str(receipt_path)}
        except Exception as exc:
            # Unverifiable GitHub data, malformed source or corrupted receipts
            # must invalidate previous green metadata. Preserve old receipts
            # but explicitly mark both most-recent views as unverified.
            code = str(exc) if isinstance(exc, Hold) else "observation_failed_" + type(exc).__name__
            outcome = {"state": "unverified", "at": timestamp.isoformat(),
                       "reason": code, "effect_count": 0}
            if isinstance(exc, GithubReadFailure):
                # Fixed enum and integer only; no URL, stderr or token leakage.
                outcome["github_failure_class"] = exc.failure_class
                outcome["github_get_attempts"] = exc.attempts
            _atomic(state / "last-attempt.json", outcome)
            _atomic(state / "latest.json", outcome)
            return outcome
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    args = parser.parse_args()
    try:
        outcome = observe(args.checkout, args.state)
    except (OSError, Hold, json.JSONDecodeError, ValueError) as exc:
        outcome = {"state": "unverified", "reason": type(exc).__name__ + ":" + str(exc)[:90],
                   "effect_count": 0}
    print(json.dumps(outcome, sort_keys=True))
    if outcome.get("state") not in ("observed", "already_observed"):
        raise SystemExit(75)


if __name__ == "__main__":
    main()
