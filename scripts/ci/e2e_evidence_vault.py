"""Independent, fail-closed readback of a run-specific rootless E2E evidence vault.

The untrusted Actions job sees only an empty bind mount, never the host Docker
socket or the controller's private receipt directory. A successful GitHub job
is insufficient: the owner controller checks the complete 28-case evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_FILES = 12_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]{1,512}\Z")


# Pin the actual native scenario/fixture identities; 28 arbitrary records do not pass.
FIXTURES = frozenset(("tiny", "openclaw-shaped"))
SCENARIOS = frozenset((
    "approve-intent-persistence", "completed-verdict-resume",
    "completed-verdict-source-drift", "dependency-setup-mutation",
    "final-review-failed-race", "final-review-malformed-race",
    "github-api-quota-fail-fast", "happy-path", "pending-checks",
    "planning-head-drift", "resume-intent-persistence",
    "workflow-scheduler-convergence", "verdict-head-drift",
    "ci-regression-29623139111",
))


class EvidenceHold(ValueError):
    """A missing, changed or unsafe proof is a release hold, never success."""


def _directory(path):
    try:
        info = path.lstat()
    except OSError as exc:
        raise EvidenceHold("e2e_directory_unverifiable") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise EvidenceHold("e2e_directory_unsafe")
    return info


def create_vault(receipt_dir):
    """Only the leaf is writable by the container UID; all ancestors are 0700."""
    info = _directory(receipt_dir)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise EvidenceHold("e2e_receipt_owner_untrusted")
    vault = receipt_dir / "e2e-evidence"
    try:
        vault.mkdir(mode=0o700)
        # The untrusted container UID may differ from the host owner. A sticky,
        # world-writable LEAF inside a private 0700 ancestor is run-isolated.
        # Never expose the parent or shared CI evidence root to that container.
        vault.chmod(0o1777)
    except OSError as exc:
        raise EvidenceHold("e2e_vault_creation_failed") from exc
    meta = _directory(vault)
    if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o1777:
        raise EvidenceHold("e2e_vault_permissions_unverifiable")
    return vault


def mount_args(vault):
    if _directory(vault).st_uid != os.getuid() or stat.S_IMODE(vault.stat().st_mode) != 0o1777:
        raise EvidenceHold("e2e_mount_untrusted")
    return ["--mount", "type=bind,src=" + str(vault) + ",dst=/e2e-evidence"]


def _regular(path):
    try:
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > MAX_FILE_BYTES:
            raise EvidenceHold("e2e_file_unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            live = os.fstat(fd)
            if ((live.st_dev, live.st_ino, live.st_size) !=
                    (meta.st_dev, meta.st_ino, meta.st_size)
                    or not stat.S_ISREG(live.st_mode) or live.st_nlink != 1):
                raise EvidenceHold("e2e_file_replaced")
            with os.fdopen(fd, "rb", closefd=False) as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
            if len(data) != meta.st_size or len(data) > MAX_FILE_BYTES:
                raise EvidenceHold("e2e_file_changed_or_oversize")
            return data
        finally:
            os.close(fd)
    except EvidenceHold:
        raise
    except OSError as exc:
        raise EvidenceHold("e2e_file_read_unverifiable") from exc


def _json(blob):
    try:
        record = json.loads(blob)
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceHold("e2e_invalid_json") from exc
    if not isinstance(record, dict):
        raise EvidenceHold("e2e_invalid_record")
    return record


def _relative(name):
    if (not isinstance(name, str) or not SAFE_PATH.fullmatch(name)
            or name.startswith("/") or "//" in name
            or any(part in ("", ".", "..") for part in name.split("/"))):
        raise EvidenceHold("e2e_unsafe_relative_path")
    return name


def verify_vault(vault, *, run_id, attempt, source_head, checkout_sha):
    """Verify the exact sealed matrix and every output byte after runner exit.

    checkout_sha must come from a fresh GitHub synthetic-merge ref AND have
    the separately checked [base, head] parents. Never trust a runner variable.
    """
    if (type(run_id) is not int or run_id <= 0 or type(attempt) is not int
            or attempt <= 0 or not isinstance(source_head, str)
            or not SHA40.fullmatch(source_head) or not isinstance(checkout_sha, str)
            or not SHA40.fullmatch(checkout_sha)):
        raise EvidenceHold("e2e_expected_identity_invalid")
    meta = _directory(vault)
    if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o1777:
        raise EvidenceHold("e2e_vault_owner_or_mode_changed")
    name = f"run-{run_id}-attempt-{attempt}"
    try:
        if sorted(p.name for p in vault.iterdir()) != [name]:
            raise EvidenceHold("e2e_unsealed_or_extra_vault_contents")
    except OSError as exc:
        raise EvidenceHold("e2e_vault_listing_unverifiable") from exc
    sealed = vault / name
    _directory(sealed)
    receipt_bytes = _regular(sealed / "receipt.json")
    receipt = _json(receipt_bytes)
    raw_digest = hashlib.sha256(receipt_bytes).hexdigest()
    if _regular(sealed / "receipt.sha256") != f"{raw_digest}  receipt.json\n".encode():
        raise EvidenceHold("e2e_receipt_digest_mismatch")
    required = {
        "schema": "clawsweeper.e2e-local-seal.v1",
        "github_run_id": run_id,
        "github_attempt": attempt,
        "source_head_sha": source_head,
        "checkout_sha": checkout_sha,
        "scenario_count": 28,
        "expected_cases": 28,
        "missing_or_failed": [],
        "verdict": "SEALED_28_CASES",
    }
    if any(type(receipt.get(key)) is not type(value) or receipt.get(key) != value
           for key, value in required.items()):
        raise EvidenceHold("e2e_receipt_identity_or_case_count_mismatch")
    manifest_bytes = _regular(sealed / "manifest.json")
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if receipt.get("manifest_sha256") != manifest_sha:
        raise EvidenceHold("e2e_manifest_digest_mismatch")
    manifest = _json(manifest_bytes)
    entries = manifest.get("files")
    if (manifest.get("schema") != "clawsweeper.e2e-artifact-manifest.v1"
            or manifest.get("source_head") != source_head
            or not isinstance(entries, list) or not entries or len(entries) > MAX_FILES):
        raise EvidenceHold("e2e_manifest_invalid")
    seen = set()
    total = 0
    matrix = set()
    case_files = {}
    fixture_set = set()
    scenario_set = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise EvidenceHold("e2e_manifest_entry_invalid")
        rel = _relative(entry.get("path"))
        size = entry.get("size")
        digest = entry.get("sha256")
        if (rel in seen or type(size) is not int or size < 0 or size > MAX_FILE_BYTES
                or not isinstance(digest, str) or not SHA64.fullmatch(digest)):
            raise EvidenceHold("e2e_manifest_file_identity_invalid")
        seen.add(rel)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise EvidenceHold("e2e_total_bytes_exceeded")
        full = sealed.joinpath(*rel.split("/"))
        parents = full.parents
        for parent in parents:
            if parent == sealed:
                break
            _directory(parent)
        blob = _regular(full)
        if len(blob) != size or hashlib.sha256(blob).hexdigest() != digest:
            raise EvidenceHold("e2e_manifest_file_digest_mismatch")
        parts = rel.split("/")
        if len(parts) >= 3 and parts[0] in FIXTURES and parts[1] in SCENARIOS:
            case_files.setdefault((parts[0], parts[1]), {})[
                "/".join(parts[2:])] = size
        if len(parts) == 3 and parts[2] == "summary.json":
            value = _json(blob)
            fixture, scenario = parts[:2]
            if (value.get("fixture") != fixture or value.get("scenario") != scenario
                    or value.get("status") != "passed"):
                raise EvidenceHold("e2e_case_summary_mismatch")
            matrix.add((fixture, scenario))
            fixture_set.add(fixture)
            scenario_set.add(scenario)
    if (len(matrix) != 28 or fixture_set != FIXTURES or scenario_set != SCENARIOS
            or matrix != {(f, s) for f in FIXTURES for s in SCENARIOS}):
        raise EvidenceHold("e2e_incomplete_28_case_matrix")
    # Fail closed when the job submits 28 self-attested summaries but drops
    # the actual scenario-specific execution traces. This does not by itself
    # certify that a trusted hypervisor ran the tests; GitHub job and source
    # identities are separately verified before runtime acceptance.
    for fixture in FIXTURES:
        for scenario in SCENARIOS:
            files = case_files.get((fixture, scenario), {})
            if scenario == "workflow-scheduler-convergence":
                if (files.get("scheduler-trace.json", 0) <= 0
                        or not any(name.startswith("verdict-") and size > 0
                                   for name, size in files.items())):
                    raise EvidenceHold("e2e_scheduler_execution_trace_missing")
            elif scenario == "github-api-quota-fail-fast":
                if any(files.get(f"github-{code}.{stream}.log", 0) <= 0
                       for code in ("403", "429") for stream in ("stdout", "stderr")):
                    raise EvidenceHold("e2e_quota_execution_trace_missing")
            else:
                streams = [name[:-len(".stdout.log")] for name, size in files.items()
                           if name.endswith(".stdout.log") and size > 0]
                if not any(files.get(stem + ".stderr.log", -1) >= 0
                           for stem in streams):
                    raise EvidenceHold("e2e_case_execution_step_trace_missing")
                if scenario in ("happy-path", "pending-checks") and files.get(
                        "github-state.json", 0) <= 0:
                    raise EvidenceHold("e2e_github_state_trace_missing")
    if (receipt.get("file_count") != len(seen) or type(receipt.get("bytes")) is not int
            or receipt["bytes"] != total):
        raise EvidenceHold("e2e_manifest_count_or_size_mismatch")
    actual = set()
    actual_directories = set()
    def traversal_failed(error):
        raise EvidenceHold("e2e_evidence_traversal_unverifiable") from error
    for folder, directories, files in os.walk(
            sealed, followlinks=False, onerror=traversal_failed):
        # Even empty or nested unreadable directories are unexpected evidence.
        for item in directories:
            full_dir = Path(folder) / item
            _directory(full_dir)
            actual_directories.add(full_dir.relative_to(sealed).as_posix())
            if len(actual_directories) > MAX_FILES * 4:
                raise EvidenceHold("e2e_unbounded_directory_inventory")
        for item in files:
            full = Path(folder) / item
            rel = full.relative_to(sealed).as_posix()
            _relative(rel)
            actual.add(rel)
            if len(actual) > MAX_FILES + 3:
                raise EvidenceHold("e2e_unexpected_evidence")
    if actual != seen | {"manifest.json", "receipt.json", "receipt.sha256"}:
        raise EvidenceHold("e2e_missing_or_extra_evidence")
    expected_directories = set()
    for rel in seen:
        parts = rel.split("/")
        expected_directories.update("/".join(parts[:n]) for n in range(1, len(parts)))
    if actual_directories != expected_directories:
        raise EvidenceHold("e2e_missing_or_extra_directories")
    return {"verdict": "INDEPENDENT_E2E_VAULT_PASS", "cases": 28,
            "file_count": len(seen), "bytes": total,
            "manifest_sha256": manifest_sha, "receipt_sha256": raw_digest}
