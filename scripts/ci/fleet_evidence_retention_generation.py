"""Lossless, owner-scoped CI proof lifecycle under the existing fleet control lock.

Only fully completed, GitHub-reported local-fleet job receipts and logs are
archived. Arbitrary project evidence (including ClawSweeper workspaces) is
never moved. Durable plans and verified symlinks permit crash recovery.
This module performs no runner, provider or production operations.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ID = re.compile(r"local-fleet-[0-9a-f]{12}\Z")
UTC = dt.timezone.utc
COLD_DEFAULT = Path.home() / ".local/share/local-ci-proof-archive/fleet-managed-v1"


class RetentionError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def sync_dir(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_once(path: Path, value: dict) -> None:
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    sync_dir(path.parent)


def regular(path: Path) -> bool:
    try:
        s = path.lstat()
        return stat.S_ISREG(s.st_mode) and s.st_nlink == 1
    except FileNotFoundError:
        return False


def _expected_source(root: Path, ident: str, rel: str) -> Path:
    if not ID.fullmatch(ident):
        raise RetentionError("invalid_job_identity")
    allow = {
        "evidence/fleet/" + ident + ".json",
        "logs/fleet/" + ident + ".log",
    }
    if rel not in allow and not re.fullmatch(
        r"evidence/fleet/" + re.escape(ident) + r"\.attempt[0-9]+\.json", rel
    ):
        raise RetentionError("archive_scope_violation")
    result = root / rel
    if result.parent.is_symlink():
        raise RetentionError("unsafe_source_directory")
    return result


def _stored_entry(root: Path, ident: str, source: Path) -> dict:
    rel = str(source.relative_to(root))
    _expected_source(root, ident, rel)
    if not regular(source):
        raise RetentionError("source_not_single_link_regular")
    s = source.stat()
    return {"path": rel, "sha256": sha256(source), "bytes": s.st_size,
            "mode": stat.S_IMODE(s.st_mode)}


def _verify_blob(path: Path, expected: dict) -> None:
    if not regular(path):
        raise RetentionError("archive_blob_not_regular")
    meta = path.stat()
    if (meta.st_size != expected["bytes"]
            or stat.S_IMODE(meta.st_mode) != expected["mode"]
            or sha256(path) != expected["sha256"]):
        raise RetentionError("archive_blob_integrity_failure")


def _repair(root: Path, directory: Path, plan: dict) -> int:
    ident = plan["job"]
    count = 0
    for item in plan["files"]:
        src = _expected_source(root, ident, item["path"])
        dest = directory / Path(item["path"]).name
        if src.is_symlink():
            if src.resolve(strict=False) != dest:
                raise RetentionError("original_path_wrong_archive_target")
            _verify_blob(dest, item)
        elif regular(src):
            _verify_blob(src, item)
            if dest.exists() or dest.is_symlink():
                raise RetentionError("unexpected_archive_destination")
            os.rename(src, dest)  # Same-filesystem, never overwrites a destination.
            sync_dir(src.parent)
            sync_dir(directory)
            os.symlink(str(dest), str(src))
            sync_dir(src.parent)
            _verify_blob(dest, item)
        elif not src.exists() and regular(dest):
            # Recovery after process death between rename and symlink.
            _verify_blob(dest, item)
            os.symlink(str(dest), str(src))
            sync_dir(src.parent)
        else:
            raise RetentionError("missing_or_ambiguous_proof")
        count += 1
    return count


def _eligible(row: dict, now: dt.datetime, min_age_seconds: int) -> bool:
    if row["state"] != "completed" or row["reported"] != 1:
        return False
    try:
        stamp = dt.datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
        return stamp.tzinfo is not None and (now - stamp).total_seconds() >= min_age_seconds
    except (ValueError, TypeError, AttributeError):
        return False


def _archive_one(root: Path, cold: Path, row: dict) -> dict | None:
    ident = row["id"]
    if not ID.fullmatch(ident):
        raise RetentionError("unsafe_job_id")
    folder = cold / ident
    manifest = folder / "plan.json"
    if folder.is_symlink():
        raise RetentionError("archive_directory_symlink")
    if manifest.exists():
        if manifest.is_symlink():
            raise RetentionError("archive_manifest_symlink")
        plan = json.loads(manifest.read_text())
        if plan.get("job") != ident or plan.get("repo") != row["repo"]:
            raise RetentionError("archive_plan_job_mismatch")
    else:
        receipt = root / "evidence/fleet" / (ident + ".json")
        if receipt.is_symlink() or not regular(receipt):
            return None  # Already archived by earlier retention, or untrusted/missing.
        src = [receipt, root / "logs/fleet" / (ident + ".log")]
        src += sorted((root / "evidence/fleet").glob(ident + ".attempt*.json"))
        files = [_stored_entry(root, ident, p) for p in src if p.exists() or p.is_symlink()]
        if not files:
            return None
        if folder.exists():
            raise RetentionError("archive_directory_without_plan")
        folder.mkdir(mode=0o700)
        sync_dir(folder.parent)
        plan = {"version": 1, "job": ident, "repo": row["repo"],
                "sha": row["sha"], "suite": row["suite"],
                "original_state": "completed", "reported": True,
                "files": files}
        write_once(manifest, plan)
    if plan.get("sha") != row["sha"] or plan.get("suite") != row["suite"]:
        raise RetentionError("archive_plan_source_drift")
    receipt = folder / "COMPLETED.json"
    already_completed = receipt.exists()
    moved = _repair(root, folder, plan)
    if not already_completed:
        write_once(receipt, {"version": 1, "job": ident,
                             "manifest_sha256": sha256(manifest),
                             "verified_files": moved,
                             "retained_bytes": sum(x["bytes"] for x in plan["files"]),
                             "original_paths_symlinked": True})
    elif receipt.is_symlink():
        raise RetentionError("completed_marker_symlink")
    else:
        done = json.loads(receipt.read_text())
        if done.get("manifest_sha256") != sha256(manifest) or done.get("verified_files") != moved:
            raise RetentionError("completed_marker_mismatch")
    if already_completed:
        return None
    return {"job": ident, "files": moved,
            "cold_bytes": sum(x["bytes"] for x in plan["files"])}




# SOURCE-ONLY v2 CANDIDATE. The installed v1 retention guard stays immutable.
# A v1 job archive is never rewritten: newer terminal attempts are verified and
# stored in their own immutable generation, with a manifest hash-chain.
def _sealed_plan(root: Path, directory: Path, row: dict, *, version: int) -> dict:
    if directory.is_symlink() or not regular(directory / "plan.json"):
        raise RetentionError("untrusted_generation_plan")
    manifest = directory / "plan.json"
    plan = json.loads(manifest.read_text())
    if (plan.get("version") != version or plan.get("job") != row["id"]
            or plan.get("repo") != row["repo"] or plan.get("sha") != row["sha"]
            or plan.get("suite") != row["suite"]):
        raise RetentionError("generation_plan_source_drift")
    if not isinstance(plan.get("files"), list) or not plan["files"]:
        raise RetentionError("generation_plan_empty")
    seen = set()
    for item in plan["files"]:
        path = item.get("path")
        if not isinstance(path, str):
            raise RetentionError("generation_invalid_path")
        _expected_source(root, row["id"], path)
        name = Path(path).name
        if name in seen:
            raise RetentionError("generation_duplicate_blob")
        seen.add(name)
        _verify_blob(directory / name, item)
    marker = directory / "COMPLETED.json"
    if not regular(marker):
        raise RetentionError("generation_unsealed")
    done = json.loads(marker.read_text())
    if (done.get("manifest_sha256") != sha256(manifest)
            or done.get("verified_files") != len(plan["files"])):
        raise RetentionError("generation_marker_mismatch")
    if version == 2 and (
            done.get("version") != 2
            or done.get("job") != row["id"]
            or done.get("attempt") != plan.get("attempt")
            or done.get("original_paths_symlinked") is not True):
        raise RetentionError("generation_marker_identity_mismatch")
    return plan


def _receipt_generation(root: Path, row: dict, *, after: int) -> tuple[int, list[Path]] | None:
    ident = row["id"]
    receipt = root / "evidence/fleet" / (ident + ".json")
    log = root / "logs/fleet" / (ident + ".log")
    if receipt.is_symlink() and log.is_symlink():
        return None
    if not regular(receipt) or not regular(log):
        raise RetentionError("generation_mixed_or_untrusted_sources")
    record = json.loads(receipt.read_text())
    attempt = record.get("attempt")
    if (type(attempt) is not int or attempt <= after
            or type(row.get("attempt")) is not int
            or attempt != row["attempt"] or attempt < 1):
        raise RetentionError("generation_attempt_invalid")
    for field in ("id", "repo", "sha", "suite"):
        expected = ident if field == "id" else row[field]
        if record.get(field) != expected:
            raise RetentionError("generation_receipt_source_drift")
    if record.get("outcome") != row.get("outcome"):
        raise RetentionError("generation_outcome_drift")
    if (record.get("log_sha256") != sha256(log)
            or record.get("log_bytes") != log.stat().st_size):
        raise RetentionError("generation_log_receipt_mismatch")
    files = [receipt, log]
    for snap in sorted((root / "evidence/fleet").glob(ident + ".attempt*.json")):
        if snap.is_symlink():
            continue  # Prior generation is already immutable and sealed.
        if not regular(snap):
            raise RetentionError("generation_snapshot_not_regular")
        saved = json.loads(snap.read_text())
        prev = saved.get("attempt")
        if (saved.get("id") != ident or saved.get("sha") != row["sha"]
                or type(prev) is not int or prev >= attempt or prev < 1):
            raise RetentionError("generation_snapshot_drift")
        files.append(snap)
    return attempt, files




def _preflight_pending_generation(root: Path, directory: Path, row: dict, plan: dict) -> None:
    for field in ("id", "repo", "sha", "suite"):
        key = "job" if field == "id" else field
        if plan.get(key) != row[field]:
            raise RetentionError("generation_pending_source_drift")
    if not isinstance(plan.get("files"), list) or not plan["files"]:
        raise RetentionError("generation_pending_empty")
    seen = set()
    for item in plan["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise RetentionError("generation_pending_invalid_blob")
        rel = item["path"]
        src = _expected_source(root, row["id"], rel)
        dest = directory / Path(rel).name
        if dest.name in seen:
            raise RetentionError("generation_pending_duplicate_blob")
        seen.add(dest.name)
        if src.is_symlink():
            if src.resolve(strict=False) != dest:
                raise RetentionError("generation_pending_wrong_target")
            _verify_blob(dest, item)
        elif regular(src):
            if dest.exists() or dest.is_symlink():
                raise RetentionError("generation_pending_duplicate_destination")
            _verify_blob(src, item)
        elif not src.exists() and regular(dest):
            _verify_blob(dest, item)
        else:
            raise RetentionError("generation_pending_missing_blob")

def _generation_archive(root: Path, cold: Path, row: dict) -> dict | None:
    ident = row["id"]
    folder = cold / ident
    old_plan = folder / "plan.json"
    if not old_plan.exists():
        # The original v1 code remains the initial-archive implementation.
        return _archive_one(root, cold, row)
    # A pending legacy move is repaired only against its ORIGINAL bytes.
    if not (folder / "COMPLETED.json").exists():
        return _archive_one(root, cold, row)
    old = _sealed_plan(root, folder, row, version=1)
    old_receipt = folder / (ident + ".json")
    if not regular(old_receipt):
        raise RetentionError("legacy_receipt_untrusted")
    archived = json.loads(old_receipt.read_text())
    prior = archived.get("attempt")
    if type(prior) is not int or prior < 1:
        raise RetentionError("legacy_attempt_unbound")
    gens = folder / "generations"
    existing: list[tuple[int, Path]] = []
    previous_hash = sha256(old_plan)
    if gens.exists():
        if gens.is_symlink() or not gens.is_dir():
            raise RetentionError("untrusted_generations_directory")
        for item in gens.iterdir():
            if item.is_symlink() or not item.is_dir() or not re.fullmatch(r"attempt[1-9][0-9]*", item.name):
                raise RetentionError("unexpected_generation_entry")
            existing.append((int(item.name[7:]), item))
        existing.sort()
    empty_orphan = None
    for attempt, directory in existing:
        if attempt <= prior:
            raise RetentionError("generation_nonmonotonic")
        manifest = directory / "plan.json"
        if not regular(manifest):
            # Crash between mkdir and the durable O_EXCL plan: no proof bytes
            # were moved yet. Resume ONLY a completely empty, owner-created,
            # final directory for the exact currently reported attempt.
            meta = directory.stat()
            if (directory != existing[-1][1] or attempt != row["attempt"]
                    or any(directory.iterdir()) or meta.st_uid != os.getuid()
                    or stat.S_IMODE(meta.st_mode) != 0o700):
                raise RetentionError("generation_directory_without_plan")
            empty_orphan = (attempt, directory)
            continue
        plan = json.loads(manifest.read_text())
        if (plan.get("version") != 2 or plan.get("attempt") != attempt
                or plan.get("previous_plan_sha256") != previous_hash):
            raise RetentionError("generation_chain_drift")
        if not (directory / "COMPLETED.json").exists():
            # Preflight EVERY expected object before the first recovery rename.
            # A forged or partly corrupted pending plan must cause zero moves.
            _preflight_pending_generation(root, directory, row, plan)
            _repair(root, directory, plan)
            write_once(directory / "COMPLETED.json", {
                "version": 2, "job": ident, "attempt": attempt,
                "manifest_sha256": sha256(manifest),
                "verified_files": len(plan["files"]),
                "original_paths_symlinked": True,
            })
        _sealed_plan(root, directory, row, version=2)
        prior, previous_hash = attempt, sha256(manifest)
    current = _receipt_generation(root, row, after=prior)
    if current is None:
        if empty_orphan is not None:
            raise RetentionError("generation_orphan_without_current_receipt")
        receipt = root / "evidence/fleet" / (ident + ".json")
        log = root / "logs/fleet" / (ident + ".log")
        latest = existing[-1][1] if existing else folder
        for source in (receipt, log):
            dest = latest / source.name
            if not source.is_symlink() or source.resolve(strict=False) != dest:
                raise RetentionError("generation_current_link_drift")
        return None
    attempt, sources = current
    target = gens / ("attempt" + str(attempt))
    if empty_orphan is not None:
        if empty_orphan != (attempt, target):
            raise RetentionError("generation_orphan_attempt_drift")
    elif target.exists() or target.is_symlink():
        raise RetentionError("generation_duplicate_attempt")
    if not gens.exists():
        gens.mkdir(mode=0o700)
        sync_dir(folder)
    if empty_orphan is None:
        target.mkdir(mode=0o700)
        sync_dir(gens)
    files = [_stored_entry(root, ident, f) for f in sources]
    plan = {"version": 2, "job": ident, "repo": row["repo"],
            "sha": row["sha"], "suite": row["suite"], "attempt": attempt,
            "previous_plan_sha256": previous_hash,
            "original_state": "completed", "reported": True, "files": files}
    manifest = target / "plan.json"
    write_once(manifest, plan)
    moved = _repair(root, target, plan)
    write_once(target / "COMPLETED.json", {
        "version": 2, "job": ident, "attempt": attempt,
        "manifest_sha256": sha256(manifest), "verified_files": moved,
        "original_paths_symlinked": True,
    })
    _sealed_plan(root, target, row, version=2)
    return {"job": ident, "attempt": attempt, "files": moved,
            "cold_bytes": sum(x["bytes"] for x in files)}

def heal(db, *, root: Path, cold: Path = COLD_DEFAULT,
         now: dt.datetime | None = None, min_age_seconds: int = 6 * 3600,
         limit: int = 4) -> dict:
    """Call ONLY while holding fleet's existing exclusive host control.lock.

    Never crosses into work owned by unrelated jobs. Fully completed AND
    GitHub-reported work, absent all worker state/leases, is eligible.
    """
    if root.is_symlink() or cold.is_symlink() or not (root / "OWNED_BY_LOCAL_CI").is_file():
        raise RetentionError("untrusted_archive_root")
    if (root / "OWNED_BY_LOCAL_CI").read_text() != "local-ci-v1\n":
        raise RetentionError("wrong_fleet_ownership_marker")
    if cold.exists() and cold.is_symlink():
        raise RetentionError("archive_root_symlink")
    cold.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.stat().st_dev != cold.stat().st_dev:
        raise RetentionError("archive_must_share_filesystem")
    if limit < 0 or limit > 16:
        raise RetentionError("unsafe_archive_batch")
    now = now or dt.datetime.now(UTC)
    rows = db.execute(
        "SELECT id,repo,sha,suite,state,reported,updated_at,attempt,outcome FROM jobs "
        "WHERE state='completed' AND reported=1 ORDER BY updated_at,id"
    ).fetchall()
    count = 0
    bytes_archived = 0
    for raw in rows:
        row = dict(raw)
        if count >= limit:
            break
        if not _eligible(row, now, min_age_seconds):
            continue
        if (root / "state/fleet" / (row["id"] + ".json")).exists():
            continue
        if db.execute("SELECT count(*) FROM detached_leases WHERE job_id=?", (row["id"],)).fetchone()[0]:
            continue
        result = _generation_archive(root, cold, row)
        if result:
            count += 1
            bytes_archived += result["cold_bytes"]
    return {"archived_jobs": count, "cold_bytes_verified": bytes_archived,
            "archive_version": 2, "no_foreign_evidence_moved": True}
