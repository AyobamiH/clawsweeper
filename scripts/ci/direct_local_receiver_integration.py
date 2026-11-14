#!/usr/bin/env python3
"""Fail-closed, opt-in bridge for the EXISTING owner's webhook receiver.

A released owner-only config pins the exact source checkout, HEAD and module
digests. Without that config, the receiver retains its historic wake-only path.
This module never creates a queue, runner, receiver, timer or GitHub Actions run.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SOURCE_FILES = frozenset({
    "scripts/ci/direct_local_provider_ref.py",
    "scripts/ci/direct_local_fleet_claim.py",
    "scripts/ci/direct_local_event_admission.py",
    "scripts/ci/direct_local_workflow.py",
    "scripts/ci/estate_policy.py",
})
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
SCHEMA = "clawsweeper.direct-local-owner-release.v1"


def unique_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise RuntimeError("duplicate_direct_local_release_key")
        obj[key] = value
    return obj


def _owned_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("missing_or_symlinked_direct_local_release_file")
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError("unsafe_direct_local_release_permissions")
    if info.st_size > 8192:
        raise RuntimeError("oversized_direct_local_release")
    return path.read_bytes()


def read_release(file: Path) -> dict:
    try:
        doc = json.loads(_owned_file(Path(file)), object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise RuntimeError("malformed_direct_local_release") from exc
    if (not isinstance(doc, dict) or set(doc) !=
            {"schema", "repo", "checkout", "commit", "fleet_root", "sha256"}
            or doc["schema"] != SCHEMA or doc["repo"] != "AyobamiH/clawsweeper"
            or not isinstance(doc["commit"], str)
            or not SHA40.fullmatch(doc["commit"])
            or not isinstance(doc["sha256"], dict)
            or set(doc["sha256"]) != SOURCE_FILES
            or any(not isinstance(d, str) or not SHA256.fullmatch(d)
                   for d in doc["sha256"].values())):
        raise RuntimeError("unapproved_direct_local_release_identity")
    for key in ("checkout", "fleet_root"):
        value = doc[key]
        if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
            raise RuntimeError("unsafe_direct_local_release_path")
        path = Path(value)
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.getuid():
            raise RuntimeError("unsafe_direct_local_release_directory")
        doc[key] = str(path)
    return doc


def verify_release(doc: dict) -> None:
    root = Path(doc["checkout"])
    module_dir = root / "scripts" / "ci"
    if (module_dir.is_symlink() or not module_dir.is_dir()
            or module_dir.stat().st_uid != os.getuid()):
        raise RuntimeError("unsafe_direct_local_module_directory")
    for name, expected in doc["sha256"].items():
        path = root / name
        if (path.is_symlink() or not path.is_file()
                or path.stat().st_uid != os.getuid()
                or path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise RuntimeError("unsafe_direct_local_source_module")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError("direct_local_source_module_drift")
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, check=True, timeout=5, text=True)
        changed = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
            capture_output=True, check=True, timeout=5, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("unavailable_direct_local_git_identity") from exc
    if head.stdout.strip() != doc["commit"] or changed.stdout.strip():
        raise RuntimeError("direct_local_source_not_exact_clean_head")


def load_released_claim(file: Path, *, adapter=None):
    """Load ONLY owner-pinned code. Recheck exact source on every admission."""
    doc = read_release(file)
    verify_release(doc)
    if adapter is None:
        # No uncontrolled runtime source import: every imported local module is
        # owner-hashed above and the release is explicitly installed.
        module_dir = str(Path(doc["checkout"]) / "scripts" / "ci")
        for name in ("direct_local_provider_ref", "direct_local_fleet_claim",
                     "direct_local_event_admission", "direct_local_workflow",
                     "estate_policy"):
            if name in sys.modules:
                raise RuntimeError("cached_unverified_direct_local_module")
        prior = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.path.insert(0, module_dir)
        try:
            adapter = importlib.import_module(
                "direct_local_provider_ref").claim_with_fresh_provider_readback
        finally:
            sys.path.remove(module_dir)
            sys.dont_write_bytecode = prior

    def claim(*, body: bytes, event_name: str, signature: str,
              delivery_id: str, secret: bytes) -> dict:
        # Revocation or replacement of the owner release file takes effect
        # without a receiver restart. Do not rely on a stale startup snapshot.
        if read_release(file) != doc:
            raise RuntimeError("direct_local_release_revoked_or_changed")
        verify_release(doc)
        return adapter(
            checkout=Path(doc["checkout"]), fleet_root=Path(doc["fleet_root"]),
            body=body, event_name=event_name, signature=signature,
            delivery_id=delivery_id, secret=secret,
        )
    return claim


def load_released_ingress(file: Path):
    """Verify the exact owner release without opening or writing the fleet.

    The network receiver stores only a bounded HMAC-authenticated envelope in
    its existing ledger. The separately released fleet cycle owns GitHub GET,
    canonical lock, SQLite admission and eventual event consumption.
    """
    doc = read_release(file)
    verify_release(doc)

    def verify() -> bool:
        if read_release(file) != doc:
            raise RuntimeError('direct_local_release_revoked_or_changed')
        verify_release(doc)
        return True

    return verify
