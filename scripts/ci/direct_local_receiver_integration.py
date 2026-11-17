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
# Source identity is verified BEFORE importing any checked-out modules.
# Never execute an inherited PATH shim or a checkout-defined fsmonitor.
TRUSTED_GIT = "/usr/bin/git"


def trusted_git_env() -> dict:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }


def trusted_git_source() -> str:
    binary = Path(TRUSTED_GIT)
    if (binary.is_symlink() or not binary.is_file()
            or binary.stat().st_uid != 0
            or binary.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("untrusted_absolute_git_binary")
    return str(binary)



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
        git_binary, process_env = trusted_git_source(), trusted_git_env()
        head = subprocess.run(
            [git_binary, "-c", "core.fsmonitor=false", "-C", str(root),
             "rev-parse", "HEAD"],
            env=process_env, capture_output=True, check=True, timeout=5, text=True)
        changed = subprocess.run(
            [git_binary, "-c", "core.fsmonitor=false", "-C", str(root),
             "status", "--porcelain", "--untracked-files=normal"],
            env=process_env, capture_output=True, check=True, timeout=5, text=True)
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


# A separate, non-retroactive release identity is mandatory for TWO genuine
# ordinary workflow definitions. The original v1 aggregate release remains
# usable only by the aggregate adapter and cannot attest this extra module.
DISTINCT_SCHEMA = "clawsweeper.direct-local-owner-release.v2-distinct"
DISTINCT_SOURCE_FILES = SOURCE_FILES | frozenset({
    "scripts/ci/direct_local_distinct_admission.py",
})


def read_distinct_release(file: Path) -> dict:
    """Reject an old aggregate manifest or an unpinned split module."""
    try:
        doc = json.loads(_owned_file(Path(file)), object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise RuntimeError("malformed_distinct_direct_local_release") from exc
    if (not isinstance(doc, dict)
            or set(doc) != {"schema", "repo", "checkout", "commit",
                            "fleet_root", "sha256"}
            or doc["schema"] != DISTINCT_SCHEMA
            or doc["repo"] != "AyobamiH/clawsweeper"
            or not isinstance(doc["commit"], str)
            or not SHA40.fullmatch(doc["commit"])
            or not isinstance(doc["sha256"], dict)
            or set(doc["sha256"]) != DISTINCT_SOURCE_FILES
            or any(not isinstance(h, str) or not SHA256.fullmatch(h)
                   for h in doc["sha256"].values())):
        raise RuntimeError("unapproved_distinct_direct_local_release_identity")
    for key in ("checkout", "fleet_root"):
        value = doc[key]
        if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
            raise RuntimeError("unsafe_distinct_direct_local_release_path")
        location = Path(value)
        if (location.is_symlink() or not location.is_dir()
                or location.stat().st_uid != os.getuid()):
            raise RuntimeError("unsafe_distinct_direct_local_release_directory")
        doc[key] = str(location)
    return doc


def verify_distinct_release(doc: dict) -> None:
    """Reuse all v1 checks then verify the extra split-source exact digest."""
    if (not isinstance(doc, dict)
            or doc.get("schema") != DISTINCT_SCHEMA
            or not isinstance(doc.get("sha256"), dict)
            or set(doc["sha256"]) != DISTINCT_SOURCE_FILES):
        raise RuntimeError("invalid_distinct_direct_local_release")
    base = dict(doc)
    base["schema"] = SCHEMA
    base["sha256"] = {k: doc["sha256"][k] for k in SOURCE_FILES}
    verify_release(base)  # all original modules and exact clean Git HEAD
    extra = Path(doc["checkout"]) / "scripts/ci/direct_local_distinct_admission.py"
    if (extra.is_symlink() or not extra.is_file()
            or extra.stat().st_uid != os.getuid()
            or extra.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or hashlib.sha256(extra.read_bytes()).hexdigest() !=
               doc["sha256"]["scripts/ci/direct_local_distinct_admission.py"]):
        raise RuntimeError("unverified_distinct_admission_source")


def load_released_distinct_claim(file: Path, *, adapter=None):
    """Never permit a v1 aggregate owner release to authorize split claims."""
    doc = read_distinct_release(file)
    verify_distinct_release(doc)
    if adapter is None:
        module_dir = str(Path(doc["checkout"]) / "scripts/ci")
        names = ("direct_local_provider_ref", "direct_local_distinct_admission",
                 "direct_local_fleet_claim", "direct_local_event_admission",
                 "direct_local_workflow", "estate_policy")
        if any(name in sys.modules for name in names):
            raise RuntimeError("cached_unverified_distinct_local_module")
        old_flag = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.path.insert(0, module_dir)
        try:
            provider = importlib.import_module("direct_local_provider_ref")
            # Provider adapter's split import is lazy; import and bind that
            # exact verified module WHILE the pinned path is still active.
            # Otherwise the later owner-cycle claim may fail to import it
            # after sys.path has been restored, or resolve an alien module.
            importlib.import_module("direct_local_distinct_admission")
            adapter = provider.claim_distinct_with_fresh_provider_readback
        finally:
            sys.path.remove(module_dir)
            sys.dont_write_bytecode = old_flag

    def claim(*, body: bytes, event_name: str, signature: str,
              delivery_id: str, secret: bytes) -> dict:
        if read_distinct_release(file) != doc:
            raise RuntimeError("distinct_direct_local_release_revoked_or_changed")
        verify_distinct_release(doc)
        return adapter(
            checkout=Path(doc["checkout"]), fleet_root=Path(doc["fleet_root"]),
            body=body, event_name=event_name, signature=signature,
            delivery_id=delivery_id, secret=secret,
        )
    return claim


# The frozen implementation and the independently enrolled CI target are
# different source identities before the implementation lands on develop.
# The v2 schema conflates them and therefore cannot authorise that rollout.
SPLIT_SOURCE_SCHEMA = "clawsweeper.direct-local-owner-release.v3-split"
SPLIT_SOURCE_FIELDS = frozenset({
    "schema", "repo", "implementation_checkout", "implementation_commit",
    "execution_checkout", "execution_commit", "execution_ref", "fleet_root",
    "sha256",
})


def _canonical_owner_directory(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise RuntimeError("unsafe_split_source_path")
    location = Path(value)
    if (str(location) != value or location.is_symlink()
            or not location.is_dir() or location.stat().st_uid != os.getuid()
            or location.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or any(parent.is_symlink() for parent in location.parents)):
        raise RuntimeError("unsafe_split_source_directory")
    return value


def read_split_source_release(file: Path) -> dict:
    """Read a private, explicit TWO-source release; never upgrade a v1/v2 file."""
    try:
        doc = json.loads(_owned_file(Path(file)), object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError, TypeError) as exc:
        raise RuntimeError("malformed_split_source_release") from exc
    if (not isinstance(doc, dict) or set(doc) != SPLIT_SOURCE_FIELDS
            or doc["schema"] != SPLIT_SOURCE_SCHEMA
            or doc["repo"] != "AyobamiH/clawsweeper"
            or doc["execution_ref"] != "develop"
            or any(not isinstance(doc[k], str) or not SHA40.fullmatch(doc[k])
                   for k in ("implementation_commit", "execution_commit"))
            or not isinstance(doc["sha256"], dict)
            or set(doc["sha256"]) != DISTINCT_SOURCE_FILES
            or any(not isinstance(v, str) or not SHA256.fullmatch(v)
                   for v in doc["sha256"].values())):
        raise RuntimeError("unapproved_split_source_release_identity")
    for field in ("implementation_checkout", "execution_checkout", "fleet_root"):
        doc[field] = _canonical_owner_directory(doc[field])
    return doc


def _trusted_exact_clean_head(directory: Path, expected_sha: str) -> None:
    """Verify a frozen commit without invoking repository hooks or ambient git."""
    try:
        git, env = trusted_git_source(), trusted_git_env()
        head = subprocess.run(
            [git, "-c", "core.fsmonitor=false", "-C", str(directory),
             "rev-parse", "--verify", "HEAD^{commit}"],
            env=env, capture_output=True, timeout=6, check=True, text=True)
        status = subprocess.run(
            [git, "-c", "core.fsmonitor=false", "-C", str(directory),
             "status", "--porcelain", "--untracked-files=normal"],
            env=env, capture_output=True, timeout=6, check=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("split_execution_source_unavailable") from exc
    if head.stdout.strip() != expected_sha or status.stdout.strip():
        raise RuntimeError("split_execution_source_not_exact_clean_head")


def verify_split_source_release(doc: dict, *, enrolled_sha: str) -> None:
    """Bind signed implementation and isolated CI checkout to ONE enrolled SHA.

    This read-only gate cannot install a release or admit a job. The caller
    must independently establish installed policy and source authority.
    """
    if (not isinstance(doc, dict) or set(doc) != SPLIT_SOURCE_FIELDS
            or doc.get("schema") != SPLIT_SOURCE_SCHEMA
            or not isinstance(enrolled_sha, str)
            or not SHA40.fullmatch(enrolled_sha)
            or doc.get("execution_commit") != enrolled_sha):
        raise RuntimeError("split_execution_not_enrolled_in_existing_fleet")
    implementation = {
        "schema": DISTINCT_SCHEMA,
        "repo": doc["repo"],
        "checkout": doc["implementation_checkout"],
        "commit": doc["implementation_commit"],
        "fleet_root": doc["fleet_root"],
        "sha256": doc["sha256"],
    }
    verify_distinct_release(implementation)
    _trusted_exact_clean_head(
        Path(doc["execution_checkout"]), doc["execution_commit"])
    # The caller's enrolled_sha is not authority on its own. Bind the
    # execution commit to the ACTUAL existing fleet's owner-only policy.
    policy_path = Path(doc["fleet_root"]) / "fleet-policy.json"
    if policy_path.is_symlink() or not policy_path.is_file():
        raise RuntimeError("missing_split_source_fleet_policy")
    try:
        fd = os.open(policy_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (info.st_uid != os.getuid()
                    or not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= 262144):
                raise RuntimeError("untrusted_split_source_fleet_policy")
            policy_bytes = os.read(fd, info.st_size + 1)
            if len(policy_bytes) != info.st_size:
                raise RuntimeError("changed_split_source_fleet_policy")
        finally:
            os.close(fd)
    except OSError as exc:
        raise RuntimeError("unavailable_split_source_fleet_policy") from exc
    try:
        policy = json.loads(policy_bytes, object_pairs_hook=unique_keys)
        if (policy["repositories"]["AyobamiH/clawsweeper"]["enrolled_head"]
                != enrolled_sha or
                policy["execution_hosts"]["AyobamiH/clawsweeper"]
                != os.uname().nodename):
            raise RuntimeError("split_source_not_enrolled_in_live_policy")
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise RuntimeError("unreadable_split_source_fleet_policy") from exc


def load_split_source_claim(file: Path, *, enrolled_sha: str):
    """Production entry point: no injected queue adapter or trust bypass."""
    return _load_split_source_claim(file, enrolled_sha=enrolled_sha)


def _load_split_source_claim(file: Path, *, enrolled_sha: str, adapter=None):
    """Bind a verified claim to the EXECUTION tree; injections are test-only."""
    doc = read_split_source_release(file)
    verify_split_source_release(doc, enrolled_sha=enrolled_sha)
    if adapter is None:
        names = ("direct_local_provider_ref", "direct_local_distinct_admission",
                 "direct_local_fleet_claim", "direct_local_event_admission",
                 "direct_local_workflow", "estate_policy")
        if any(name in sys.modules for name in names):
            raise RuntimeError("cached_unverified_split_source_module")
        module_dir = str(Path(doc["implementation_checkout"]) / "scripts" / "ci")
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.path.insert(0, module_dir)
        try:
            provider = importlib.import_module("direct_local_provider_ref")
            importlib.import_module("direct_local_distinct_admission")
            adapter = provider.claim_distinct_with_fresh_provider_readback
        finally:
            sys.path.remove(module_dir)
            sys.dont_write_bytecode = previous

    def claim(*, body: bytes, event_name: str, signature: str,
              delivery_id: str, secret: bytes) -> dict:
        if read_split_source_release(file) != doc:
            raise RuntimeError("split_source_release_revoked_or_changed")
        verify_split_source_release(doc, enrolled_sha=enrolled_sha)
        return adapter(
            checkout=Path(doc["execution_checkout"]),
            fleet_root=Path(doc["fleet_root"]),
            body=body, event_name=event_name, signature=signature,
            delivery_id=delivery_id, secret=secret)
    return claim
