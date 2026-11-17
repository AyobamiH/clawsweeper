#!/usr/bin/env python3
"""Read-only, owner-signed exact v3 local-fleet install/rollback preflight.

A pass proves bytes and identity only. It never installs, dispatches or edits the
shared fleet, and it never claims that either ordinary CI job has executed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import socket
import stat
import subprocess
import sys
import types

SCHEMA = "clawsweeper.v3-split-manual-install-integrity.v1"
RELEASE = "2026.11.17-v3-clawsweeper-split-manual"
SIGNER = "heryourbarme@live.com"
SIGN_NAMESPACE = "clawsweeper-local-fleet-release"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
EXPECTED_NAMES = frozenset({
    "fleet_ci.py", "fleet-policy.json",
    "secrets/clawsweeper-direct-local-release.json",
})
REPO = "AyobamiH/clawsweeper"


def unique_pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate_manifest_key")
        result[k] = v
    return result


def safe_dir(path: Path) -> Path:
    if (path.is_symlink() or not path.is_dir()
            or path.stat().st_uid != os.getuid()
            or path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise ValueError("untrusted_directory:" + path.name)
    return path


def safe_file(path: Path, *, bound=524288) -> bytes:
    if path.is_symlink():
        raise ValueError("symlinked_file:" + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 0 < before.st_size <= bound):
            raise ValueError("untrusted_file:" + path.name)
        data = os.read(fd, bound + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("changed_during_read:" + path.name)
        return data
    finally:
        os.close(fd)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verified_file(path: Path, value: str, *, bound=524288) -> bytes:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError("invalid_digest")
    data = safe_file(path, bound=bound)
    if digest(data) != value:
        raise ValueError("digest_mismatch:" + path.name)
    return data


def strict_relative(value: str) -> Path:
    if (not isinstance(value, str) or not value or "\\" in value
            or PurePosixPath(value).is_absolute()
            or any(p in ("", ".", "..") for p in value.split("/"))):
        raise ValueError("unsafe_relative_name")
    return Path(value)


def verify_signature(path: Path, signers: Path, *, bound=655360) -> bytes:
    data = safe_file(path, bound=bound)
    sig = Path(str(path) + ".sig")
    safe_file(sig, bound=4096)
    safe_file(signers, bound=8192)
    verifier = Path("/usr/bin/ssh-keygen")
    if (verifier.is_symlink() or not verifier.is_file()
            or verifier.stat().st_uid != 0
            or verifier.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise ValueError("untrusted_signature_binary")
    userhome = pwd.getpwuid(os.getuid()).pw_dir
    outcome = subprocess.run(
        [str(verifier), "-Y", "verify", "-f", str(signers), "-I", SIGNER,
         "-n", SIGN_NAMESPACE, "-s", str(sig)],
        env={"PATH": "/usr/bin:/bin", "HOME": userhome, "LC_ALL": "C"},
        input=data, capture_output=True, timeout=15, check=False,
    )
    if outcome.returncode:
        raise ValueError("signature_invalid:" + path.name)
    return data


def check_map(root: Path, mapping: dict, *, bound=524288) -> int:
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("missing_hash_inventory")
    for name, expected in mapping.items():
        path = strict_relative(name)
        verified_file(root / path, expected, bound=bound)
    return len(mapping)


def verify_source(root: Path, descriptor: Path, sha256: str, policy: dict) -> None:
    verified_file(descriptor, sha256, bound=16384)
    doc = json.loads(safe_file(descriptor, bound=16384), object_pairs_hook=unique_pairs)
    if (doc.get("schema") != "clawsweeper.direct-local-owner-release.v3-split"
            or doc.get("repo") != REPO
            or doc.get("execution_ref") != "develop"
            or doc.get("fleet_root") != "/home/johnh/.local/share/local-ci"
            or doc.get("execution_commit") != policy["repositories"][REPO]["enrolled_head"]
            or not SHA40.fullmatch(doc.get("implementation_commit", ""))
            or not SHA40.fullmatch(doc.get("execution_commit", ""))):
        raise ValueError("source_identity_or_enrolment_mismatch")
    # Verify the reviewed source-bound checker byte-for-byte BEFORE executing it.
    module_bytes = verified_file(
        root / "manual/direct_local_receiver_integration.py",
        policy["_verification"]["receiver_sha256"], bound=655360)
    module = types.ModuleType("pinned_v3_source_verifier")
    module.__file__ = str(root / "manual/direct_local_receiver_integration.py")
    exec(compile(module_bytes, module.__file__, "exec"), module.__dict__)
    verified = module.read_split_source_release(descriptor)
    module.verify_split_source_release(
        verified, enrolled_sha=policy["repositories"][REPO]["enrolled_head"])


def verify_package(*, manifest: Path, stage: Path, runtime: Path, unit: Path,
                   signers: Path, mode: str) -> dict:
    if mode not in ("staged", "installed"):
        raise ValueError("invalid_mode")
    stage = safe_dir(stage)
    runtime = safe_dir(runtime)
    if manifest != stage / "RELEASE_MANIFEST.json":
        raise ValueError("unrecognised_manifest_path")
    doc = json.loads(verify_signature(manifest, signers), object_pairs_hook=unique_pairs)
    if (doc.get("schema") != SCHEMA or doc.get("release") != RELEASE
            or doc.get("owner_uid") != os.getuid()
            or doc.get("host") != socket.gethostname()
            or doc.get("github_actions_required") is not False
            or doc.get("original_controller_sha256")
               != "0a1e52cc1fb1e8f582b8032abaffed1e3d1f49cf08ec39dd63d3fab8208203da"
            or doc.get("accepted_ordinary_at_signing") != 0):
        raise ValueError("unexpected_release_contract")
    staged = safe_dir(stage / "frozen")
    source_files = doc["source_files"]
    if (not isinstance(source_files, dict)
            or "controller/fleet_ci.py" not in source_files
            or "policy/fleet-policy.json" not in source_files
            or "descriptor/clawsweeper-direct-local-release.json" not in source_files
            or "manual/direct_local_receiver_integration.py" not in source_files
            or len([x for x in source_files if x.startswith("manual/")]) != 8):
        raise ValueError("incomplete_frozen_v3_release")
    if (len([x for x in (staged / "manual").iterdir() if x.is_file()]) != 8
            or any(x.is_symlink() or not x.is_file()
                   for x in (staged / "manual").iterdir())):
        raise ValueError("extra_or_missing_frozen_modules")
    count = check_map(staged, source_files, bound=655360)
    expected_controller = source_files["controller/fleet_ci.py"]
    expected_policy = source_files["policy/fleet-policy.json"]
    candidate_policy = json.loads(
        safe_file(staged / "policy/fleet-policy.json", bound=655360),
        object_pairs_hook=unique_pairs)
    actual_policy = json.loads(
        safe_file(runtime / "fleet-policy.json", bound=655360),
        object_pairs_hook=unique_pairs)
    before = doc["original_runtime"]
    if (not isinstance(before, dict) or len(before) < 54
            or "fleet_ci.py" not in before or "fleet-policy.json" not in before
            or "secrets/clawsweeper-direct-local-release.json" not in before):
        raise ValueError("incomplete_original_runtime_inventory")
    if mode == "staged":
        check_map(runtime, before, bound=655360)
    else:
        retained = {k: v for k, v in before.items() if k not in
                    {"fleet_ci.py", "fleet-policy.json",
                     "secrets/clawsweeper-direct-local-release.json"}}
        check_map(runtime, retained, bound=655360)
        check_map(runtime, {
            "fleet_ci.py": expected_controller,
            "fleet-policy.json": expected_policy,
            "secrets/clawsweeper-direct-local-release.json":
                source_files["descriptor/clawsweeper-direct-local-release.json"],
            **{"clawsweeper-manual-code-v3/" + name.removeprefix("manual/"): value
               for name, value in source_files.items()
               if name.startswith("manual/")}
        }, bound=655360)
    # Do not silently alter other repositories, defaults, images, or resource limits.
    old_claw = actual_policy["repositories"][REPO]
    new_claw = candidate_policy["repositories"][REPO]
    if mode == "installed" and actual_policy != candidate_policy:
        raise ValueError("installed_policy_not_exact_candidate")
    if (mode == "staged"
            and ({k: v for k, v in actual_policy.items() if k != "repositories"}
                 != {k: v for k, v in candidate_policy.items() if k != "repositories"}
                 or {k: v for k, v in actual_policy["repositories"].items() if k != REPO}
                    != {k: v for k, v in candidate_policy["repositories"].items() if k != REPO}
                 or any(new_claw.get(k) != old_claw.get(k) for k in
                        ("branch", "contract", "enrolled_head", "excluded_coverage"))
                 or new_claw["suites"]["linux-node24"] != old_claw["suites"]["linux-node24"])):
        raise ValueError("unreviewed_nonclaw_or_policy_changes")
    if set(new_claw["suites"]) != {
        "linux-node24", "linux-node24-claw-check", "linux-node24-claw-sparse"
    }:
        raise ValueError("unreviewed_suite_names")
    for name in ("linux-node24-claw-check", "linux-node24-claw-sparse"):
        profile = new_claw["suites"][name]
        base = new_claw["suites"]["linux-node24"]
        if any(profile[key] != base[key] for key in
               ("cpus", "memory_mib", "writable_mib", "node", "image", "pids",
                "execution_environment_revision")):
            raise ValueError("unreviewed_job_resource_profile")
    unit_expected = doc["unit_candidate_sha256"] if mode == "installed" else doc["unit_original_sha256"]
    verified_file(unit, unit_expected, bound=32768)
    verified_file(stage / "20-direct-local.conf.candidate", doc["unit_candidate_sha256"], bound=32768)
    control = stage / "control/v3_integrity.py"
    verified_file(control, doc["control_sha256"], bound=655360)
    verify_signature(control, signers)
    rollback = safe_dir(stage / "rollback-r8p3")
    count_rollback = check_map(rollback, doc["rollback_files"], bound=655360)
    if mode == "staged":
        for name, expected in doc["rollback_files"].items():
            # The snapshot must have been copied from the EXACT installed bytes.
            if name.startswith("runtime/"):
                verified_file(runtime / name.removeprefix("runtime/"), expected,
                              bound=655360)
            elif name == "unit/20-direct-local.conf":
                verified_file(unit, expected, bound=32768)
    # Verifier is bound to the signed manifest before executing the source gate.
    descriptor = staged / "descriptor/clawsweeper-direct-local-release.json"
    source_policy = dict(candidate_policy)
    source_policy["_verification"] = {
        "receiver_sha256": source_files["manual/direct_local_receiver_integration.py"]
    }
    verify_source(staged, descriptor,
                  source_files["descriptor/clawsweeper-direct-local-release.json"],
                  source_policy)
    return {
        "release": RELEASE, "mode": mode, "source_files_verified": count,
        "rollback_files_verified": count_rollback, "signed_manifest": True,
        "signed_verifier": True, "installed": mode == "installed",
        "ordinary_jobs_accepted": 0, "github_actions_required": False,
        "candidate_controller_sha256": expected_controller,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("staged", "installed"))
    for arg in ("manifest", "stage", "runtime", "unit", "signers"):
        parser.add_argument("--" + arg, required=True, type=Path)
    opt = parser.parse_args()
    try:
        result = verify_package(**vars(opt))
    except Exception as exc:
        print(json.dumps({"gate": "HELD", "reason": type(exc).__name__,
                          "detail": str(exc)[:170]}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
