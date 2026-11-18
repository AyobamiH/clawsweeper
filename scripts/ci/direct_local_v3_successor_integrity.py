#!/usr/bin/env python3
"""Read-only signed v3 successor verification; never installs or starts CI."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

SCHEMA = "clawsweeper.v3-successor-integrity.v1"
RELEASE = "2026.11.18-v3-clawsweeper-split-compatibility"
PARENT = Path("/home/johnh/.local/opt/local-ci-fleet/releases/2026.11.17-v3-clawsweeper-split-manual")
PARENT_MANIFEST = "0d438309dce0c9611bb425d14384bc1819b02cc1884a7e19d8fa7cacce3cda2d"
PARENT_CONTROLLER = "87e89f1cbfca7a1e33bc5601ef84a6a6e292c80663fcc635e67396a1a573b528"
NEW_CONTROLLER = "dbfeb11511c3104b46c4f729642a5af27a054bc40db2aae6cebc11b23b246b37"
SIGNER = "heryourbarme@live.com"
NAMESPACE = "clawsweeper-local-fleet-release"
HASH = re.compile(r"[0-9a-f]{64}\Z")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, val in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = val
    return result


def regular(path, limit=1024 * 1024):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlinked_file:" + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022 or not 0 < info.st_size <= limit):
            raise ValueError("unsafe_file:" + path.name)
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if (len(raw) != info.st_size or
                (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise ValueError("changed_during_read:" + path.name)
        return raw
    finally:
        os.close(fd)


def digest_file(path, expected):
    if not isinstance(expected, str) or not HASH.fullmatch(expected):
        raise ValueError("invalid_expected_hash")
    raw = regular(path)
    if sha(raw) != expected:
        raise ValueError("digest_mismatch:" + Path(path).name)
    return raw


def signed(path, signers):
    raw = regular(path)
    sig = Path(str(path) + ".sig")
    regular(sig, 4096)
    regular(signers, 8192)
    out = subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(signers),
         "-I", SIGNER, "-n", NAMESPACE, "-s", str(sig)],
        input=raw, capture_output=True, timeout=15, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/home/johnh"})
    if out.returncode:
        raise ValueError("invalid_owner_signature:" + path.name)
    return raw


def checked_map(root, mapping):
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("invalid_inventory")
    for rel, expected in mapping.items():
        if (not isinstance(rel, str) or not rel or
                any(part in ("", ".", "..") for part in rel.split("/"))
                or "\\" in rel or rel.startswith("/")):
            raise ValueError("unsafe_inventory_path")
        digest_file(root / rel, expected)
    return len(mapping)


def directory(path):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or
            info.st_uid != os.getuid() or info.st_mode & 0o022):
        raise ValueError("unsafe_directory:" + path.name)
    return path


def verify(mode, stage, runtime, fleet_unit, webhook_unit, signers):
    if mode not in ("staged", "installed"):
        raise ValueError("invalid_verification_mode")
    stage, runtime = directory(stage), directory(runtime)
    parent = directory(PARENT)
    old_raw = digest_file(parent / "RELEASE_MANIFEST.json", PARENT_MANIFEST)
    signed(parent / "RELEASE_MANIFEST.json", signers)
    old = json.loads(old_raw, object_pairs_hook=unique)
    if (old.get("release") != "2026.11.17-v3-clawsweeper-split-manual"
            or old["source_files"]["controller/fleet_ci.py"] != PARENT_CONTROLLER
            or len(old["rollback_files"]) != 11):
        raise ValueError("unexpected_parent_release")
    manifest = json.loads(signed(stage / "RELEASE_MANIFEST.json", signers),
                          object_pairs_hook=unique)
    if (manifest.get("schema") != SCHEMA or manifest.get("release") != RELEASE or
            manifest.get("parent_manifest_sha256") != PARENT_MANIFEST or
            manifest.get("parent_controller_sha256") != PARENT_CONTROLLER or
            manifest.get("source_commit") != "fde3a88be0cd6bcdf07a758501f6bbf3e34ddbcb" or
            manifest.get("owner_uid") != os.getuid() or
            manifest.get("host") != socket.gethostname() or
            manifest.get("github_actions_dispatched") is not False or
            manifest.get("production_installed_at_signing") is not False):
        raise ValueError("unexpected_successor_manifest_identity")
    control = stage / "control/direct_local_v3_successor_integrity.py"
    digest_file(control, manifest["control_sha256"])
    signed(control, signers)
    sources = manifest["source_files"]
    expected_names = set(old["source_files"])
    if (set(sources) != expected_names or len(sources) != 11 or
            sources["controller/fleet_ci.py"] != NEW_CONTROLLER or
            {k:v for k,v in sources.items() if k != "controller/fleet_ci.py"} !=
            {k:v for k,v in old["source_files"].items() if k != "controller/fleet_ci.py"}):
        raise ValueError("unexpected_successor_source_closure")
    if set(p.name for p in (stage/"frozen/manual").iterdir()) != {
            name.removeprefix("manual/") for name in sources if name.startswith("manual/")}:
        raise ValueError("unreviewed_extra_manual_helper")
    checked_map(stage/"frozen", sources)
    checked_map(parent/"frozen", old["source_files"])
    checked_map(stage/"rollback-r8p3", old["rollback_files"])
    if manifest["rollback_r8p3"] != old["rollback_files"]:
        raise ValueError("r8_rollback_changed")
    originals = manifest["rollback_current_v3"]
    expect_original = {
        "runtime/fleet_ci.py": PARENT_CONTROLLER,
        "runtime/fleet-policy.json": old["source_files"]["policy/fleet-policy.json"],
        "runtime/secrets/clawsweeper-direct-local-release.json":
            old["source_files"]["descriptor/clawsweeper-direct-local-release.json"],
        **{"runtime/clawsweeper-manual-code-v3/" + key.removeprefix("manual/"): value
           for key,value in old["source_files"].items() if key.startswith("manual/")},
        "unit/fleet-20-direct-local.conf": old["unit_candidate_sha256"],
        "unit/webhook-20-direct-local.conf": manifest["webhook_unit_original_sha256"],
    }
    if originals != expect_original or len(originals) != 13:
        raise ValueError("incomplete_current_v3_rollback")
    checked_map(stage/"rollback-current-v3", originals)
    if (manifest["unit_candidate_sha256"].keys() !=
            {"fleet", "webhook"} or
            manifest["unit_original_sha256"] != {
                "fleet": originals["unit/fleet-20-direct-local.conf"],
                "webhook": originals["unit/webhook-20-direct-local.conf"]}):
        raise ValueError("unit_inventory_mismatch")
    checked_map(stage/"unit", {
        "fleet-20-direct-local.conf.candidate": manifest["unit_candidate_sha256"]["fleet"],
        "webhook-20-direct-local.conf.candidate": manifest["unit_candidate_sha256"]["webhook"],
    })
    if mode == "staged":
        checked_map(runtime, {k.removeprefix("runtime/"):v for k,v in originals.items()
                              if k.startswith("runtime/")})
    else:
        checked_map(runtime, {
            "fleet_ci.py": NEW_CONTROLLER,
            "fleet-policy.json": sources["policy/fleet-policy.json"],
            "secrets/clawsweeper-direct-local-release.json":
                sources["descriptor/clawsweeper-direct-local-release.json"],
            **{"clawsweeper-manual-code-v3/" + name.removeprefix("manual/"):value
               for name,value in sources.items() if name.startswith("manual/")},
        })
    old_inventory = dict(old["original_runtime"])
    # All unrelated controller dependencies remain byte-identical to parent.
    for name in ("fleet_ci.py", "fleet-policy.json",
                 "secrets/clawsweeper-direct-local-release.json"):
        old_inventory.pop(name)
    checked_map(runtime, old_inventory)
    expected_units = (manifest["unit_original_sha256"]
                      if mode == "staged" else manifest["unit_candidate_sha256"])
    digest_file(fleet_unit, expected_units["fleet"])
    digest_file(webhook_unit, expected_units["webhook"])
    return {"release": RELEASE, "mode": mode,
            "controller_sha256": NEW_CONTROLLER,
            "source_files_verified": len(sources),
            "current_v3_rollback_files_verified": len(originals),
            "r8p3_rollback_files_verified": len(old["rollback_files"]),
            "old_unrelated_runtime_verified": len(old_inventory),
            "owner_signed": True, "production_installed": mode == "installed",
            "job_execution_claimed": False}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=("staged", "installed"))
    for key in ("stage", "runtime", "fleet_unit", "webhook_unit", "signers"):
        p.add_argument("--" + key.replace("_", "-"), type=Path, required=True)
    a = vars(p.parse_args())
    mode = a.pop("mode")
    try:
        print(json.dumps(verify(mode, **a), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"gate":"HELD", "reason":type(exc).__name__,
                          "detail":str(exc)[:190]}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
