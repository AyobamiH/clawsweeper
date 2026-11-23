#!/usr/bin/env python3
"""Stage an owner-signed v3 split CI release; NEVER install or admit any job."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys

EVIDENCE = Path.home()/".local/state/agent-worktrees/evidence/clawsweeper-distinct-admission-20261116"
SOURCE = EVIDENCE/"v3-split-manual-source-bfff23836-20261117"
PRIOR = EVIDENCE/"v3-preinstall-frozen-signed-sources-bfff23836-20261117"
TARGET = EVIDENCE/"v3-signed-integrity-package-bfff23836-20261117"
RELEASE_NAME = "2026.11.17-v3-clawsweeper-split-manual"
RELEASE_ROOT = Path.home()/".local/opt/local-ci-fleet/releases"/RELEASE_NAME
RUNTIME = Path.home()/".local/share/local-ci"
R8_MANIFEST = Path.home()/".local/opt/local-ci-fleet/releases/2026.11.15-r8p3-clawsweeper-local-manual/frozen/RELEASE_MANIFEST.json"
UNIT = Path.home()/".config/systemd/user/local-ci-fleet.service.d/20-direct-local.conf"
SIGNERS = Path.home()/".config/git/allowed_signers"
SCRIPT_ROOT = Path(__file__).resolve().parent
FROZEN_KEYS = ("direct_local_workflow.py", "direct_local_signed_split_manual.py",
    "direct_local_distinct_admission.py", "estate_policy.py",
    "direct_local_event_admission.py", "direct_local_manual_auth.py",
    "direct_local_receiver_integration.py", "direct_local_fleet_claim.py")

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def exact_copy(src, dst, *, limit=524288):
    if src.is_symlink() or not src.is_file() or src.stat().st_size>limit:
        raise RuntimeError("unsafe_source_copy:"+src.name)
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if dst.exists():
        raise RuntimeError("unexpected_destination_exists")
    shutil.copyfile(src, dst)
    dst.chmod(0o600)
    if sha(src)!=sha(dst):
        raise RuntimeError("copy_changed_bytes")
    return sha(dst)

def sign(path):
    env = {"PATH":"/usr/bin:/bin", "HOME":pwd.getpwuid(os.getuid()).pw_dir,
           "LC_ALL":"C", "SSH_AUTH_SOCK":os.environ.get("SSH_AUTH_SOCK", "")}
    signer=Path.home()/".ssh/github-signing-2026.pub"
    if not signer.is_file():
        raise RuntimeError("owner_signing_key_unavailable")
    result=subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "sign", "-n",
         "clawsweeper-local-fleet-release", "-f", str(signer), str(path)],
        env=env, capture_output=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError("owner_signature_unavailable")
    sig=Path(str(path)+".sig")
    sig.chmod(0o600)
    verify=subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(SIGNERS),
         "-I", "heryourbarme@live.com", "-n",
         "clawsweeper-local-fleet-release", "-s", str(sig)],
        input=path.read_bytes(),env=env,capture_output=True,timeout=15)
    if verify.returncode:
        raise RuntimeError("signature_roundtrip_failed")
    return sha(sig)

def main():
    os.umask(0o077)
    if TARGET.exists():
        raise RuntimeError("staging_already_exists_do_not_overwrite")
    r8=json.loads(R8_MANIFEST.read_text())
    if r8.get("r8_controller_sha256")!="0a1e52cc1fb1e8f582b8032abaffed1e3d1f49cf08ec39dd63d3fab8208203da":
        raise RuntimeError("unexpected_installed_r8")
    original=dict(r8["r7_source_sha256"])
    original["fleet_ci.py"]=r8["r8_controller_sha256"]
    for name, value in r8["manual_library_sha256"].items():
        original["clawsweeper-manual-code-v1/"+name]=value
    original["secrets/clawsweeper-direct-local-release.json"] = sha(
        RUNTIME/"secrets/clawsweeper-direct-local-release.json")
    if original["fleet-policy.json"]!=sha(RUNTIME/"fleet-policy.json") or original["fleet_ci.py"]!=sha(RUNTIME/"fleet_ci.py"):
        raise RuntimeError("installed_fleet_has_changed")
    for name,digest in original.items():
        if sha(RUNTIME/name)!=digest:
            raise RuntimeError("original_runtime_drift:"+name)
    # Protect against a concurrent worker or mid-install mutation.
    if sha(UNIT)!=r8["r8_unit_sha256"]:
        raise RuntimeError("installed_release_unit_changed")
    if not SOURCE.is_dir() or not PRIOR.is_dir():
        raise RuntimeError("existing_verified_source_stage_missing")
    TARGET.mkdir(mode=0o700)
    frozen=TARGET/"frozen"
    frozen.mkdir(mode=0o700)
    control=TARGET/"control"
    control.mkdir(mode=0o700)
    source_map={}
    paths={
      "controller/fleet_ci.py":SOURCE/"controller/fleet_ci.py",
      "policy/fleet-policy.json":SOURCE/"policy/fleet-policy.json",
      "descriptor/clawsweeper-direct-local-release.json":PRIOR/"SOURCE_RELEASE_CANDIDATE.json"
    }
    for name in FROZEN_KEYS:
        paths["manual/"+name]=SOURCE/"frozen/clawsweeper-manual-code-v3"/name
    if set(paths)!=set(("controller/fleet_ci.py","policy/fleet-policy.json",
        "descriptor/clawsweeper-direct-local-release.json")) | set("manual/"+x for x in FROZEN_KEYS):
        raise RuntimeError("unexpected_release_closure")
    for rel,src in paths.items():
        source_map[rel]=exact_copy(src,frozen/rel)
    rollback=TARGET/"rollback-r8p3"
    rollback.mkdir(mode=0o700)
    rollback_map={}
    for src in sorted((PRIOR/"rollback-r8p3").rglob("*")):
        if src.is_file():
            rel=src.relative_to(PRIOR/"rollback-r8p3").as_posix()
            rollback_map[rel]=exact_copy(src,rollback/rel)
            # All rollback bytes exactly match the original installed runtime.
            if rel.startswith("runtime/") and rollback_map[rel]!=original[rel.removeprefix("runtime/")]:
                raise RuntimeError("rollback_not_matching_runtime")
    if len(rollback_map)!=11:
        raise RuntimeError("rollback_inventory_incomplete")
    verifier_src=SCRIPT_ROOT/"direct_local_v3_release_integrity.py"
    verifier=control/"v3_integrity.py"
    verifier_digest=exact_copy(verifier_src,verifier)
    verifier_signature=sign(verifier)

    unit_path=TARGET/"20-direct-local.conf.candidate"
    # Existing service/timer remain unchanged until exact authorisation.
    new_unit=(
        "[Service]\n"
        "ExecStartPre=\n"
        f"ExecStartPre=/usr/bin/python3 -I {RELEASE_ROOT}/control/v3_integrity.py "
        f"installed --manifest {RELEASE_ROOT}/RELEASE_MANIFEST.json "
        f"--stage {RELEASE_ROOT} --runtime {RUNTIME} "
        f"--unit {UNIT} --signers {SIGNERS}\n"
        f"Environment=FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE={RUNTIME}/secrets/clawsweeper-direct-local-release.json\n"
    )
    unit_path.write_text(new_unit)
    unit_path.chmod(0o600)

    manifest={
        "schema":"clawsweeper.v3-split-manual-install-integrity.v1",
        "release":RELEASE_NAME,
        "owner_uid":os.getuid(), "host":socket.gethostname(),
        "github_actions_required":False,
        "accepted_ordinary_at_signing":0,
        "implementation_commit":"bfff2383668822eba7babd266406f1d229e51d3e",
        "execution_commit":"944fd5ad04ba5c01d73b8c3059313469aad3357f",
        "original_controller_sha256":r8["r8_controller_sha256"],
        "original_runtime":original,
        "source_files":source_map,
        "rollback_files":rollback_map,
        "unit_original_sha256":r8["r8_unit_sha256"],
        "unit_candidate_sha256":sha(unit_path),
        "control_sha256":verifier_digest,
        "control_signature_sha256":verifier_signature,
        "source_release_original_sha256":sha(PRIOR/"SOURCE_RELEASE_CANDIDATE.json"),
        "stage_created_utc":datetime.now(timezone.utc).isoformat(),
        "approval_status":"source_staged_not_production_install_approved",
    }
    m=TARGET/"RELEASE_MANIFEST.json"
    m.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
    m.chmod(0o600)
    signature=sign(m)
    print(json.dumps({"release":RELEASE_NAME,"staged":str(TARGET),
      "manifest_sha256":sha(m),"manifest_signature_sha256":signature,
      "verifier_sha256":verifier_digest,"source_files":len(source_map),
      "rollback_files":len(rollback_map),"unit_candidate_sha256":sha(unit_path),
      "production_installed":False,"job_admissions":0},sort_keys=True))

if __name__=="__main__":
    try: main()
    except Exception as exc:
        print(json.dumps({"stage":"HELD","reason":type(exc).__name__,"detail":str(exc)[:170]}))
        sys.exit(2)
