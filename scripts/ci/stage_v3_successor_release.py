#!/usr/bin/env python3
"""Stage ONE signed source-bound successor to installed v3; never install or dispatch."""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile

import direct_local_v3_successor_integrity as verify
from stage_v3_split_release_integrity import sign

EVIDENCE = Path.home()/".local/state/agent-worktrees/evidence/clawsweeper-distinct-admission-20261116"
TARGET = EVIDENCE/"v3-signed-compatibility-successor-fde3a88-20261118"
CANDIDATE = EVIDENCE/"v3-split-compatibility-repair-candidate-20261118/candidate-controller.py"
SOURCE = Path.home()/".local/share/agent-worktrees/clawsweeper/direct-local-event-bridge-20261113"
RUNTIME = Path.home()/".local/share/local-ci"
PARENT = verify.PARENT
NEW_RELEASE = Path.home()/".local/opt/local-ci-fleet/releases"/verify.RELEASE
FLEET_UNIT = Path.home()/".config/systemd/user/local-ci-fleet.service.d/20-direct-local.conf"
WEBHOOK_UNIT = Path.home()/".config/systemd/user/local-ci-webhook.service.d/20-direct-local.conf"
SIGNERS = Path.home()/".config/git/allowed_signers"
HEAD = "fde3a88be0cd6bcdf07a758501f6bbf3e34ddbcb"
SPLIT_IDS = ("local-fleet-bf40e3b5fe1b","local-fleet-602d95280d8f")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_copy(src, dst, expected):
    verify.digest_file(src, expected)
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if dst.exists() or dst.is_symlink():
        raise ValueError("source_only_staging_collision")
    shutil.copyfile(src, dst)
    dst.chmod(0o600)
    verify.digest_file(dst, expected)


def run(argv, *, timeout=25):
    outcome=subprocess.run([str(v) for v in argv],capture_output=True,
                           text=True,timeout=timeout,check=False,
                           env={**os.environ,"PATH":"/usr/bin:/bin"})
    if outcome.returncode:
        raise RuntimeError("source_verification_failed:" + outcome.stderr[-200:])
    return outcome.stdout


def queue():
    database=RUNTIME/"fleet.sqlite3"
    c=sqlite3.connect("file:"+str(database)+"?mode=ro",uri=True,timeout=5)
    try:
        c.execute("PRAGMA query_only=ON")
        c.execute("BEGIN")
        if c.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("fleet_database_integrity_error")
        if c.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('running','claimed')").fetchone()[0]:
            raise ValueError("fleet_active_worker")
        if c.execute("SELECT COUNT(*) FROM detached_leases").fetchone()[0]:
            raise ValueError("detached_worker_lease")
        records=c.execute("SELECT id,sha,suite,state,attempt FROM jobs WHERE id IN (?,?)",
                          SPLIT_IDS).fetchall()
        if len(records)!=2 or any(row[1]!="944fd5ad04ba5c01d73b8c3059313469aad3357f"
                or row[3]!="queued" or row[4]!=0 for row in records):
            raise ValueError("original_split_queue_changed")
        all_queued=c.execute("SELECT id FROM jobs WHERE state='queued'").fetchall()
        return {"original_split_jobs":[dict(zip(("id","sha","suite","state","attempt"),r)) for r in records],
                "queued_ids":sorted(r[0] for r in all_queued)}
    finally:
        c.rollback()
        c.close()


def unit_content():
    args=(f"installed --stage {NEW_RELEASE} --runtime {RUNTIME} "
          f"--fleet-unit {FLEET_UNIT} --webhook-unit {WEBHOOK_UNIT} --signers {SIGNERS}")
    command=f"/usr/bin/python3 -I {NEW_RELEASE}/control/direct_local_v3_successor_integrity.py {args}"
    shared=(f"[Service]\nExecStartPre=\nExecStartPre={command}\n"
            f"Environment=FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE="
            f"{RUNTIME}/secrets/clawsweeper-direct-local-release.json\n")
    return {"fleet":shared.encode(),"webhook":shared.encode()}


def check_base():
    if os.getuid()!=1000 or socket.gethostname()!="web":
        raise ValueError("wrong_owner_or_host")
    if TARGET.exists() or TARGET.is_symlink() or NEW_RELEASE.exists():
        raise ValueError("already_staged_or_installed_do_not_replay")
    if sha(PARENT/"RELEASE_MANIFEST.json")!=verify.PARENT_MANIFEST:
        raise ValueError("unverified_parent")
    verify.signed(PARENT/"RELEASE_MANIFEST.json",SIGNERS)
    source_head=run(["/usr/bin/git","-C",SOURCE,"rev-parse","HEAD"]).strip()
    if source_head != HEAD:
        # This builder is subsequently committed on the same owner branch.
        # The original repair must remain in ancestry with exact content.
        ancestry=run(["/usr/bin/git","-C",SOURCE,"merge-base","--is-ancestor",HEAD,source_head])
    run(["/usr/bin/git","-C",SOURCE,"verify-commit",HEAD])
    # Read-only remote head: never push or change source to make a verifier pass.
    remote=run(["/usr/bin/git","-C",SOURCE,"ls-remote","origin",
                "refs/heads/agent/direct-local-workflow-router-20261113"]).split()
    if len(remote)!=2 or remote[0]!=source_head:
        raise ValueError("source_not_exact_published_head")
    if run(["/usr/bin/git","-C",SOURCE,"status","--porcelain=v1"]).strip():
        raise ValueError("source_worktree_dirty")
    if sha(CANDIDATE)!=verify.NEW_CONTROLLER:
        raise ValueError("candidate_not_verified_focused_test_bytes")
    parent_check=run(["/usr/bin/python3","-I",PARENT/"control/v3_integrity.py",
            "installed","--manifest",PARENT/"RELEASE_MANIFEST.json",
            "--stage",PARENT,"--runtime",RUNTIME,
            "--unit",FLEET_UNIT,"--signers",SIGNERS])
    if not json.loads(parent_check).get("installed"):
        raise ValueError("parent_installed_gate_failed")
    return source_head


def stage_release():
    os.umask(0o077)
    source_head=check_base()
    before=queue()
    old=json.loads((PARENT/"RELEASE_MANIFEST.json").read_text())
    sources=dict(old["source_files"])
    sources["controller/fleet_ci.py"]=verify.NEW_CONTROLLER
    original_units={"fleet":sha(FLEET_UNIT),"webhook":sha(WEBHOOK_UNIT)}
    if original_units["fleet"]!=old["unit_candidate_sha256"]:
        raise ValueError("installed_fleet_unit_drift")
    originals={
        "runtime/fleet_ci.py":old["source_files"]["controller/fleet_ci.py"],
        "runtime/fleet-policy.json":old["source_files"]["policy/fleet-policy.json"],
        "runtime/secrets/clawsweeper-direct-local-release.json":
            old["source_files"]["descriptor/clawsweeper-direct-local-release.json"],
        **{"runtime/clawsweeper-manual-code-v3/"+name.removeprefix("manual/"):value
           for name,value in old["source_files"].items() if name.startswith("manual/")},
        "unit/fleet-20-direct-local.conf":original_units["fleet"],
        "unit/webhook-20-direct-local.conf":original_units["webhook"],
    }
    if len(originals)!=13 or len(sources)!=11:
        raise ValueError("invalid_frozen_closure")
    unit_bytes=unit_content()
    target_tmp=Path(str(TARGET)+".incomplete")
    if target_tmp.exists() or target_tmp.is_symlink():
        raise ValueError("existing_partial_stage_requires_reconciliation")
    target_tmp.mkdir(mode=0o700)
    try:
        for name,expected in sources.items():
            src=CANDIDATE if name=="controller/fleet_ci.py" else PARENT/"frozen"/name
            checked_copy(src,target_tmp/"frozen"/name,expected)
        for name,expected in originals.items():
            if name.startswith("runtime/"):
                path=RUNTIME/name.removeprefix("runtime/")
            else:
                path=FLEET_UNIT if name=="unit/fleet-20-direct-local.conf" else WEBHOOK_UNIT
            checked_copy(path,target_tmp/"rollback-current-v3"/name,expected)
        for name,expected in old["rollback_files"].items():
            checked_copy(PARENT/"rollback-r8p3"/name,target_tmp/"rollback-r8p3"/name,expected)
        control=target_tmp/"control/direct_local_v3_successor_integrity.py"
        root=Path(__file__).resolve().parent
        src_control=root/control.name
        checked_copy(src_control,control,sha(src_control))
        sign(control)
        unit_hashes={}
        for label,data in unit_bytes.items():
            dst=target_tmp/"unit"/(label+"-20-direct-local.conf.candidate")
            dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            dst.write_bytes(data)
            dst.chmod(0o600)
            unit_hashes[label]=sha(dst)
        manifest={
            "schema":verify.SCHEMA,"release":verify.RELEASE,
            "parent_manifest_sha256":verify.PARENT_MANIFEST,
            "parent_controller_sha256":verify.PARENT_CONTROLLER,
            "source_commit":HEAD,"builder_signed_branch_head":source_head,
            "owner_uid":os.getuid(),"host":socket.gethostname(),
            "source_files":sources,"rollback_current_v3":originals,
            "rollback_r8p3":old["rollback_files"],
            "webhook_unit_original_sha256":original_units["webhook"],
            "unit_original_sha256":original_units,
            "unit_candidate_sha256":unit_hashes,
            "control_sha256":sha(control),
            "github_actions_dispatched":False,
            "production_installed_at_signing":False,
            "approval_status":"held_for_new_exact_source_install_authority",
            "at_utc":datetime.now(timezone.utc).isoformat(),
        }
        file=target_tmp/"RELEASE_MANIFEST.json"
        file.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
        file.chmod(0o600)
        sign(file)
        # Stage location and production candidate are distinct; verify before publishing.
        receipt=verify.verify("staged",target_tmp,RUNTIME,FLEET_UNIT,WEBHOOK_UNIT,SIGNERS)
        if before!=queue():
            raise ValueError("queue_changed_during_staging")
        target_tmp.rename(TARGET)
        return {"schema":"clawsweeper.v3-successor-signed-source-stage.v1",
                "verified":receipt,"signed_manifest_sha256":sha(TARGET/"RELEASE_MANIFEST.json"),
                "signed_control_sha256":sha(TARGET/"control/direct_local_v3_successor_integrity.py"),
                "staged_path":str(TARGET),"candidate_release_path":str(NEW_RELEASE),
                "old_runtime_unchanged":True,"jobs_unchanged":before,
                "r8p3_rollback_preserved":True,
                "install_authorised":False,"install_performed":False}
    except Exception:
        # Preserve incomplete artifacts for explicit forensics; never blindly clean them.
        raise


if __name__=="__main__":
    try:
        print(json.dumps(stage_release(),sort_keys=True,indent=2))
    except Exception as exc:
        print(json.dumps({"stage":"HELD","error":type(exc).__name__,
                          "detail":str(exc)[:200]}))
        sys.exit(2)
