#!/usr/bin/env python3
"""Prepare ONE signed, staged, rollback-rehearsed Docker inspection release.

Source-only: no live runtime, services, queue, GitHub or remote process effects.
Production installation of this new release needs distinct exact owner authority.
"""
from __future__ import annotations
from datetime import datetime,timezone
import hashlib,json,os
from pathlib import Path
import shutil,subprocess,sys,tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import direct_local_inspect_recovery_integrity as gate
import direct_local_inspect_timeout_recovery as renderer

SOURCE=Path("/home/johnh/.local/share/agent-worktrees/clawsweeper/direct-local-event-bridge-20261113")
EVIDENCE=Path("/home/johnh/.local/state/agent-worktrees/evidence/clawsweeper-distinct-admission-20261116")
STAGE=EVIDENCE/"inspect-retry-owner-staged-20261118"
PUB=Path("/home/johnh/.ssh/github-signing-2026.pub")
SOCK="/run/user/1000/owner-git-signing/agent.sock"
NAMESPACE="clawsweeper-local-fleet-release"
EXPECTED_BRANCH="agent/direct-local-workflow-router-20261113"

def sha(raw):return hashlib.sha256(raw).hexdigest()

def run(args,*,input=None,env=None):
    p=subprocess.run(args,input=input,capture_output=True,check=False,timeout=30,env=env)
    if p.returncode:raise RuntimeError("staging_tool_failed:"+str(args[0]))
    return p.stdout

def persist(path,data):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(),0o600)
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    if sha(path.read_bytes())!=sha(data):raise RuntimeError("staging_written_bytes_changed")
    return sha(data)

def sign(path):
    if not PUB.is_file():raise RuntimeError("owner_signer_unavailable")
    env={"PATH":"/usr/bin:/bin","LC_ALL":"C","HOME":"/home/johnh","SSH_AUTH_SOCK":SOCK}
    run(["/usr/bin/ssh-keygen","-Y","sign","-n",NAMESPACE,"-f",str(PUB),str(path)],env=env)
    signature=Path(str(path)+".sig")
    signature.chmod(0o600)
    # Only count source signed when the signature round trip verifies.
    gate.owner_parent(gate.SIGNERS)
    raw=path.read_bytes()
    run(["/usr/bin/ssh-keygen","-Y","verify","-f",str(gate.SIGNERS),
         "-I","heryourbarme@live.com","-n",NAMESPACE,"-s",str(signature)],input=raw)
    return sha(signature.read_bytes())

def source_sha():
    if os.getuid()!=1000 or os.uname().nodename!="web":raise RuntimeError("wrong_source_host")
    if STAGE.exists() or STAGE.is_symlink():raise RuntimeError("stage_already_exists")
    git=["/usr/bin/git","-C",str(SOURCE)]
    head=run(git+["rev-parse","HEAD"]).decode().strip()
    branch=run(git+["branch","--show-current"]).decode().strip()
    if branch!=EXPECTED_BRANCH or len(head)!=40:
        raise RuntimeError("unexpected_source_branch")
    if run(git+["status","--porcelain"]):
        raise RuntimeError("source_not_clean_prevent_unsigned_staging")
    run(git+["-c","gpg.ssh.allowedSignersFile="+str(gate.SIGNERS),"verify-commit",head])
    # Strictly bind the staging inputs to reviewed git objects, not worktree drift.
    for rel in ("scripts/ci/direct_local_inspect_timeout_recovery.py",
                "scripts/ci/direct_local_inspect_recovery_integrity.py"):
        actual=(SOURCE/rel).read_bytes()
        if actual!=run(git+["show",head+":"+rel]):
            raise RuntimeError("unverified_source_bytes:"+rel)
    return head

def main():
    os.umask(0o077)
    head=source_sha()
    cap,manifest,inventory=gate.owner_parent(gate.SIGNERS)
    # Current signed 69-file installed gate must pass before staging a successor.
    cap_live=cap.verify("installed",gate.CAPACITY_RELEASE,gate.RUNTIME,
                        gate.FLEET_UNIT,gate.WEBHOOK_UNIT,gate.SIGNERS,
                        manifest["source_head"])
    if not cap_live.get("production_installed"):
        raise RuntimeError("current_runtime_not_signed_capacity_successor")
    old=cap.regular(gate.CAPACITY_RELEASE/"frozen/fleet_ci.py")
    candidate=renderer.render(old)
    if sha(cap.regular(gate.RUNTIME/"fleet_ci.py"))!=sha(old):
        raise RuntimeError("live_controller_changed_during_review")
    if STAGE.exists():raise RuntimeError("do_not_duplicate_stage")
    STAGE.mkdir(mode=0o700)
    persist(STAGE/"frozen/fleet_ci.py",candidate)
    persist(STAGE/"rollback/runtime/fleet_ci.py",old)
    for name,rel in ((gate.CONTROL,"scripts/ci/direct_local_inspect_recovery_integrity.py"),
                     (gate.BUILDER,"scripts/ci/direct_local_inspect_timeout_recovery.py")):
        persist(STAGE/name,(SOURCE/rel).read_bytes())
    for label,installed in (("fleet",gate.FLEET_UNIT),("webhook",gate.WEBHOOK_UNIT)):
        oldunit=cap.regular(installed)
        if sha(oldunit)!=manifest["unit_candidate_sha256"][label]:
            raise RuntimeError("current_owner_preflight_changed")
        persist(STAGE/"rollback/unit"/(label+"-20-direct-local.conf"),oldunit)
        persist(STAGE/"unit"/(label+"-20-direct-local.conf.candidate"),
                gate.unit_bytes(head)[label])
    signed_control=sign(STAGE/gate.CONTROL)
    doc=gate.expected(STAGE,head,cap,manifest,inventory)
    persist(STAGE/"RELEASE_MANIFEST.json",
        (json.dumps(doc,indent=2,sort_keys=True)+"\n").encode())
    signed_manifest=sign(STAGE/"RELEASE_MANIFEST.json")
    staged=gate.verify("staged",STAGE,gate.RUNTIME,gate.FLEET_UNIT,
                        gate.WEBHOOK_UNIT,gate.SIGNERS,head)
    if staged["runtime_installed"]:raise RuntimeError("staged_incorrectly_called_installed")
    # Disposable same-UID rehearsal. No live settings or services are changed.
    with tempfile.TemporaryDirectory(prefix="clawsweeper-inspect-disposable-",
                                     dir=EVIDENCE) as temp:
        scratch=Path(temp)
        fake_runtime=scratch/"runtime";fake_runtime.mkdir(mode=0o700)
        for rel in inventory:
            src=gate.RUNTIME/rel
            dst=fake_runtime/rel
            persist(dst,cap.regular(src))
        fake_units={}
        for label in ("fleet","webhook"):
            p=scratch/(label+"-unit.conf")
            persist(p,(STAGE/"unit"/(label+"-20-direct-local.conf.candidate")).read_bytes())
            fake_units[label]=p
        # Production-like exact new file, no fleet DB copied/mutated.
        (fake_runtime/"fleet_ci.py").unlink()
        persist(fake_runtime/"fleet_ci.py",candidate)
        installed=gate.verify("installed",STAGE,fake_runtime,
                              fake_units["fleet"],fake_units["webhook"],gate.SIGNERS,head)
        if not installed["runtime_installed"]:raise RuntimeError("disposable_install_unverified")
        (fake_runtime/"fleet_ci.py").unlink()
        persist(fake_runtime/"fleet_ci.py",old)
        for label in ("fleet","webhook"):
            fake_units[label].unlink()
            persist(fake_units[label],(STAGE/"rollback/unit"/
                                      (label+"-20-direct-local.conf")).read_bytes())
        rollback=gate.verify("staged",STAGE,fake_runtime,
                             fake_units["fleet"],fake_units["webhook"],gate.SIGNERS,head)
        if rollback["runtime_installed"]:raise RuntimeError("disposable_rollback_unverified")
    # Live runtime must remain byte-for-byte identical, still signed and healthy.
    cap.verify("installed",gate.CAPACITY_RELEASE,gate.RUNTIME,
               gate.FLEET_UNIT,gate.WEBHOOK_UNIT,gate.SIGNERS,manifest["source_head"])
    report={"schema":"clawsweeper.inspect-retry-signed-staged.v1",
            "at_utc":datetime.now(timezone.utc).isoformat(),
            "source_head":head,
            "stage":str(STAGE),
            "signed_manifest_sha256":staged["signed_manifest_sha256"],
            "signature_sha256":{"control":signed_control,"manifest":signed_manifest},
            "candidate_controller_sha256":sha(candidate),
            "rollback_controller_sha256":sha(old),
            "staged_verified":True,"disposable_installed_verified":True,
            "disposable_rollback_verified":True,
            "live_installed_capacity_release_preserved":True,
            "live_runtime_mutated":False,"fleet_queue_mutated":False,
            "production_authority":"NOT_GRANTED_FOR_NEW_INSPECT_RELEASE",
            "existing_job_retry_authority":"NOT_GRANTED",
            "distinct_job_success_count":1}
    persist(STAGE/"STAGED_ONLY_VERIFIED.json",
            (json.dumps(report,indent=2,sort_keys=True)+"\n").encode())
    print(json.dumps(report,sort_keys=True))
    return 0

if __name__=="__main__":
    try:sys.exit(main())
    except Exception as exc:
        print(json.dumps({"stage":"HELD","error_type":type(exc).__name__,
                          "detail":str(exc)[:240]},sort_keys=True))
        sys.exit(2)
