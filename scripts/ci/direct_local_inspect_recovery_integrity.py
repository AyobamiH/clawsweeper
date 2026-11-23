#!/usr/bin/env python3
"""Signed two-file receiver + inspection recovery, staged or installed.

Read-only verifier; accepts only the complete prior signed capacity release,
exact candidate bytes, current queues/policies untouched, both preflights,
and the permanent standing-capacity guard.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os
from pathlib import Path
import re, socket, sys, types

CAPACITY_RELEASE=Path("/home/johnh/.local/opt/local-ci-fleet/releases/2026.11.18-clawsweeper-capacity-2g")
CAPACITY_MANIFEST_SHA="369ef76f497f6cfd1b70f5c59405b8d06aec8591595687d60a19661689f596a5"
CAPACITY_CONTROL_SHA="e7c0dd7ba49308328f40f3ce2a76a647ddeb9a0aa4ff4c5d0f195d8b37caf7f6"
RELEASE_NAME="2026.11.18-clawsweeper-receiver-inspect"
RELEASES=CAPACITY_RELEASE.parent
RUNTIME=Path("/home/johnh/.local/share/local-ci")
FLEET_UNIT=Path("/home/johnh/.config/systemd/user/local-ci-fleet.service.d/20-direct-local.conf")
WEBHOOK_UNIT=Path("/home/johnh/.config/systemd/user/local-ci-webhook.service.d/20-direct-local.conf")
SIGNERS=Path("/home/johnh/.config/git/allowed_signers")
CONTROL="control/direct_local_inspect_recovery_integrity.py"
BUILDER="source/direct_local_inspect_timeout_recovery.py"
RECEIVER_SOURCE="source/direct_local_receiver_integration.py"
RECEIVER_RUNTIME="fleet_direct_local_receiver_integration.py"
STANDING_UNIT_SHA="eaed3a815441548d2bf39c0a87ebe9ce0d305b34b6a44311da4f60120bdef0c2"
STANDING_GUARD_SHA="258a2ef650c47fc294b202131ebd4a0226edcf4f50d9b3c29c3546e894cd8557"
STANDING_POLICY_SHA="8944af79b7769f1f1f5e578dd75929f99ac770314bb4cd39e126f340fafe41ff"
STANDING_ROOT=Path("/home/johnh/.local/opt/local-ci-fleet/policies/2026.11.18-web-capacity-standing-v2")
SOURCE_REPO="AyobamiH/clawsweeper"
COMMIT=re.compile(r"[a-f0-9]{40}\Z")

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def owner_parent(signers):
    # Authenticate the predecessor verifier before executing its library code.
    control=CAPACITY_RELEASE/"control/direct_local_capacity_integrity.py"
    raw=control.read_bytes()
    if sha(raw)!=CAPACITY_CONTROL_SHA:
        raise RuntimeError("parent_verifier_digest_changed")
    module=types.ModuleType("signed_parent_capacity_integrity")
    exec(compile(raw,str(control),"exec"),module.__dict__)
    module.regular(control)
    module.signed(control,signers)
    old, successor=module.ancestors(signers)
    parent=module.manifest_at(CAPACITY_RELEASE,CAPACITY_MANIFEST_SHA,signers)
    if (parent["release"]!=CAPACITY_RELEASE.name or
            parent["control_sha256"]!=CAPACITY_CONTROL_SHA or
            parent["schema"]!="clawsweeper.capacity-policy-integrity.v1" or
            parent["source_head"]!="ebfa7e26c396d155a785540c6ed75814fe5c5e4f" or
            parent["capacity"]!=module.CAPACITY or
            parent["rollback_units"].keys()!={"fleet","webhook"} or
            set(parent["changed_runtime"])!=module.CHANGED):
        raise RuntimeError("unexpected_parent_capacity_release")
    module.exact_files(CAPACITY_RELEASE/"frozen",module.CHANGED)
    module.checked_map(CAPACITY_RELEASE/"frozen",parent["changed_runtime"])
    module.checked_map(CAPACITY_RELEASE/"rollback/runtime",parent["rollback_runtime"])
    module.checked_map(CAPACITY_RELEASE/"unit",{
        k+"-20-direct-local.conf.candidate":v for k,v in parent["unit_candidate_sha256"].items()})
    inventory=module.current_inventory(old,successor)
    inventory.update(parent["changed_runtime"])
    if len(inventory)!=69 or inventory["fleet_ci.py"]!=parent["changed_runtime"]["fleet_ci.py"]:
        raise RuntimeError("parent_runtime_inventory_changed")
    return module,parent,inventory

def unit_bytes(source_head):
    if not COMMIT.fullmatch(source_head):raise RuntimeError("invalid_source_commit")
    path=RELEASES/RELEASE_NAME
    args=(f"/usr/bin/python3 -I {path}/{CONTROL} installed --stage {path} "
          f"--runtime {RUNTIME} --fleet-unit {FLEET_UNIT} "
          f"--webhook-unit {WEBHOOK_UNIT} --signers {SIGNERS} "
          f"--source-head {source_head}")
    data=(f"[Service]\nExecStartPre=\nExecStartPre={args}\n"
          f"Environment=FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE="
          f"{RUNTIME}/secrets/clawsweeper-direct-local-release.json\n").encode()
    return {"fleet":data,"webhook":data}

def candidate_bytes(stage,parent):
    # Frozen renderer is bound by the manifest's signed source hash. Execution
    # must come only after the signature+whole-manifest comparison succeeds.
    source=(Path(stage)/BUILDER).read_bytes()
    namespace={"__name__":"signed_capacity_inspect_renderer"}
    exec(compile(source,str(Path(stage)/BUILDER),"exec"),namespace)
    original=(CAPACITY_RELEASE/"frozen/fleet_ci.py").read_bytes()
    if sha(original)!=parent["changed_runtime"]["fleet_ci.py"]:
        raise RuntimeError("parent_controller_changed")
    receiver=(Path(stage)/RECEIVER_SOURCE).read_bytes()
    if sha(receiver)!=sha((Path(stage)/"frozen"/RECEIVER_RUNTIME).read_bytes()):
        raise RuntimeError("receiver_candidate_not_frozen_exact_source")
    return {"fleet_ci.py":namespace["render"](original), RECEIVER_RUNTIME:receiver}

def expected(stage,source_head,cap,parent,inventory):
    stage=cap.directory(stage)
    files={
        "fleet_ci.py":sha(cap.regular(stage/"frozen/fleet_ci.py")),
        RECEIVER_RUNTIME:sha(cap.regular(stage/"frozen"/RECEIVER_RUNTIME))}
    return {
        "schema":"clawsweeper.receiver-inspect-integrity.v1",
        "release":RELEASE_NAME,"host":"web","owner_uid":1000,
        "source_repo":SOURCE_REPO,"source_head":source_head,
        "parent_manifest_sha256":CAPACITY_MANIFEST_SHA,
        "parent_controller_sha256":parent["changed_runtime"]["fleet_ci.py"],
        "parent_receiver_sha256":inventory[RECEIVER_RUNTIME],
        "changed_runtime":files,
        "rollback_runtime":{"fleet_ci.py":parent["changed_runtime"]["fleet_ci.py"],
                            RECEIVER_RUNTIME:inventory[RECEIVER_RUNTIME]},
        "rollback_units":parent["unit_candidate_sha256"],
        "unit_candidate_sha256":{k:sha(v) for k,v in unit_bytes(source_head).items()},
        "control_sha256":sha(cap.regular(stage/CONTROL)),
        "builder_sha256":sha(cap.regular(stage/BUILDER)),
        "receiver_source_sha256":sha(cap.regular(stage/RECEIVER_SOURCE)),
        "unchanged_runtime_files":len(inventory)-2,
        "source_code_only_at_signing":True,
        "github_actions_dispatched":False,
    }

def verify(mode,stage,runtime,fleet_unit,webhook_unit,signers,source_head):
    if mode not in ("staged","installed") or not COMMIT.fullmatch(source_head):
        raise RuntimeError("invalid_gate_mode_or_source")
    if os.getuid()!=1000 or socket.gethostname()!="web":
        raise RuntimeError("unapproved_host_or_uid")
    stage=Path(stage);runtime=Path(runtime);signers=Path(signers)
    cap,parent,inventory=owner_parent(signers)
    raw=cap.signed(stage/"RELEASE_MANIFEST.json",signers)
    doc=json.loads(raw,object_pairs_hook=cap.unique)
    if doc!=expected(stage,source_head,cap,parent,inventory):
        raise RuntimeError("signed_manifest_scope_mismatch")
    cap.digest_file(stage/CONTROL,doc["control_sha256"]);cap.signed(stage/CONTROL,signers)
    cap.exact_files(stage/"control",{"direct_local_inspect_recovery_integrity.py",
                                     "direct_local_inspect_recovery_integrity.py.sig"})
    cap.digest_file(stage/BUILDER,doc["builder_sha256"])
    cap.digest_file(stage/RECEIVER_SOURCE,doc["receiver_source_sha256"])
    cap.exact_files(stage/"frozen",{"fleet_ci.py",RECEIVER_RUNTIME})
    cap.checked_map(stage/"frozen",doc["changed_runtime"])
    cap.exact_files(stage/"source",{"direct_local_inspect_timeout_recovery.py",
                                    "direct_local_receiver_integration.py"})
    rendered=candidate_bytes(stage,parent)
    if set(rendered)!=set(doc["changed_runtime"]) or any(
            sha(rendered[name])!=doc["changed_runtime"][name] for name in rendered):
        raise RuntimeError("candidate_not_exact_reviewed_source")
    cap.exact_files(stage/"rollback/runtime",{"fleet_ci.py",RECEIVER_RUNTIME})
    cap.checked_map(stage/"rollback/runtime",doc["rollback_runtime"])
    for label in ("fleet","webhook"):
        cap.digest_file(stage/"unit"/(label+"-20-direct-local.conf.candidate"),
            doc["unit_candidate_sha256"][label])
        cap.digest_file(stage/"rollback/unit"/(label+"-20-direct-local.conf"),
            doc["rollback_units"][label])
    cap.exact_files(stage/"unit",{"fleet-20-direct-local.conf.candidate",
                                  "webhook-20-direct-local.conf.candidate"})
    cap.exact_files(stage/"rollback/unit",{"fleet-20-direct-local.conf",
                                           "webhook-20-direct-local.conf"})
    if any(cap.regular(stage/"unit"/(label+"-20-direct-local.conf.candidate"))
           !=unit_bytes(source_head)[label] for label in ("fleet","webhook")):
        raise RuntimeError("preflight_unit_command_changed")
    for label in ("fleet","webhook"):
        cap.digest_file(Path("/home/johnh/.config/systemd/user")/
            ("local-ci-"+label+".service.d/90-standing-capacity-policy.conf"),
            STANDING_UNIT_SHA)
    cap.digest_file(STANDING_ROOT/"standing_capacity_policy.py",STANDING_GUARD_SHA)
    cap.digest_file(STANDING_ROOT/"policy.json",STANDING_POLICY_SHA)
    check=dict(inventory)
    if mode=="installed":
        check.update(doc["changed_runtime"])
    cap.checked_map(runtime,check)
    manual={k.removeprefix("clawsweeper-manual-code-v3/") for k in check
            if k.startswith("clawsweeper-manual-code-v3/")}
    cap.exact_files(runtime/"clawsweeper-manual-code-v3",manual)
    pin=doc["rollback_units"] if mode=="staged" else doc["unit_candidate_sha256"]
    cap.digest_file(fleet_unit,pin["fleet"])
    cap.digest_file(webhook_unit,pin["webhook"])
    return {"release":RELEASE_NAME,"mode":mode,"signed_manifest_sha256":sha(raw),
            "source_head":source_head,"verified_runtime_count":len(check),
            "verified_exact_controller":check["fleet_ci.py"],
            "verified_exact_receiver":check[RECEIVER_RUNTIME],
            "rollback_controller_sha256":doc["rollback_runtime"]["fleet_ci.py"],
            "rollback_receiver_sha256":doc["rollback_runtime"][RECEIVER_RUNTIME],
            "standing_guard_preserved":True,
            "registered_existing_queue_untouched":True,
            "runtime_installed":mode=="installed","provider_accepted":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("staged","installed"))
    for name in ("stage","runtime","fleet_unit","webhook_unit","signers"):
        p.add_argument("--"+name.replace("_","-"),required=True,type=Path)
    p.add_argument("--source-head",required=True)
    try:
        print(json.dumps(verify(**vars(p.parse_args())),sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"gate":"HELD","error_type":type(exc).__name__,
                          "detail":str(exc)[:220]},sort_keys=True))
        return 2

if __name__=="__main__":sys.exit(main())
