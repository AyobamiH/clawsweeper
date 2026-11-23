#!/usr/bin/env python3
"""Build, without installing, one reviewed v3 existing-fleet split/manual controller.

The existing timer/queue/fleet is the only executor. Each local-manual request
creates two independently owned and verified jobs through its original queue.
Requires separately authorised frozen source release and physical capacity.
"""
from __future__ import annotations
import ast
import hashlib
import json
import re

import direct_local_fleet_cycle_wiring as wiring
import direct_local_split_policy_gate as gate

FILES = (
    "direct_local_signed_split_manual.py",
    "direct_local_manual_auth.py",
    "direct_local_distinct_admission.py",
    "direct_local_fleet_claim.py",
    "direct_local_event_admission.py",
    "direct_local_workflow.py",
    "direct_local_receiver_integration.py",
    "estate_policy.py",
)

def _hash(raw):
    return hashlib.sha256(raw).hexdigest()

def _replace_function(source: str, name: str, body: str) -> str:
    lines=source.splitlines(keepends=True)
    tree=ast.parse(source)
    targets=[item for item in tree.body
             if isinstance(item,ast.FunctionDef) and item.name==name]
    if len(targets)!=1 or not body.startswith(f"def {name}("):
        raise RuntimeError("v3_manual_unreviewed_function_shape_"+name)
    old=targets[0]
    lines[old.lineno-1:old.end_lineno]=[body.rstrip()+"\n"]
    result="".join(lines)
    ast.parse(result)
    return result

def _bind_v3_ingress_to_verified_release(src: str) -> str:
    """Repair pre-lock v3 module provenance; never execute obsolete r7/v1 code.

    The already-verified frozen v3 helper supplies the release verifier. The
    ingress adapter must come from the SAME immutable implementation commit,
    byte-checked against a sealed Git blob before any of its code executes.
    Keep the established pre-lock, queue and webhook ownership unchanged.
    """
    verifier_start = "                _dl_files = (\n"
    verifier_end = ("                _dl_doc = "
                    "_dl_verifier.read_split_source_release(_dl_bound)\n")
    if src.count(verifier_start) != 1 or src.count(verifier_end) != 1:
        raise RuntimeError("v3_ingress_unrecognised_legacy_verifier_block")
    begin = src.index(verifier_start)
    finish = src.index(verifier_end, begin) + len(verifier_end)
    trusted_verifier = """                _verified_local_manual_worker()
                _dl_verifier_entry = _MANUAL_LIB / 'direct_local_receiver_integration.py'
                _dl_verified_bytes = _dl_verifier_entry.read_bytes()
                if (hashlib.sha256(_dl_verified_bytes).hexdigest()
                        != _MANUAL_HASHES['direct_local_receiver_integration.py']):
                    raise RuntimeError('v3_frozen_release_verifier_changed')
                _dl_verifier = _dl_types.ModuleType('verified_clawsweeper_release_pin')
                _dl_verifier.__file__ = str(_dl_verifier_entry)
                exec(compile(_dl_verified_bytes, str(_dl_verifier_entry), 'exec'),
                     _dl_verifier.__dict__)
                _dl_doc = _dl_verifier.read_split_source_release(_dl_bound)
"""
    src = src[:begin] + trusted_verifier + src[finish:]
    legacy_ingress = """                _dl_entry = ROOT / 'direct_local_ingress_reconcile.py'
                _dl_module = _dl_types.ModuleType('verified_clawsweeper_local_ingress')
                _dl_module.__file__ = str(_dl_entry)
                exec(compile(_dl_bytes[_dl_entry.name], str(_dl_entry), 'exec'),
                     _dl_module.__dict__)
"""
    trusted_ingress = """                # Exact clean implementation checkout was verified above.
                # Confirm the adapter's bytes against its signed Git object
                # before compiling: no mutable runtime module or ambient PATH.
                _dl_entry = (pathlib.Path(_dl_doc['implementation_checkout'])
                             / 'scripts/ci/direct_local_ingress_reconcile.py')
                _dl_git = _dl_verifier.trusted_git_source()
                _dl_env = _dl_verifier.trusted_git_env()
                _dl_object = (_dl_doc['implementation_commit']
                              + ':scripts/ci/direct_local_ingress_reconcile.py')
                _dl_result = subprocess.run(
                    [_dl_git, '-c', 'core.fsmonitor=false', '-C',
                     _dl_doc['implementation_checkout'], 'show',
                     '--no-ext-diff', _dl_object],
                    env=_dl_env, capture_output=True, timeout=8, check=True)
                _dl_ingress_bytes = _dl_result.stdout
                if (not 0 < len(_dl_ingress_bytes) <= 262144
                        or _dl_entry.is_symlink() or not _dl_entry.is_file()
                        or _dl_entry.stat().st_uid != os.getuid()
                        or _dl_entry.stat().st_mode
                           & (_dl_stat.S_IWGRP | _dl_stat.S_IWOTH)
                        or hashlib.sha256(_dl_entry.read_bytes()).digest()
                           != hashlib.sha256(_dl_ingress_bytes).digest()):
                    raise RuntimeError('v3_ingress_not_exact_signed_source')
                _dl_module = _dl_types.ModuleType('verified_clawsweeper_local_ingress')
                _dl_module.__file__ = str(_dl_entry)
                exec(compile(_dl_ingress_bytes, str(_dl_entry), 'exec'),
                     _dl_module.__dict__)
"""
    if src.count(legacy_ingress) != 1:
        raise RuntimeError("v3_ingress_unrecognised_legacy_ingress_block")
    src = src.replace(legacy_ingress, trusted_ingress, 1)
    # Detached workers also used the old verifier, even if pre-lock succeeded.
    # Replace their verifier before any container or claim effect.
    worker_start = "            _dl_file = ROOT / 'direct_local_receiver_integration.py'\n"
    worker_end = "            _dl_doc = _dl_mod.read_split_source_release(_dl_bound)\n"
    if src.count(worker_start) != 1 or src.count(worker_end) != 1:
        raise RuntimeError("v3_worker_unrecognised_legacy_verifier_block")
    begin = src.index(worker_start)
    finish = src.index(worker_end, begin) + len(worker_end)
    trusted_worker = """            _verified_local_manual_worker()
            _dl_file = _MANUAL_LIB / 'direct_local_receiver_integration.py'
            _dl_data = _dl_file.read_bytes()
            if (hashlib.sha256(_dl_data).hexdigest()
                    != _MANUAL_HASHES['direct_local_receiver_integration.py']):
                raise RuntimeError('clawsweeper_v3_worker_release_verifier_changed')
            _dl_mod = _dl_types.ModuleType('clawsweeper_worker_release_verifier')
            _dl_mod.__file__ = str(_dl_file)
            exec(compile(_dl_data, str(_dl_file), 'exec'), _dl_mod.__dict__)
            _dl_doc = _dl_mod.read_split_source_release(_dl_bound)
"""
    src = src[:begin] + trusted_worker + src[finish:]
    leftovers = (
        "_dl_bytes[", "_dl_files = (",
        "ROOT / 'direct_local_receiver_integration.py'",
        "ROOT / 'direct_local_ingress_reconcile.py'",
    )
    if any(item in src for item in leftovers):
        raise RuntimeError("v3_ingress_legacy_module_fallback_remains:" +
                           ",".join(item for item in leftovers if item in src))
    ast.parse(src)
    return src

def compile_v3_manual_controller(current: bytes, *, expected_sha256: str,
                                 reviewed_frozen_sources: dict[str, bytes]) -> dict:
    """Exact installed source -> v3 + split-policy + sandbox capture + signed-manual."""
    if (not isinstance(current,bytes)
            or not re.fullmatch("[a-f0-9]{64}",expected_sha256)
            or _hash(current)!=expected_sha256
            or set(reviewed_frozen_sources)!=set(FILES)
            or any(not isinstance(b,bytes) or not b
                   for b in reviewed_frozen_sources.values())):
        raise RuntimeError("v3_manual_unverified_installed_or_frozen_inputs")
    v3=wiring.compile_split_v3_installed_upgrade(
        current,expected_sha256=expected_sha256)
    src=v3["content"]
    policy=gate.compile_split_policy_gate(src,expected_sha256=_hash(src))
    src=policy["content"]
    capture=wiring.compile_distinct_sandbox_evidence_source(
        src,expected_sha256=_hash(src))
    src=capture["content"].decode("utf-8")
    # The original v3 renderer retained an r7/v1 verifier and ingress adapter
    # at pre-lock, causing a real installed AttributeError and blocking both jobs.
    # Repair only the signed v3 path; never modify the live installed controller.
    src=_bind_v3_ingress_to_verified_release(src)
    old_lib="_MANUAL_LIB = ROOT / \"clawsweeper-manual-code-v1\""
    if src.count(old_lib)!=1:
        raise RuntimeError("v3_manual_unreviewed_old_library")
    src=src.replace(old_lib,
        "_MANUAL_LIB = ROOT / \"clawsweeper-manual-code-v3\"",1)
    # The only installed library must have bytes identical to the reviewed
    # full dependency closure, never silently fall back to an old v1 module.
    old_line=re.search(r"^_MANUAL_HASHES = \{[^\n]+\}\n",src,re.M)
    if not old_line or src.count("_MANUAL_HASHES = ")!=1:
        raise RuntimeError("v3_manual_unreviewed_hash_map")
    hashes={name:_hash(reviewed_frozen_sources[name]) for name in FILES}
    src=src[:old_line.start()]+(
        "_MANUAL_HASHES = "+repr(hashes)+"\n")+src[old_line.end():]
    # Prevent a stale or injected __pycache__ from running ahead of the
    # byte-hashed modules. -B suppresses writing, not loading, bytecode.
    src=_replace_function(src,"_verified_local_manual_worker",FROZEN_VERIFY)
    # Keep the historical manual proof and provider reporting paths; replace
    # only the legacy aggregate admission/verification handlers.
    src=_replace_function(src,"_manual_proof_subprocess",MANUAL_PROOF)
    src=_replace_function(src,"_signed_manual_claim_entry",MANUAL_CLAIM)
    # No legacy aggregate queue proof can enter the new authenticated v3 path.
    anchor="""        if _dl_job['repo'] != 'AyobamiH/clawsweeper':
            return True
"""
    extension="""        if _dl_job['ref'] == 'local-manual':
            try:
                _verified_manual_claim(_dl_job)
                return True
            except Exception:
                return False
"""
    if src.count(anchor)!=1 or src.count(extension):
        raise RuntimeError("v3_manual_unreviewed_authenticator_location")
    src=src.replace(anchor,anchor+extension,1)
    # Each distinct successful job requires an actual Docker container ID.
    anchor="""    if receipt.get("mode") != "local-scheduler-not-github-actions"
"""
    # Add the check within the existing exact success verifier, not a
    # top-level bypass around the verified command/log/cleanup checks.
    expected="def _verified_manual_success_receipt(job, receipt):"
    if src.count(expected)!=1:
        raise RuntimeError("v3_manual_missing_original_success_verifier")
    success_head=src.split(expected,1)[1].split("\ndef ",1)[0]
    if "receipt.get(\"mode\")" not in success_head:
        raise RuntimeError("v3_manual_success_verifier_shape_changed")
    prefix="""    if (job["suite"] in ("linux-node24-claw-check", "linux-node24-claw-sparse")
            and (not isinstance(receipt.get("engine_container_id"), str)
                 or not re.fullmatch("[a-f0-9]{64}",
                                     receipt["engine_container_id"]))):
        raise RuntimeError("split_manual_success_without_real_container_id")
"""
    src=src.replace(expected,expected+"\n"+prefix,1)
    # Confirm that the old aggregate subprocess is absent and the
    # v3 paths are present exactly once.
    if (src.count("def _manual_proof_subprocess(")!=1
            or src.count("def _signed_manual_claim_entry(")!=1
            or "import direct_local_manual_worker as w;" in src
            or "import direct_local_manual_run as m;" in src
            or src.count("clawsweeper-manual-code-v3")!=1
            or src.count("verified_owner_origin")<1):
        raise RuntimeError("v3_manual_old_aggregate_dispatch_remains")
    compiled=src.encode("utf-8")
    ast.parse(src)
    return {
        "schema":"clawsweeper.source-only-v3-split-manual-release.v1",
        "state":"prepared_not_installed",
        "original_sha256":expected_sha256,
        "v3_sha256":v3["proposed_sha256"],
        "policy_sha256":policy["proposed_sha256"],
        "capture_sha256":capture["proposed_sha256"],
        "proposed_sha256":_hash(compiled),
        "frozen_hashes":hashes,
        "controller":compiled,
    }

FROZEN_VERIFY='''def _verified_local_manual_worker():
    \"\"\"Only precisely byte-verified sources may enter the isolated importer.\"\"\"
    import stat
    if (_MANUAL_LIB.is_symlink() or not _MANUAL_LIB.is_dir()
            or _MANUAL_LIB.stat().st_uid != os.getuid()
            or _MANUAL_LIB.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("split_manual_frozen_dir_untrusted")
    # Python may LOAD old .pyc even under -B. Fail closed on any extra path.
    if set(p.name for p in _MANUAL_LIB.iterdir()) != set(_MANUAL_HASHES):
        raise RuntimeError("split_manual_frozen_extra_or_missing_module")
    for filename, expected in _MANUAL_HASHES.items():
        path=_MANUAL_LIB / filename
        if (path.is_symlink() or not path.is_file()
                or path.stat().st_uid != os.getuid()
                or path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise RuntimeError("split_manual_frozen_module_drift")
    return True
'''

MANUAL_PROOF='''def _manual_proof_subprocess(job, start=False):
    """Signature, sibling policies, source and release verified before execution."""
    _verified_local_manual_worker()
    if job["repo"] != _MANUAL_REPO or job["ref"] != "local-manual":
        raise RuntimeError("not_a_split_local_manual_job")
    program = (
        "import sys,json,pathlib;"
        "sys.path.insert(0,sys.argv[1]);"
        "import direct_local_signed_split_manual as m;"
        "import direct_local_receiver_integration as v;"
        "p=m.verify_existing_split_manual_claim("
        "fleet_root=pathlib.Path(sys.argv[2]),job_id=sys.argv[3]);"
        "r=pathlib.Path(sys.argv[4]);"
        "d=v.read_split_source_release(r);"
        "v.verify_split_source_release(d,enrolled_sha=p['source_sha']);"
        "m.auth.read_fresh_develop_sha()==p['source_sha'] or "
        "(_ for _ in ()).throw(RuntimeError('manual_source_changed'));"
        "p.update(live_develop_verified=True,"
        "exact_clean_source_verified=True);"
        "print(json.dumps(p,sort_keys=True))"
    )
    try:
        result=subprocess.run(
            [sys.executable,"-I","-B","-c",program,
             str(_MANUAL_LIB),str(ROOT),job["id"],
             str(ROOT / "secrets" / "clawsweeper-direct-local-release.json")],
            capture_output=True,timeout=60,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimeError("signed_split_manual_verification_unavailable") from exc
    if result.returncode!=0 or not 0<len(result.stdout)<=8192:
        raise RuntimeError("signed_split_manual_verification_failed")
    try:
        proof=json.loads(result.stdout)
    except (ValueError,UnicodeError) as exc:
        raise RuntimeError("signed_split_manual_proof_malformed") from exc
    if (not isinstance(proof,dict)
            or proof.get("schema") !=
               "clawsweeper.existing-fleet-local-manual-split-claim.v1"
            or proof.get("verified_owner_origin") is not True
            or proof.get("provider_status_authorised") is not False
            or proof.get("github_actions_admission_authorised") is not False
            or proof.get("job_id") != job["id"]
            or proof.get("source_sha") != job["sha"]
            or proof.get("ref") != job["ref"]
            or proof.get("live_develop_verified") is not True
            or proof.get("exact_clean_source_verified") is not True
            or not isinstance(proof.get("request_sha256"),str)
            or not re.fullmatch("[a-f0-9]{64}",proof["request_sha256"])
            or (start and proof.get("queue_state") not in
                ("queued","claimed","running"))):
        raise RuntimeError("signed_split_manual_proof_not_bound_to_job")
    return proof
'''

MANUAL_CLAIM='''def _signed_manual_claim_entry(request_file, signature_file):
    """One owner signed request -> two distinct existing fleet queue rows."""
    _verified_local_manual_worker()
    program=(
        "import sys,json,pathlib;"
        "sys.path.insert(0,sys.argv[1]);"
        "import direct_local_receiver_integration as v;"
        "import direct_local_signed_split_manual as m;"
        "r=pathlib.Path(sys.argv[4]);"
        "d=v.read_split_source_release(r);"
        "p=m.auth.owner_bytes(pathlib.Path(sys.argv[2]),4096);"
        "policy=json.loads(m.auth.owner_bytes("
        "pathlib.Path(sys.argv[5]),262144,private=False));"
        "v.verify_split_source_release("
        "d,enrolled_sha=policy['repositories']['AyobamiH/clawsweeper']['enrolled_head']);"
        "result=m.claim_owner_signed_split_manual_run("
        "checkout=pathlib.Path(d['execution_checkout']),"
        "fleet_root=pathlib.Path(sys.argv[6]),"
        "request_file=pathlib.Path(sys.argv[2]),"
        "signature_file=pathlib.Path(sys.argv[3]));"
        "print(json.dumps(result,sort_keys=True))"
    )
    try:
        result=subprocess.run(
            [sys.executable,"-I","-B","-c",program,
             str(_MANUAL_LIB),str(request_file),str(signature_file),
             str(ROOT/"secrets"/"clawsweeper-direct-local-release.json"),
             str(POLICY),str(ROOT)],
            capture_output=True,timeout=75,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimeError("signed_split_manual_claim_unavailable") from exc
    if result.returncode!=0 or not 0<len(result.stdout)<=8192:
        raise RuntimeError("signed_split_manual_claim_held")
    try:
        claim=json.loads(result.stdout)
    except (ValueError,UnicodeError) as exc:
        raise RuntimeError("signed_split_manual_claim_malformed") from exc
    expected={".github/workflows/ci.yml#check":"linux-node24-claw-check",
              ".github/workflows/ci.yml#sparse-repair-builds":"linux-node24-claw-sparse"}
    records=claim.get("jobs") if isinstance(claim,dict) else None
    if (claim.get("schema") !=
           "clawsweeper.existing-fleet-local-manual-split-claim.v1"
            or claim.get("ref")!="local-manual"
            or claim.get("job_intents")!=list(expected)
            or claim.get("admission") not in ("queued","already_admitted")
            or not isinstance(claim.get("source_sha"),str)
            or not SHA.fullmatch(claim["source_sha"])
            or not isinstance(records,list) or len(records)!=2
            or any(not isinstance(item,dict)
                   or item.get("workflow_job") not in expected
                   or item.get("suite")!=expected[item["workflow_job"]]
                   or not isinstance(item.get("job_id"),str)
                   or not NAME.fullmatch(item["job_id"])
                   or not isinstance(item.get("policy"),str)
                   or not re.fullmatch("[a-f0-9]{64}",item["policy"])
                   for item in records)
            or len({item["job_id"] for item in records})!=2
            or len({item["workflow_job"] for item in records})!=2):
        raise RuntimeError("signed_split_manual_claim_result_untrusted")
    return claim
'''
