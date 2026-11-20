#!/usr/bin/env python3
"""Render a source-only successor to the existing installed v3 fleet controller.

No installation, queue write, external effects or new controller. The frozen
third-replay helper closure and exact signed successor installation are separate.
"""
from __future__ import annotations

import ast
import hashlib
import re

import direct_local_offline_replay_suite as replay_suite

REPLAY_LIB = (
    "direct_local_replay_admission.py",
    "direct_local_replay_release_contract.py",
    "direct_local_offline_replay_suite.py",
    "direct_local_offline_replay.py",
)
REF = "local-manual-replay"
SUITE = replay_suite.SUITE
REPO = "AyobamiH/clawsweeper"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _once(source: str, before: str, after: str) -> str:
    if source.count(before) != 1 or (before != after and source.count(after)):
        raise ValueError("replay_controller_unreviewed_anchor:" + before[:64])
    changed = source.replace(before, after, 1)
    ast.parse(changed)
    return changed


def _old_map(source: str) -> dict[str, str]:
    hits = re.findall(r"^_MANUAL_HASHES = (\{[^\n]+\})$", source, re.M)
    if len(hits) != 1:
        raise ValueError("replay_untrusted_existing_module_hashes")
    hashes = ast.literal_eval(hits[0])
    if (not isinstance(hashes, dict) or len(hashes) != 8
            or "direct_local_signed_split_manual.py" not in hashes
            or "direct_local_receiver_integration.py" not in hashes
            or any(not re.fullmatch("[a-f0-9]{64}", value)
                   for value in hashes.values())):
        raise ValueError("replay_untrusted_existing_v3_closure")
    return hashes


def render(installed: bytes, expected_sha256: str,
           frozen_sources: dict[str, bytes]) -> dict:
    if (not isinstance(installed, bytes)
            or not re.fullmatch("[a-f0-9]{64}", expected_sha256)
            or _sha(installed) != expected_sha256):
        raise ValueError("replay_unverified_installed_controller_bytes")
    source = installed.decode("utf-8")
    ast.parse(source)
    former = _old_map(source)
    if set(frozen_sources) != set(former) | set(REPLAY_LIB):
        raise ValueError("replay_incomplete_or_unreviewed_source_closure")
    if any(not isinstance(raw, bytes) or not raw
           for raw in frozen_sources.values()):
        raise ValueError("replay_missing_frozen_source")
    if any(_sha(frozen_sources[name]) != expected
           for name, expected in former.items()):
        raise ValueError("replay_historical_v3_closure_changed")
    updated = {**former, **{name: _sha(frozen_sources[name])
                            for name in REPLAY_LIB}}
    source = _once(source, "_MANUAL_HASHES = " + repr(former),
                   "_MANUAL_HASHES = " + repr(updated))
    source = _once(
        source,
        "ALLOWED_WORKFLOW_PATHS = frozenset({",
        "ALLOWED_WORKFLOW_PATHS = frozenset({'.github/workflows/release-offline-replay.yml', "
    )
    # v3 two-suite rule is untouched. A distinct explicit third rule applies.
    source = _once(
        source,
        "repo == 'AyobamiH/clawsweeper' and name in _dl_names):",
        "repo == 'AyobamiH/clawsweeper' and "
        "(name in _dl_names or name == 'linux-node24-claw-replay')):")
    needle = "            if suite['node'] not in ('20','22','24'):"
    extra = """            if repo == 'AyobamiH/clawsweeper' and name == 'linux-node24-claw-replay':
                if (set(suite) != {'node', 'image', 'cpus', 'memory_mib',
                                   'pids', 'writable_mib', 'execution_environment_revision',
                                   'steps'}
                        or suite.get('node') != '24'
                        or suite.get('image') != 'sha256:dc7e982df33f88146add5c0f00907c355777ca06f0fc56b568c5c9f9a7ce35e2'
                        or suite.get('execution_environment_revision') != 'web-docker-v7-dual-path-pnpm-jq'
                        or tuple(suite.get(k) for k in ('cpus','memory_mib','writable_mib','pids'))
                           != (1,1536,1536,256)
                        or suite.get('steps') != """ + repr([
                            {"name": name, "command": cmd, "timeout": timeout}
                            for name, cmd, timeout in replay_suite.STEPS
                        ]) + """):
                    raise RuntimeError('unreviewed_clawsweeper_third_replay_policy')
"""
    source = _once(source, needle, extra + needle)
    source = _once(
        source,
        "def setup():\n",
        REPLAY_HELPERS + "\ndef setup():\n")
    source = _once(
        source,
        "    if job[\"repo\"] == _MANUAL_REPO and job[\"ref\"] == \"local-manual\":\n"
        "        _verified_manual_start(job)  # transient GET failures HOLD; never cancel source\n",
        "    if job['repo'] == _MANUAL_REPO and job['ref'] == 'local-manual-replay':\n"
        "        _verified_replay_claim(job, start=True)\n"
        "        return True\n"
        "    if job[\"repo\"] == _MANUAL_REPO and job[\"ref\"] == \"local-manual\":\n"
        "        _verified_manual_start(job)  # transient GET failures HOLD; never cancel source\n")
    # Constrain the detached worker, its actual isolation proof and deadline.
    source = _once(
        source,
        "job['suite'] in ('linux-node24-claw-check',\n"
        "                                 'linux-node24-claw-sparse')):",
        "job['suite'] in ('linux-node24-claw-check',\n"
        "                                 'linux-node24-claw-sparse',\n"
        "                                 'linux-node24-claw-replay')):")
    source = _once(
        source,
        "job[\"suite\"] in (\"linux-node24-claw-check\", \"linux-node24-claw-sparse\")",
        "job[\"suite\"] in (\"linux-node24-claw-check\", \"linux-node24-claw-sparse\", "
        "\"linux-node24-claw-replay\")")
    source = _once(
        source,
        "    overall_deadline=time.monotonic()+cfg.get('total_timeout',10800)",
        "    overall_deadline=time.monotonic()+("
        "min(cfg.get('total_timeout',10800),900) "
        "if job['repo']==_MANUAL_REPO and job['ref']=='local-manual-replay' "
        "else cfg.get('total_timeout',10800))")
    # replay_no_implicit_second_execution: this one-use owner authority is
    # for a single real container attempt, including an error/timeout outcome.
    source = _once(
        source,
        "        retry=outcome=='error' and attempt<3 and 'cleanup_error' not in receipt",
        "        retry=(outcome=='error' and attempt<3 and 'cleanup_error' not in receipt "
        "and not (job['repo']==_MANUAL_REPO and job['ref']=='local-manual-replay'))")
    # Source ref is neither the main-poller path nor a GitHub status ref.
    source = _once(
        source,
        "def validate_job(job,policy):\n",
        "def validate_job(job,policy):\n"
        "    if (job['repo']==_MANUAL_REPO and job['suite']=='linux-node24-claw-replay'\n"
        "            and job['ref']!='local-manual-replay') or (\n"
        "            job['ref']=='local-manual-replay' and (\n"
        "            job['repo']!=_MANUAL_REPO or job['suite']!='linux-node24-claw-replay')):\n"
        "        raise RuntimeError('replay_wrong_source_ref_or_job')\n")
    source = _once(
        source,
        "def publish(db,job,state,description,receipt=None):\n",
        "def publish(db,job,state,description,receipt=None):\n"
        + REPLAY_PUBLISH)
    source = _once(
        source,
        "def publish_pending(db,job,description):\n",
        "def publish_pending(db,job,description):\n"
        "    if job['repo']==_MANUAL_REPO and job['ref']=='local-manual-replay':\n"
        "        _verified_replay_claim(job)\n"
        "        return None\n")
    source = _once(
        source,
        "choices=['status','discover','cycle','cleanup','work','execute-job','route','manual-claim']",
        "choices=['status','discover','cycle','cleanup','work','execute-job','route','manual-claim','replay-claim']")
    source = _once(
        source,
        "    if a.mode == 'manual-claim':\n",
        "    if a.mode == 'replay-claim':\n"
        "        if (HOST != 'web' or not a.signed_local_request\n"
        "                or not a.signed_local_request_signature):\n"
        "            raise RuntimeError('replay_requires_web_signed_files')\n"
        "        result = _signed_replay_claim_entry(\n"
        "            a.signed_local_request, a.signed_local_request_signature)\n"
        "        print(json.dumps({'replay_existing_fleet_claim':result},sort_keys=True))\n"
        "        return\n"
        "    if a.mode == 'manual-claim':\n")
    source = _once(
        source,
        "        _dl_names = {\n"
        "            '.github/workflows/ci.yml#check': 'linux-node24-claw-check',",
        "        if _dl_job['ref'] == 'local-manual-replay':\n"
        "            try:\n"
        "                return bool(_verified_replay_claim(dict(_dl_job),start=True))\n"
        "            except Exception:\n"
        "                return False\n"
        "        _dl_names = {\n"
        "            '.github/workflows/ci.yml#check': 'linux-node24-claw-check',")
    source = _once(
        source,
        "            _dl_release = os.environ.get('FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE')",
        "            if (_dl_job and _dl_job['repo'] == _MANUAL_REPO\n"
        "                    and _dl_job['ref'] == 'local-manual-replay'):\n"
        "                _verified_replay_claim(dict(_dl_job),start=True)\n"
        "            _dl_release = os.environ.get('FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE')")
    # Keep the manual-success verifier's command, Docker ID and log checks.
    # The additional ref must never enter the unguarded provider publisher.
    ast.parse(source)
    return {
        "schema": "clawsweeper.source-only-third-replay-controller.v1",
        "state": "prepared_not_installed",
        "installed_sha256": expected_sha256,
        "candidate_sha256": _sha(source.encode()),
        "frozen_hashes": updated,
        "controller": source.encode(),
        "extra_frozen_files": list(REPLAY_LIB),
        "worker_uses_existing_queue": True,
        "new_controller": False,
        "new_service": False,
        "github_dispatch": False,
        "installed": False,
        "admitted": False,
        "executed": False,
    }


REPLAY_HELPERS = r'''
def _verified_replay_proof(job):
    _verified_local_manual_worker()
    if (job['repo'] != _MANUAL_REPO
            or job['ref'] != 'local-manual-replay'
            or job['suite'] != 'linux-node24-claw-replay'):
        raise RuntimeError('replay_wrong_local_only_job')
    program = (
        "import json,sys,pathlib;"
        "sys.path.insert(0,sys.argv[1]);"
        "import direct_local_replay_admission as a;"
        "import direct_local_receiver_integration as v;"
        "r=pathlib.Path(sys.argv[4]);"
        "d=v.read_split_source_release(r);"
        "v.verify_split_source_release(d,enrolled_sha=sys.argv[5]);"
        "p=a.verify_existing_replay(checkout=pathlib.Path(d['execution_checkout']),"
        "fleet_root=pathlib.Path(sys.argv[2]),job_id=sys.argv[3]);"
        "print(json.dumps(p,sort_keys=True))"
    )
    try:
        result=subprocess.run(
            [sys.executable,'-I','-B','-c',program,
             str(_MANUAL_LIB),str(ROOT),job['id'],
             str(ROOT/'secrets'/'clawsweeper-direct-local-release.json'),
             job['sha']], capture_output=True, timeout=70, check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimeError('replay_owner_proof_unavailable') from exc
    if result.returncode or not 0<len(result.stdout)<=8192:
        raise RuntimeError('replay_owner_proof_not_verified')
    try:
        proof=json.loads(result.stdout)
    except (TypeError,ValueError) as exc:
        raise RuntimeError('replay_owner_proof_malformed') from exc
    if (proof.get('schema')!='clawsweeper.existing-fleet-single-replay-claim.v1'
            or proof.get('job_id') != job['id']
            or proof.get('source_sha') != job['sha']
            or proof.get('ref') != job['ref']
            or proof.get('verified_owner_origin') is not True
            or proof.get('provider_status_authorised') is not False
            or proof.get('github_actions_admission_authorised') is not False
            or not isinstance(proof.get('request_sha256'), str)
            or not re.fullmatch('[a-f0-9]{64}',proof['request_sha256'])):
        raise RuntimeError('replay_owner_proof_wrong_job_or_scope')
    return proof


def _verified_replay_claim(job,start=False):
    proof=_verified_replay_proof(job)
    if start and proof.get('queue_state') not in ('queued','claimed','running'):
        raise RuntimeError('replay_worker_not_live_queue_state')
    return proof


def _signed_replay_claim_entry(request_file,signature_file):
    _verified_local_manual_worker()
    program = (
        "import json,sys,pathlib;"
        "sys.path.insert(0,sys.argv[1]);"
        "import direct_local_replay_admission as a;"
        "import direct_local_receiver_integration as v;"
        "r=pathlib.Path(sys.argv[4]);"
        "d=v.read_split_source_release(r);"
        "p=json.loads(a.auth.owner_bytes(pathlib.Path(sys.argv[5]),"
        "262144,private=False));"
        "v.verify_split_source_release(d,"
        "enrolled_sha=p['repositories']['AyobamiH/clawsweeper']['enrolled_head']);"
        "q=a.claim_owner_signed_replay("
        "checkout=pathlib.Path(d['execution_checkout']),"
        "fleet_root=pathlib.Path(sys.argv[6]),"
        "request_file=pathlib.Path(sys.argv[2]),"
        "signature_file=pathlib.Path(sys.argv[3]));"
        "print(json.dumps(q,sort_keys=True))"
    )
    try:
        outcome=subprocess.run([
            sys.executable,'-I','-B','-c',program,
            str(_MANUAL_LIB),str(request_file),str(signature_file),
            str(ROOT/'secrets'/'clawsweeper-direct-local-release.json'),
            str(POLICY),str(ROOT)],capture_output=True,timeout=80,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RuntimeError('replay_admission_unavailable') from exc
    if outcome.returncode or not 0<len(outcome.stdout)<=8192:
        raise RuntimeError('replay_signed_admission_held')
    try:
        claim=json.loads(outcome.stdout)
    except (ValueError,TypeError) as exc:
        raise RuntimeError('replay_signed_admission_malformed') from exc
    items=claim.get('jobs') if isinstance(claim,dict) else None
    if (claim.get('schema')!='clawsweeper.existing-fleet-single-replay-claim.v1'
            or claim.get('ref')!='local-manual-replay'
            or claim.get('job_intents') != ['.github/workflows/release-offline-replay.yml#replay']
            or claim.get('admission') not in ('queued','already_admitted')
            or not isinstance(claim.get('source_sha'),str)
            or not SHA.fullmatch(claim['source_sha'])
            or not isinstance(items,list) or len(items)!=1
            or items[0].get('workflow_job') != '.github/workflows/release-offline-replay.yml#replay'
            or items[0].get('suite') != 'linux-node24-claw-replay'
            or not NAME.fullmatch(items[0].get('job_id',''))
            or not re.fullmatch('[a-f0-9]{64}',items[0].get('policy',''))):
        raise RuntimeError('replay_admission_result_not_exact')
    return claim
'''

REPLAY_PUBLISH = r'''    if job['repo']==_MANUAL_REPO and job['ref']=='local-manual-replay':
        if state not in ('pending','success','failure','error'):
            raise RuntimeError('replay_invalid_local_outcome')
        proof=_verified_replay_claim(job)
        if receipt is None:
            if state!='pending':
                raise RuntimeError('replay_missing_terminal_receipt')
            return None
        if (state=='pending' or receipt.get('outcome')!=state
                or any(receipt.get(k)!=job[k] for k in
                       ('id','repo','sha','suite','ref','policy'))
                or not isinstance(receipt.get('cleanup'),dict)
                or receipt['cleanup'].get('container_absent') is not True):
            raise RuntimeError('replay_unverified_terminal_cleanup')
        if state=='success':
            _verified_manual_success_receipt(job,receipt)
        receipt['origin']='owner-signed-local-manual-replay'
        receipt['provider_status']='suppressed-local-replay'
        receipt['manual_request_sha256']=proof['request_sha256']
        receipt['github_status']=None
        core.atomic(EVIDENCE/(job['id']+'.json'),receipt)
        db.execute("UPDATE jobs SET reported=1 WHERE id=? AND ref=?",
                   (job['id'],'local-manual-replay'))
        db.commit()
        return None
'''
