#!/usr/bin/env python3
"""Build an OFFLINE, byte-pinned r7 -> local-manual controller release candidate.

This generator NEVER installs/replaces the live controller.  It consumes the
existing signed r7 controller and signed candidate Git blobs, staging the same
fleet controller with a strictly local-manual admission and reporting path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

REPO = "AyobamiH/clawsweeper"
R7_SHA256 = "30749cfab0eab608a5a5b23bb06a7510ae277c96fb7accb6689ba64433a73297"
MANUAL_SOURCE_COMMIT = "fd975fcca48e0cd7d175eb095288909feec136ab"
MANUAL_SOURCE_CHECKOUT = "/home/johnh/.local/share/agent-worktrees/clawsweeper/direct-local-event-bridge-20261113"
LIBRARIES = (
    "estate_policy.py",
    "direct_local_event_admission.py",
    "direct_local_workflow.py",
    "direct_local_fleet_claim.py",
    "direct_local_manual_run.py",
    "direct_local_manual_worker.py",
    "direct_local_job_receipts.py",
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError("r7_controller_anchor_moved_or_ambiguous")
    return source.replace(old, new, 1)


def build_controller(r7: bytes, library_hashes: dict[str, str]) -> bytes:
    if digest(r7) != R7_SHA256 or set(library_hashes) != set(LIBRARIES):
        raise RuntimeError("unrecognised_original_r7_or_local_manual_library")
    src = r7.decode("utf-8")
    # Each trust dependency is frozen by SHA-256 in the GENERATED controller;
    # Python's import cache and mutable checkout cannot add extra authority.
    loader = '''
_MANUAL_REPO = "AyobamiH/clawsweeper"
_MANUAL_CHECKOUT = pathlib.Path(%s)
_MANUAL_LIB = ROOT / "clawsweeper-manual-code-v1"
_MANUAL_HASHES = %s
_MANUAL_IMPORTS = ("estate_policy", "direct_local_event_admission",
                   "direct_local_workflow", "direct_local_fleet_claim",
                   "direct_local_manual_run", "direct_local_manual_worker")
_manual_loaded = None


def _verified_local_manual_worker():
    """Only the frozen, owner-owned modules can establish manual provenance."""
    global _manual_loaded
    import importlib
    import stat
    if (_MANUAL_LIB.is_symlink() or not _MANUAL_LIB.is_dir()
            or _MANUAL_LIB.stat().st_uid != os.getuid()
            or _MANUAL_LIB.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError("manual_frozen_library_missing_or_untrusted")
    for filename, expected in _MANUAL_HASHES.items():
        path = _MANUAL_LIB / filename
        if (path.is_symlink() or not path.is_file()
                or path.stat().st_uid != os.getuid()
                or path.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise RuntimeError("manual_frozen_library_drift")
    return True


def _manual_proof_subprocess(job, start=False):
    """Isolate frozen imports from the r7 process's older import cache."""
    _verified_local_manual_worker()
    if job["repo"] != _MANUAL_REPO or job["ref"] != "local-manual":
        raise RuntimeError("not_a_local_manual_job")
    # -I: no environment/user path imports; imports originate in hashed lib.
    # No shell, GitHub Actions API, status POST, queue mutation or runner start.
    program = (
        "import sys,json,pathlib;"
        "sys.path.insert(0,sys.argv[1]);"
        "import direct_local_manual_worker as w;"
        "p=w.verify_manual_worker_start("
        "checkout=pathlib.Path(sys.argv[4]),fleet_root=pathlib.Path(sys.argv[2]),"
        "job_id=sys.argv[3]) if sys.argv[5]=='start' "
        "else w.verify_manual_queue_provenance("
        "fleet_root=pathlib.Path(sys.argv[2]),job_id=sys.argv[3]);"
        "print(json.dumps(p,sort_keys=True))"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", program,
             str(_MANUAL_LIB), str(ROOT), job["id"],
             str(_MANUAL_CHECKOUT), "start" if start else "claim"],
            capture_output=True, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("manual_exact_source_or_owner_verifier_unavailable") from exc
    if result.returncode != 0 or len(result.stdout) > 8192:
        # Never expose subprocess stderr, provider errors or credential data.
        raise RuntimeError("manual_exact_source_or_owner_verification_held")
    try:
        proof = json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("manual_owner_proof_malformed") from exc
    if (not isinstance(proof, dict)
            or proof.get("verified_owner_origin") is not True
            or proof.get("provider_status_authorised") is not False
            or proof.get("github_actions_admission_authorised") is not False
            or proof.get("job_id") != job["id"]
            or proof.get("ref") != "local-manual"
            or proof.get("source_sha") != job["sha"]
            or not isinstance(proof.get("request_sha256"), str)
            or not re.fullmatch("[0-9a-f]{64}", proof["request_sha256"])):
        raise RuntimeError("manual_claim_and_job_identity_drift")
    if start and (proof.get("live_develop_verified") is not True
                  or proof.get("exact_clean_source_verified") is not True):
        raise RuntimeError("manual_worker_start_not_source_verified")
    return proof


def _verified_manual_success_receipt(job, receipt):
    # A local-only success must not become reported=1 before the actual
    # command list and log are checked. The separate read-only verifier
    # remains the operational acceptance authority.
    import stat
    if (receipt.get("mode") != "local-scheduler-not-github-actions"
            or receipt.get("controller_sha256") != CONTROLLER_SHA
            or type(receipt.get("attempt")) is not int
            or receipt["attempt"] < 1
            or not isinstance(receipt.get("started_at"), str)
            or not isinstance(receipt.get("finished_at"), str)
            or receipt.get("cleanup_error") is not None
            or receipt.get("container_state", {}).get("OOMKilled") is True):
        raise RuntimeError("manual_success_execution_metadata_incomplete")
    policy = load_policy()
    if policy_hash(policy, job["repo"], job["suite"]) != job["policy"]:
        raise RuntimeError("manual_success_execution_policy_moved")
    cfg = policy["repositories"][job["repo"]]["suites"][job["suite"]]
    required = [("Exact commit checkout", None)] + [
        (step["name"], step["command"]) for step in cfg["steps"]]
    steps = receipt.get("steps")
    if not isinstance(steps, list) or len(steps) != len(required):
        raise RuntimeError("manual_success_missing_command_receipts")
    for step, (name, command) in zip(steps, required):
        if (not isinstance(step, dict) or step.get("name") != name
                or type(step.get("exit_code")) is not int
                or step["exit_code"] != 0
                or not isinstance(step.get("started_at"), str)
                or not isinstance(step.get("finished_at"), str)
                or not isinstance(step.get("command"), str)
                or (command is not None and step["command"] != command)):
            raise RuntimeError("manual_success_failed_or_relabelled_command")
    initial = steps[0]["command"]
    if (not initial.startswith("git init -q; ")
            or "git checkout --quiet --detach FETCH_HEAD" not in initial
            or "git rev-parse HEAD" not in initial
            or "GITHUB_SHA" not in initial
            or "https://github.com/" + job["repo"] + ".git" not in initial):
        raise RuntimeError("manual_success_source_checkout_unverified")
    path = LOGS / (job["id"] + ".log")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("manual_success_log_missing_or_untrusted")
    info = path.stat()
    if (info.st_uid != os.getuid()
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < info.st_size <= 16777216
            or receipt.get("log_bytes") != info.st_size
            or hashlib.sha256(path.read_bytes()).hexdigest()
               != receipt.get("log_sha256")):
        raise RuntimeError("manual_success_log_integrity_mismatch")
    return True


def _verified_manual_claim(job):
    return _manual_proof_subprocess(job)


def _verified_manual_start(job):
    return _manual_proof_subprocess(job, start=True)


def _signed_manual_claim_entry(request_file, signature_file):
    """The existing controller's sole owner-signed manual queue entry point."""
    _verified_local_manual_worker()
    program = (
        "import sys,json,pathlib;"
        "sys.path.insert(0,sys.argv[1]);"
        "import direct_local_manual_run as m;"
        "p=m.claim_owner_signed_manual_run("
        "checkout=pathlib.Path(sys.argv[2]),"
        "fleet_root=pathlib.Path(sys.argv[3]),"
        "request_file=pathlib.Path(sys.argv[4]),"
        "signature_file=pathlib.Path(sys.argv[5]),"
        "allowed_signers_file=pathlib.Path(sys.argv[6]));"
        "print(json.dumps(p,sort_keys=True))"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", program,
             str(_MANUAL_LIB), str(_MANUAL_CHECKOUT), str(ROOT),
             str(request_file), str(signature_file),
             str(pathlib.Path.home() / ".config/git/allowed_signers")],
            capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("owner_signed_manual_claim_unavailable") from exc
    if result.returncode != 0 or len(result.stdout) > 8192:
        raise RuntimeError("owner_signed_manual_claim_held")
    try:
        claim = json.loads(result.stdout)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("owner_signed_manual_claim_malformed") from exc
    if (not isinstance(claim, dict)
            or claim.get("schema") != "clawsweeper.existing-fleet-local-manual-claim.v1"
            or claim.get("source_ref") != "local-manual"
            or claim.get("suite") != "linux-node24"
            or claim.get("admission") not in ("queued", "already_admitted")
            or not isinstance(claim.get("source_sha"), str)
            or not re.fullmatch("[0-9a-f]{40}", claim["source_sha"])
            or not isinstance(claim.get("existing_fleet_job_id"), str)
            or not NAME.fullmatch(claim["existing_fleet_job_id"])
            or claim.get("job_intents") != [
                ".github/workflows/ci.yml#check",
                ".github/workflows/ci.yml#sparse-repair-builds"
            ]):
        raise RuntimeError("owner_signed_manual_claim_result_not_trusted")
    return claim


''' % (repr(MANUAL_SOURCE_CHECKOUT), repr(dict(sorted(library_hashes.items()))))
    src = replace_once(src, "def setup():\n", loader + "def setup():\n")
    src = replace_once(src, "def current_reference(job,policy=None):\n",
                       'def current_reference(job,policy=None):\n'
                       '    if job["repo"] == _MANUAL_REPO and job["ref"] == "local-manual":\n'
                       '        _verified_manual_start(job)  # transient GET failures HOLD; never cancel source\n'
                       '        return True\n')
    src = replace_once(src, "def publish(db,job,state,description,receipt=None):\n",
                       '''def publish(db,job,state,description,receipt=None):
    if job["repo"] == _MANUAL_REPO and job["ref"] == "local-manual":
        # Neither pending nor final reporting is allowed to touch GitHub.
        if state not in ("pending", "success", "failure", "error"):
            raise RuntimeError("unrecognised_local_manual_report_state")
        proof = _verified_manual_claim(job)
        if receipt is None:
            if state != "pending":
                raise RuntimeError("manual_final_report_missing_receipt")
            return None
        if (state == "pending" or receipt.get("outcome") != state
                or any(receipt.get(k) != job[k] for k in
                       ("id", "repo", "sha", "suite", "ref", "policy"))
                or not isinstance(receipt.get("cleanup"), dict)
                or receipt["cleanup"].get("container_absent") is not True):
            raise RuntimeError("manual_final_receipt_requires_exact_cleaned_execution")
        if state == "success":
            _verified_manual_success_receipt(job, receipt)
        receipt["origin"] = "owner-signed-local-manual"
        receipt["provider_status"] = "suppressed-local-manual"
        receipt["manual_request_sha256"] = proof["request_sha256"]
        receipt["github_status"] = None
        core.atomic(EVIDENCE / (job["id"] + ".json"), receipt)
        db.execute("UPDATE jobs SET reported=1 WHERE id=? AND ref=?",
                   (job["id"], "local-manual"))
        db.commit()
        return None
''')
    src = replace_once(src, "def publish_pending(db,job,description):\n",
                       '''def publish_pending(db,job,description):
    if job["repo"] == _MANUAL_REPO and job["ref"] == "local-manual":
        _verified_manual_claim(job)
        return None
''')
    # The owner-controlled existing dispatcher holds control.lock when this
    # executes, and the detached child independently performs the same check.
    src = replace_once(src,
        "        _dl_job = db.execute('SELECT repo FROM jobs WHERE id=?',\n",
        "        _dl_job = db.execute('SELECT id,repo,ref,sha,suite,state,policy FROM jobs WHERE id=?',\n")
    src = replace_once(src,
        "        if _dl_job['repo'] != 'AyobamiH/clawsweeper':\n            return True\n",
        '''        if _dl_job['repo'] != 'AyobamiH/clawsweeper':
            return True
        if _dl_job["ref"] == "local-manual":
            try:
                _verified_manual_claim(_dl_job)
                return True
            except Exception:
                return False
''')
    src = replace_once(src,
        "            if not _dl_authenticated_existing_job(a.job_id or ''):\n",
        '''            if _dl_job["ref"] == "local-manual":
                # No provider or container effect before revalidating the exact
                # owner-signed local source in the detached worker.
                _verified_manual_start(_dl_job)
            if not _dl_authenticated_existing_job(a.job_id or ''):
''')
    src = replace_once(src,
        "    p.add_argument('mode',choices=['status','discover','cycle','cleanup','work','execute-job','route'])\n",
        "    p.add_argument('mode',choices=['status','discover','cycle','cleanup','work','execute-job','route','manual-claim'])\n")
    src = replace_once(src,
        "    a=p.parse_args()\n    policy=load_policy()\n",
        """    p.add_argument('--signed-local-request')
    p.add_argument('--signed-local-request-signature')
    a=p.parse_args()
    policy=load_policy()
    if a.mode == 'manual-claim':
        if (HOST != 'web' or not a.signed_local_request
                or not a.signed_local_request_signature):
            raise RuntimeError('local_manual_requires_exact_web_owner_signed_files')
        receipt = _signed_manual_claim_entry(
            a.signed_local_request, a.signed_local_request_signature)
        print(json.dumps({'manual_existing_fleet_claim': receipt}, sort_keys=True))
        return
""")
    src = replace_once(src,
        "                _dl_hold = False\n",
        '''                # Source-bound adapter is mandatory for this release.
                # A missing/mutated manual library holds ClawSweeper alone.
                _verified_local_manual_worker()
                _dl_hold = False
''')
    result = src.encode("utf-8")
    compile(result, "candidate-fleet_ci.py", "exec")
    return result


def signed_git_files(repo: Path) -> dict[str, bytes]:
    data = {}
    for filename in LIBRARIES:
        name = "scripts/ci/" + filename
        result = subprocess.run(
            ["git", "-C", str(repo), "show", MANUAL_SOURCE_COMMIT + ":" + name],
            capture_output=True, check=False, timeout=10)
        if result.returncode or not result.stdout:
            raise RuntimeError("signed_candidate_library_missing")
        data[filename] = result.stdout
    return data


def _exclusive_file(path: Path, content: bytes) -> None:
    if path.is_symlink() or path.exists():
        raise RuntimeError("refuse_overwrite_existing_release_candidate")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())


def stage(*, base: Path, repo: Path, destination: Path) -> dict:
    # Installation is a SEPARATE owner decision. Never stage inside the live
    # fleet/controller/source directory or replace an existing artefact.
    evidence = Path.home() / ".local/share/local-ci/evidence/clawsweeper-direct-local-20261113"
    if (destination.is_symlink() or destination.exists()
            or not destination.absolute().is_relative_to(evidence)
            or base.resolve() != (Path.home() / ".local/share/local-ci/fleet_ci.py").resolve()):
        raise RuntimeError("release_stage_must_be_new_private_evidence_directory")
    if (not repo.is_dir() or repo.is_symlink()
            or repo.stat().st_uid != os.getuid()):
        raise RuntimeError("untrusted_manual_source_repository")
    signed = subprocess.run(["git", "-C", str(repo), "verify-commit", MANUAL_SOURCE_COMMIT],
                            capture_output=True, timeout=10)
    if signed.returncode:
        raise RuntimeError("local_manual_signed_source_not_verified")
    frozen = signed_git_files(repo)
    hashes = {name: digest(raw) for name, raw in frozen.items()}
    candidate = build_controller(base.read_bytes(), hashes)
    destination.mkdir(mode=0o700)
    lib = destination / "clawsweeper-manual-code-v1"
    lib.mkdir(mode=0o700)
    for name, raw in frozen.items():
        _exclusive_file(lib / name, raw)
    _exclusive_file(destination / "fleet_ci.py", candidate)
    manifest = {
        "schema": "clawsweeper.r8-local-manual-controller-candidate.v1",
        "production_installed": False,
        "installed_r7_unchanged": True,
        "reviewed_original_controller_sha256": R7_SHA256,
        "replacement_controller_sha256": digest(candidate),
        "library_source_signed_commit": MANUAL_SOURCE_COMMIT,
        "ordinary_source_commit": "944fd5ad04ba5c01d73b8c3059313469aad3357f",
        "library_file_sha256": hashes,
        "canonical_fleet_root": str(Path.home() / ".local/share/local-ci"),
        "rollback": "restore the byte-verified r7 controller and remove only the newly installed manual sidecar directory after exclusive control",
        "github_actions_dispatched": False,
        "production_effects": False,
    }
    _exclusive_file(destination / "CANDIDATE_MANIFEST.json",
                    (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    args = parser.parse_args()
    doc = stage(base=args.base, repo=args.repo, destination=args.stage)
    print(json.dumps({"staged": str(args.stage), "replacement_controller_sha256":
                      doc["replacement_controller_sha256"], "installed": False},
                     sort_keys=True))


if __name__ == "__main__":
    main()
