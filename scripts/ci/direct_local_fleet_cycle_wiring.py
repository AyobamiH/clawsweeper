#!/usr/bin/env python3
"""Render a proposed exact-source pre-lock hook into the EXISTING fleet cycle.

No filesystem writes, runner, queue, provider effects, or installation. The
owner must approve a new frozen fleet release before using rendered code.
"""
from __future__ import annotations
import ast
import hashlib
import json
import re

SHA256 = re.compile(r"[a-f0-9]{64}\Z")
ANCHOR = b"    with core.lock():\n"
SCHEMA = "clawsweeper.exact-local-fleet-cycle-wiring.v1"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compile_prelock_source(current: bytes, *, expected_sha256: str,
                           ingress_adapter: bytes, release_verifier: bytes) -> dict:
    """Produce deterministic in-memory replacement; fail closed on drift."""
    if (not isinstance(current, bytes) or not isinstance(expected_sha256, str)
            or not SHA256.fullmatch(expected_sha256)
            or sha(current) != expected_sha256):
        raise RuntimeError("fleet_controller_exact_source_mismatch")
    if not isinstance(ingress_adapter, bytes) or not isinstance(release_verifier, bytes):
        raise RuntimeError("invalid_ingress_source_type")
    try:
        ast.parse(current.decode("utf-8"))
        ast.parse(ingress_adapter.decode("utf-8"))
        ast.parse(release_verifier.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise RuntimeError("non_python_fleet_or_ingress_source") from exc
    if (not ingress_adapter or not release_verifier
            or current.count(ANCHOR) != 1
            or current.count(b"    if a.mode=='execute-job':\n") != 1
            or not (current.rfind(b"    db=setup()\n", 0, current.index(ANCHOR)) >
                    current.index(b"def main():") and
                    current.rfind(b"    db=setup()\n", 0, current.index(ANCHOR)) <
                    current.index(b"    if a.mode=='execute-job':\n") <
                    current.index(ANCHOR))
            or b"if a.mode in ('discover','cycle'):" not in current
            or b"if a.mode in ('work','cycle'):" not in current
            or b"FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE" in current):
        raise RuntimeError("unrecognised_canonical_fleet_cycle_shape")
    ingress_hash, release_hash = sha(ingress_adapter), sha(release_verifier)
    hook = f'''    # Signed ClawSweeper pre-lock ingestion on the EXISTING local fleet.
    # The newly installed controller must never fall back to old ClawSweeper
    # admission merely because a release environment variable is missing.
    # No other repository changes its authorised route.
    _dl_hold = a.mode in ('discover', 'cycle', 'work')
    if a.mode in ('discover', 'cycle', 'work') and HOST == 'web':
        _dl_release = os.environ.get('FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE')
        if _dl_release:
            try:
                import stat as _dl_stat
                import types as _dl_types
                _dl_bound = ROOT / 'secrets' / 'clawsweeper-direct-local-release.json'
                if pathlib.Path(_dl_release) != _dl_bound:
                    raise RuntimeError('unrecognised_direct_local_release_path')
                _dl_files = (
                    (ROOT / 'direct_local_ingress_reconcile.py', '{ingress_hash}'),
                    (ROOT / 'direct_local_receiver_integration.py', '{release_hash}'),
                )
                _dl_bytes = {{}}
                for _dl_file, _dl_expected in _dl_files:
                    if (_dl_file.is_symlink() or not _dl_file.is_file()
                            or _dl_file.stat().st_uid != os.getuid()
                            or _dl_file.stat().st_mode & (_dl_stat.S_IWGRP | _dl_stat.S_IWOTH)):
                        raise RuntimeError('unsafe_installed_direct_local_module')
                    _dl_data = _dl_file.read_bytes()
                    if hashlib.sha256(_dl_data).hexdigest() != _dl_expected:
                        raise RuntimeError('installed_direct_local_module_drift')
                    _dl_bytes[_dl_file.name] = _dl_data
                # The owner release, the installed candidate and the fleet
                # suite's source pin must refer to the SAME immutable tree.
                # Without this check a zero-event cycle could run old ClawSweeper
                # jobs even though the new release source was never enrolled.
                _dl_verifier_entry = ROOT / 'direct_local_receiver_integration.py'
                _dl_verifier = _dl_types.ModuleType('verified_clawsweeper_release_pin')
                _dl_verifier.__file__ = str(_dl_verifier_entry)
                exec(compile(_dl_bytes[_dl_verifier_entry.name],
                             str(_dl_verifier_entry), 'exec'),
                     _dl_verifier.__dict__)
                _dl_doc = _dl_verifier.read_release(_dl_bound)
                _dl_verifier.verify_release(_dl_doc)
                _dl_cfg = policy['repositories'].get('AyobamiH/clawsweeper')
                if (not isinstance(_dl_cfg, dict)
                        or _dl_cfg.get('enrolled_head') != _dl_doc.get('commit')):
                    raise RuntimeError('clawsweeper_existing_fleet_policy_pin_mismatch')
                _dl_entry = ROOT / 'direct_local_ingress_reconcile.py'
                _dl_module = _dl_types.ModuleType('verified_clawsweeper_local_ingress')
                _dl_module.__file__ = str(_dl_entry)
                exec(compile(_dl_bytes[_dl_entry.name], str(_dl_entry), 'exec'),
                     _dl_module.__dict__)
                _dl_receipt = _dl_module.reconcile_existing_fleet_ingress(
                    ledger_dir=ROOT / 'webhook-deliveries',
                    release_file=_dl_bound,
                    secret_file=ROOT / 'secrets' / 'webhook-hmac')
                print(json.dumps({{'clawsweeper_direct_local_prelock': _dl_receipt}},
                                 sort_keys=True), flush=True)
                _dl_hold = False
            except Exception as _dl_error:
                # Invalid ClawSweeper release must not starve other repositories.
                # Never log provider errors, secrets or signed event payloads.
                _dl_hold = True
                print(json.dumps({{'clawsweeper_direct_local_hold': {{
                    'class': 'release_or_ingress_unverified',
                    'error_type': type(_dl_error).__name__
                }}}}, sort_keys=True), flush=True)
    _dl_exec_policy = policy
    if _dl_hold:
        # Filter only this cycle's view; never mutate installed fleet policy.
        _dl_exec_policy = dict(policy)
        _dl_exec_policy['repositories'] = {{
            _dl_repo: _dl_cfg for _dl_repo, _dl_cfg in policy['repositories'].items()
            if _dl_repo != 'AyobamiH/clawsweeper'
        }}
'''
    # All supported execution modes exclude ClawSweeper when its exact-source
    # release is invalid; unrelated repositories retain their original policy.
    substitutions = (
        (b"discover(db,policy,not a.main_only,a.repo)",
         b"discover(db,_dl_exec_policy,not a.main_only,a.repo)"),
        (b"detached.dispatch(db,policy,a.max_jobs)",
         b"detached.dispatch(db,_dl_exec_policy,a.max_jobs)"),
        (b"def parallel_work(db,policy,max_jobs):",
         b"def parallel_work(db,policy,max_jobs,blocked_repo=None):"),
        (b"parallel_work(db,policy,a.max_jobs)",
         b"parallel_work(db,_dl_exec_policy,a.max_jobs,\n"
         b"                              'AyobamiH/clawsweeper' if _dl_hold else None)"),
        (b"row=db.execute(\"SELECT * FROM jobs WHERE state='queued' AND ready_at<=? "
         b"ORDER BY CASE ref WHEN 'main' THEN 0 ELSE 1 END,created_at,id LIMIT 1\",(time.time(),)).fetchone()",
         b"row=db.execute(\"SELECT * FROM jobs WHERE state='queued' AND ready_at<=? \"\n"
         b"                                   + (\"AND repo!=? \" if _dl_hold else \"\")\n"
         b"                                   + \"ORDER BY CASE ref WHEN 'main' THEN 0 ELSE 1 END,created_at,id LIMIT 1\",\n"
         b"                                   (time.time(),'AyobamiH/clawsweeper') if _dl_hold else (time.time(),)).fetchone()"),
        (b"rows=[dict(r) for r in db.execute(\n"
         b"        \"SELECT * FROM jobs WHERE state='queued' AND ready_at<=? \"\n"
         b"        \"ORDER BY CASE ref WHEN 'main' THEN 0 ELSE 1 END,created_at,id LIMIT 100\",\n"
         b"        (time.time(),)).fetchall()]",
         b"rows=[dict(r) for r in db.execute(\n"
         b"        \"SELECT * FROM jobs WHERE state='queued' AND ready_at<=? \"\n"
         b"        + (\"AND repo!=? \" if blocked_repo else \"\")\n"
         b"        + \"ORDER BY CASE ref WHEN 'main' THEN 0 ELSE 1 END,created_at,id LIMIT 100\",\n"
         b"        (time.time(),blocked_repo) if blocked_repo else (time.time(),)).fetchall()]"),
    )
    output = current.replace(ANCHOR, hook.encode("utf-8") + ANCHOR, 1)
    for before, after in substitutions:
        if current.count(before) != 1:
            raise RuntimeError("unrecognised_local_fleet_repository_isolation_shape")
        output = output.replace(before, after, 1)
    # Detached workers are separate processes: revalidate the signed release
    # for ClawSweeper before execution; leave other repositories untouched.
    worker_before = (
        b"    if a.mode=='execute-job':\n"
        b"        result=detached.execute(db,policy,a.job_id or '',a.claim_token or '')"
    )
    worker_guard = f'''    if a.mode=='execute-job':
        _dl_job = db.execute('SELECT repo FROM jobs WHERE id=?',
                             (a.job_id or '',)).fetchone()
        if _dl_job and _dl_job['repo'] == 'AyobamiH/clawsweeper':
            # systemd-run workers are separate processes. Their environment
            # does not reliably inherit the timer's release variable. Always
            # validate the owner-bound release at its fixed private path.
            _dl_release = os.environ.get('FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE')
            import stat as _dl_stat
            import types as _dl_types
            _dl_bound = ROOT / 'secrets' / 'clawsweeper-direct-local-release.json'
            if _dl_release is not None and pathlib.Path(_dl_release) != _dl_bound:
                raise RuntimeError('clawsweeper_worker_release_path_unverified')
            _dl_file = ROOT / 'direct_local_receiver_integration.py'
            if (_dl_file.is_symlink() or not _dl_file.is_file()
                    or _dl_file.stat().st_uid != os.getuid()
                    or _dl_file.stat().st_mode & (_dl_stat.S_IWGRP | _dl_stat.S_IWOTH)):
                raise RuntimeError('clawsweeper_worker_release_verifier_untrusted')
            _dl_data = _dl_file.read_bytes()
            if hashlib.sha256(_dl_data).hexdigest() != '{release_hash}':
                raise RuntimeError('clawsweeper_worker_release_verifier_changed')
            _dl_mod = _dl_types.ModuleType('clawsweeper_worker_release_verifier')
            _dl_mod.__file__ = str(_dl_file)
            exec(compile(_dl_data, str(_dl_file), 'exec'), _dl_mod.__dict__)
            _dl_doc = _dl_mod.read_release(_dl_bound)
            _dl_mod.verify_release(_dl_doc)
            _dl_cfg = policy['repositories'].get('AyobamiH/clawsweeper')
            if (not isinstance(_dl_cfg, dict)
                    or _dl_cfg.get('enrolled_head') != _dl_doc.get('commit')):
                raise RuntimeError('clawsweeper_worker_source_policy_pin_mismatch')
        result=detached.execute(db,policy,a.job_id or '',a.claim_token or '')'''
    if current.count(worker_before) != 1:
        raise RuntimeError("unrecognised_local_fleet_worker_isolation_shape")
    output = output.replace(worker_before, worker_guard.encode("utf-8"), 1)
    try:
        ast.parse(output.decode("utf-8"))
    except SyntaxError as exc:
        raise RuntimeError("generated_fleet_cycle_invalid_python") from exc
    return {
        "schema": SCHEMA, "state": "source_only_not_installed",
        "current_sha256": expected_sha256, "proposed_sha256": sha(output),
        "ingress_sha256": ingress_hash, "verifier_sha256": release_hash,
        "content": output
    }


def non_secret_receipt(result: dict) -> str:
    if result.get("schema") != SCHEMA:
        raise RuntimeError("invalid_direct_local_patch_receipt")
    return json.dumps({k: v for k, v in result.items() if k != "content"},
                      sort_keys=True)
