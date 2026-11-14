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
    if a.mode in ('discover', 'cycle') and HOST == 'web':
        _dl_release = os.environ.get('FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE')
        if _dl_release:
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
'''
    output = current.replace(ANCHOR, hook.encode("utf-8") + ANCHOR, 1)
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
