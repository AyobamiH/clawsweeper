#!/usr/bin/env python3
"""Read-only integrity gate for the owner-authorised 2 GiB host-reserve release."""
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

SCHEMA = 'clawsweeper.capacity-policy-integrity.v1'
RELEASE = '2026.11.18-clawsweeper-capacity-2g'
RELEASES = Path('/home/johnh/.local/opt/local-ci-fleet/releases')
PARENT = RELEASES / '2026.11.18-v3-clawsweeper-split-compatibility'
V3 = RELEASES / '2026.11.17-v3-clawsweeper-split-manual'
PARENT_HASH = '29222443435f8d3c8b12402cb4f0b1cc08855720b7a8aea65fbb9b37132761cc'
V3_HASH = '0d438309dce0c9611bb425d14384bc1819b02cc1884a7e19d8fa7cacce3cda2d'
RUNTIME = Path('/home/johnh/.local/share/local-ci')
FLEET_UNIT = Path('/home/johnh/.config/systemd/user/local-ci-fleet.service.d/20-direct-local.conf')
WEBHOOK_UNIT = Path('/home/johnh/.config/systemd/user/local-ci-webhook.service.d/20-direct-local.conf')
SIGNERS = Path('/home/johnh/.config/git/allowed_signers')
CONTROL = 'control/direct_local_capacity_integrity.py'
SIGNER = 'heryourbarme@live.com'
NAMESPACE = 'clawsweeper-local-fleet-release'
CHANGED = frozenset(('fleet_ci.py', 'local_ci.py', 'fleet_detached.py', 'config.json'))
CAPACITY = {'physical_disk_reserve_GiB': 2, 'minimum_admission_free_GiB': 4,
            'max_parallel_jobs': 1, 'execution_mode': 'detached'}
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result

def regular(path, limit=1024*1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o022 or not 0 < before.st_size <= limit):
            raise ValueError('unsafe_file:' + path.name)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        if (len(raw) != before.st_size or
                (before.st_size, before.st_mtime_ns, before.st_ino) !=
                (after.st_size, after.st_mtime_ns, after.st_ino)):
            raise ValueError('changed_during_read:' + path.name)
        return raw
    finally:
        os.close(fd)

def digest_file(path, expected):
    if not isinstance(expected, str) or not HASH.fullmatch(expected):
        raise ValueError('invalid_expected_hash')
    raw = regular(path)
    if sha(raw) != expected:
        raise ValueError('digest_mismatch:' + Path(path).name)
    return raw

def directory(path):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        raise ValueError('unsafe_directory:' + path.name)
    return path

def relative_file(root, rel):
    if (not isinstance(rel, str) or not rel or rel.startswith('/') or '\\' in rel
            or any(part in ('', '.', '..') for part in rel.split('/'))):
        raise ValueError('unsafe_inventory_path')
    current = directory(root)
    for part in rel.split('/')[:-1]:
        current = directory(current / part)
    return current / rel.split('/')[-1]

def checked_map(root, mapping):
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError('invalid_inventory')
    for rel, expected in mapping.items():
        digest_file(relative_file(root, rel), expected)
    return len(mapping)

def exact_files(root, expected):
    directory(root)
    actual = set()
    for p in root.rglob('*'):
        if p.is_symlink():
            raise ValueError('symlinked_release_entry')
        if p.is_dir():
            directory(p)
        elif p.is_file():
            actual.add(str(p.relative_to(root)))
        else:
            raise ValueError('special_release_entry')
    if actual != set(expected):
        raise ValueError('unexpected_release_entries:' + root.name)

def signed(path, signers):
    raw = regular(path)
    signature = Path(str(path) + '.sig')
    regular(signature, 4096)
    regular(signers, 8192)
    result = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(signers),
        '-I', SIGNER, '-n', NAMESPACE, '-s', str(signature)], input=raw,
        capture_output=True, check=False, timeout=15,
        env={'PATH':'/usr/bin:/bin', 'LC_ALL':'C', 'HOME':'/home/johnh'})
    if result.returncode:
        raise ValueError('invalid_owner_signature:' + Path(path).name)
    return raw

def manifest_at(root, expected, signers):
    path = directory(root) / 'RELEASE_MANIFEST.json'
    raw = digest_file(path, expected)
    if signed(path, signers) != raw:
        raise ValueError('manifest_changed_during_verification')
    return json.loads(raw, object_pairs_hook=unique)

def ancestors(signers):
    """Validate retained signed releases without executing either old verifier."""
    old = manifest_at(V3, V3_HASH, signers)
    parent = manifest_at(PARENT, PARENT_HASH, signers)
    if (old['release'] != V3.name or parent['release'] != PARENT.name
            or parent['parent_manifest_sha256'] != V3_HASH
            or len(old['source_files']) != 11 or len(old['rollback_files']) != 11
            or len(parent['rollback_current_v3']) != 13
            or parent['rollback_r8p3'] != old['rollback_files']):
        raise ValueError('unexpected_predecessor_identity')
    for root, doc, control in ((V3, old, 'control/v3_integrity.py'),
                               (PARENT, parent, 'control/direct_local_v3_successor_integrity.py')):
        digest_file(relative_file(root, control), doc['control_sha256'])
        signed(root / control, signers)
        checked_map(root/'frozen', doc['source_files'])
        exact_files(root/'frozen/manual', {key.removeprefix('manual/')
                    for key in doc['source_files'] if key.startswith('manual/')})
    checked_map(V3/'rollback-r8p3', old['rollback_files'])
    checked_map(PARENT/'rollback-r8p3', parent['rollback_r8p3'])
    checked_map(PARENT/'rollback-current-v3', parent['rollback_current_v3'])
    checked_map(PARENT/'unit', {label+'-20-direct-local.conf.candidate': digest
                              for label, digest in parent['unit_candidate_sha256'].items()})
    return old, parent

def current_inventory(old, parent):
    inventory = dict(old['original_runtime'])
    for name, digest in parent['source_files'].items():
        if name == 'controller/fleet_ci.py': destination = 'fleet_ci.py'
        elif name == 'policy/fleet-policy.json': destination = 'fleet-policy.json'
        elif name == 'descriptor/clawsweeper-direct-local-release.json':
            destination = 'secrets/clawsweeper-direct-local-release.json'
        elif name.startswith('manual/'):
            destination = 'clawsweeper-manual-code-v3/' + name.removeprefix('manual/')
        else: raise ValueError('unexpected_predecessor_source_path')
        inventory[destination] = digest
    if not CHANGED <= inventory.keys():
        raise ValueError('missing_predecessor_capacity_files')
    return inventory

def unit_bytes(source_head):
    if not COMMIT.fullmatch(source_head):
        raise ValueError('invalid_source_head')
    release = RELEASES / RELEASE
    command = (f'/usr/bin/python3 -I {release}/{CONTROL} installed --stage {release} '
               f'--runtime {RUNTIME} --fleet-unit {FLEET_UNIT} --webhook-unit {WEBHOOK_UNIT} '
               f'--signers {SIGNERS} --source-head {source_head}')
    value = (f'[Service]\nExecStartPre=\nExecStartPre={command}\n'
             f'Environment=FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE='
             f'{RUNTIME}/secrets/clawsweeper-direct-local-release.json\n').encode()
    return {'fleet':value, 'webhook':value}

def _manifest_values(stage, source_head, old, parent):
    stage = directory(Path(stage))
    original = current_inventory(old, parent)
    candidates = {name:sha(regular(relative_file(stage/'frozen', name))) for name in sorted(CHANGED)}
    units = unit_bytes(source_head)
    return {'schema':SCHEMA, 'release':RELEASE, 'host':'web', 'owner_uid':old['owner_uid'],
        'source_repository':'AyobamiH/clawsweeper', 'source_head':source_head,
        'parent_manifest_sha256':PARENT_HASH, 'v3_manifest_sha256':V3_HASH,
        'capacity':dict(CAPACITY), 'changed_runtime':candidates,
        'rollback_runtime':{name:original[name] for name in sorted(CHANGED)},
        'rollback_units':dict(parent['unit_candidate_sha256']),
        'unit_candidate_sha256':{key:sha(value) for key,value in units.items()},
        'control_sha256':sha(regular(relative_file(stage, CONTROL))),
        'github_actions_dispatched':False, 'production_installed_at_signing':False}

def build_manifest(stage, source_head, *, signers=SIGNERS):
    """Read/build helper: caller supplies frozen4, rollback6, control and units."""
    old, parent = ancestors(Path(signers))
    return _manifest_values(stage, source_head, old, parent)

def verify(mode, stage, runtime, fleet_unit, webhook_unit, signers, source_head):
    if mode not in ('staged','installed') or not COMMIT.fullmatch(source_head):
        raise ValueError('invalid_mode_or_source_head')
    stage, runtime = directory(Path(stage)), directory(Path(runtime))
    old, parent = ancestors(Path(signers))
    raw = signed(stage/'RELEASE_MANIFEST.json', signers)
    doc = json.loads(raw, object_pairs_hook=unique)
    expected = _manifest_values(stage, source_head, old, parent)
    # JSON comparison also distinguishes booleans/floats from authorised integer limits.
    if (json.dumps(doc, sort_keys=True) != json.dumps(expected, sort_keys=True)
            or doc['owner_uid'] != os.getuid() or socket.gethostname() != 'web'):
        raise ValueError('capacity_manifest_scope_or_identity_mismatch')
    digest_file(relative_file(stage, CONTROL), doc['control_sha256'])
    signed(stage/CONTROL, signers)
    exact_files(stage/'frozen', CHANGED)
    checked_map(stage/'frozen', doc['changed_runtime'])
    exact_files(stage/'rollback/runtime', CHANGED)
    checked_map(stage/'rollback/runtime', doc['rollback_runtime'])
    rollback_units = {key+'-20-direct-local.conf':value for key,value in doc['rollback_units'].items()}
    exact_files(stage/'rollback/unit', rollback_units)
    checked_map(stage/'rollback/unit', rollback_units)
    units = unit_bytes(source_head)
    expected_unit_files = {label+'-20-direct-local.conf.candidate':sha(value) for label,value in units.items()}
    exact_files(stage/'unit', expected_unit_files)
    checked_map(stage/'unit', expected_unit_files)
    original_config = json.loads(regular(stage/'rollback/runtime/config.json'), object_pairs_hook=unique)
    new_config = json.loads(regular(stage/'frozen/config.json'), object_pairs_hook=unique)
    desired_config = {**original_config, **CAPACITY}
    if new_config != desired_config:
        raise ValueError('unrelated_or_invalid_config_change')
    # bool equals int in Python: demand exact scalar types for these three limits.
    if any(type(new_config[key]) is not int for key in ('physical_disk_reserve_GiB',
            'minimum_admission_free_GiB','max_parallel_jobs')):
        raise ValueError('noninteger_capacity_limits')
    inventory = current_inventory(old, parent)
    unchanged = len(inventory) - len(CHANGED)
    if mode == 'installed': inventory.update(doc['changed_runtime'])
    checked_map(runtime, inventory)
    manual = {key.removeprefix('clawsweeper-manual-code-v3/') for key in inventory
              if key.startswith('clawsweeper-manual-code-v3/')}
    exact_files(runtime/'clawsweeper-manual-code-v3', manual)
    unit_hashes = doc['rollback_units'] if mode == 'staged' else doc['unit_candidate_sha256']
    digest_file(fleet_unit, unit_hashes['fleet'])
    digest_file(webhook_unit, unit_hashes['webhook'])
    return {'release':RELEASE, 'mode':mode, 'source_head':source_head,
        'manifest_sha256':sha(raw), 'owner_signed':True, 'capacity':CAPACITY,
        'runtime_files_verified':len(inventory), 'changed_runtime_files_verified':4,
        'unchanged_runtime_files_verified':unchanged, 'immediate_rollback_files_verified':6,
        'current_v3_rollback_files_verified':13, 'r8p3_rollback_files_verified':11,
        'production_installed':mode=='installed', 'job_execution_claimed':False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('staged','installed'))
    for key in ('stage','runtime','fleet_unit','webhook_unit','signers'):
        parser.add_argument('--'+key.replace('_','-'), type=Path, required=True)
    parser.add_argument('--source-head', required=True)
    try:
        print(json.dumps(verify(**vars(parser.parse_args())), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'gate':'HELD','reason':type(exc).__name__,'detail':str(exc)[:220]}))
        return 2

if __name__ == '__main__':
    sys.exit(main())
