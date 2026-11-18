#!/usr/bin/env python3
"""Render the owner-approved host capacity change from one exact installed base.

This source-only builder never changes the live runtime, queues or services.
The caller must bind the four outputs into a signed release and transaction.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path

BASELINE = {
    "local_ci.py": "05e61076e8d5e7246c98e3444ad23854abe06da45dc9f51a01e5a42e4f31027d",
    "fleet_ci.py": "dbfeb11511c3104b46c4f729642a5af27a054bc40db2aae6cebc11b23b246b37",
    "fleet_detached.py": "e7d697cdc65d9c07093b7c99306043777c589b06c65e23848a03beb6d355bb18",
    "config.json": "ed8f3153f47acb181e57ae9887cdd7c1a108909fd0292436d45ef7fe69d5a604",
}
CAPACITY = {
    "physical_disk_reserve_GiB": 2,
    "minimum_admission_free_GiB": 4,
    "max_parallel_jobs": 1,
}

DISK_HELPER = '''def disk_policy() -> tuple[int, int]:
    """Owner-configured physical stop reserve and minimum admission, in bytes.

    Missing legacy settings retain the original conservative defaults. Existing
    malformed or unsafe configuration fails closed, including during a job.
    """
    import math, stat
    path = ROOT / 'config.json'
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise RuntimeError('Duplicate local CI config key')
            result[key] = value
        return result
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return 12*GIB, 14*GIB
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022 or not 0 < info.st_size <= 65536):
            raise RuntimeError('Unsafe local CI capacity configuration')
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
        if (len(raw) != info.st_size or
                (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise RuntimeError('Local CI capacity configuration changed during read')
    finally:
        os.close(fd)
    try:
        config = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError('Malformed local CI capacity configuration') from exc
    if not isinstance(config, dict):
        raise RuntimeError('Local CI capacity configuration must be an object')
    reserve = config.get('physical_disk_reserve_GiB', 12)
    minimum = config.get('minimum_admission_free_GiB', 14)
    for value in (reserve, minimum):
        try:
            valid = type(value) in (int, float) and math.isfinite(value) and value > 0
        except (OverflowError, ValueError):
            valid = False
        if not valid: raise RuntimeError('Invalid local CI disk capacity value')
    if minimum < reserve:
        raise RuntimeError('Local CI admission floor is below its stop reserve')
    # Round reservations upwards if an owner later selects fractional GiB.
    return math.ceil(reserve*GIB), math.ceil(minimum*GIB)


'''


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError("capacity_patch_baseline_expression_changed")
    return text.replace(old, new, 1)


def render_runtime(baseline: dict[str, bytes]) -> dict[str, bytes]:
    if set(baseline) != set(BASELINE):
        raise ValueError("capacity_baseline_inventory_changed")
    for name, expected in BASELINE.items():
        if not isinstance(baseline[name], bytes) or sha(baseline[name]) != expected:
            raise ValueError("capacity_baseline_digest_mismatch:" + name)
    core = baseline['local_ci.py'].decode('utf-8')
    core = once(core, 'def admission(s: dict) -> list[str]:\n',
                DISK_HELPER + 'def admission(s: dict) -> list[str]:\n')
    core = once(core,
        "    if min(s['windows_free_bytes'], s['linux_free_bytes']) < 14*GIB:\n"
        "        reasons.append('less than 14 GiB free before job (12 GiB reserve plus headroom)')",
        "    reserve, minimum = disk_policy()\n"
        "    if min(s['windows_free_bytes'], s['linux_free_bytes']) < minimum:\n"
        "        reasons.append(f'less than {minimum/GIB:g} GiB free before job "
        "({reserve/GIB:g} GiB reserve plus headroom)')")
    core = once(core,
        "if min(shutil.disk_usage('/mnt/c').free,shutil.disk_usage(ROOT).free)<12*GIB:",
        "if min(shutil.disk_usage('/mnt/c').free,shutil.disk_usage(ROOT).free)<disk_policy()[0]:")
    fleet = baseline['fleet_ci.py'].decode('utf-8')
    fleet = once(fleet,
        '    required_disk=max(14*core.GIB,12*core.GIB+(writable_mib+512)*core.MIB)',
        '    reserve, minimum=core.disk_policy()\n'
        '    required_disk=max(minimum,reserve+(writable_mib+512)*core.MIB)')
    fleet = once(fleet,
        "if min(core.shutil.disk_usage('/mnt/c').free,core.shutil.disk_usage(ROOT).free)<12*core.GIB:",
        "if min(core.shutil.disk_usage('/mnt/c').free,core.shutil.disk_usage(ROOT).free)<core.disk_policy()[0]:")
    fleet = once(fleet,
        '    # Each job has a separate writable layer; retain the physical 12 GiB stop reserve.\n'
        "    disk_budget=max(0,min(resources['windows_free_bytes'],resources['linux_free_bytes'])-12*core.GIB)",
        '    # Each writable layer retains the owner-configured physical stop reserve.\n'
        "    disk_budget=max(0,min(resources['windows_free_bytes'],resources['linux_free_bytes'])-core.disk_policy()[0])")
    detached = baseline['fleet_detached.py'].decode('utf-8')
    detached = once(detached,
        "                       12*fleet.core.GIB-sum(l['disk_bytes'] for l in leases))",
        "                       fleet.core.disk_policy()[0]-sum(l['disk_bytes'] for l in leases))")
    config = json.loads(baseline['config.json'])
    if (config.get('physical_disk_reserve_GiB') != 12 or
            config.get('minimum_admission_free_GiB') != 14 or
            config.get('max_parallel_jobs') != 2 or
            config.get('execution_mode') != 'detached'):
        raise ValueError('capacity_baseline_settings_changed')
    config.update(CAPACITY)
    output = {'local_ci.py':core.encode(), 'fleet_ci.py':fleet.encode(),
              'fleet_detached.py':detached.encode(),
              'config.json':(json.dumps(config, indent=2)+'\n').encode()}
    for name, raw in output.items():
        if name.endswith('.py'): ast.parse(raw, filename=name)
    return output


def render_directory(source: Path, destination: Path) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError('capacity_candidate_already_exists_do_not_overwrite')
    baseline = {}
    for name in BASELINE:
        file = source/name
        if file.is_symlink() or not file.is_file():
            raise ValueError('unsafe_capacity_baseline_file:' + name)
        baseline[name] = file.read_bytes()
    output = render_runtime(baseline)
    destination.mkdir(mode=0o700)
    for name, raw in output.items():
        with (destination/name).open('xb') as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(raw); file.flush(); os.fsync(file.fileno())
    fd = os.open(destination, os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return {'schema':'clawsweeper.owner-capacity-source-candidate.v1',
            'base_files':BASELINE,'candidate_files':{k:sha(v) for k,v in output.items()},
            'capacity':CAPACITY,'clawsweeper_single_job_admission_GiB':6.5,
            'per_job_reservations_unchanged':True,'production_installed':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(render_directory(args.baseline,args.output),sort_keys=True,indent=2))
