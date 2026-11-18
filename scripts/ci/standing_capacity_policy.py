#!/usr/bin/env python3
"""Read-only standing capacity condition; never imports candidate runtime code.

The existing signed release preflight remains responsible for full integrity.
This independent condition prevents a predecessor or successor from silently
reinstating a superseded capacity policy. Any failure exits 255, not systemd's
non-failing ExecCondition skip range. The fixed unit wrapper also maps a missing
guard/interpreter failure to 255. No repair, job launch or retry is performed.
"""
from __future__ import annotations
import argparse
import ast
import copy
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys

SCHEMA = 'local-ci.standing-capacity-policy.v1'
POLICY_ID = 'web-owner-capacity-20261118'
OWNER = Path('/home/johnh')
HOST = 'web'
OWNER_UID = 1000
SIGNER = 'heryourbarme@live.com'
FINGERPRINT = 'SHA256:h+NSfpBiTBgfCZbTf+lB237kCxYfhdLBE0f8cqXXLNU'
NAMESPACE = 'local-ci-standing-capacity-policy'
CAPACITY = {'physical_disk_reserve_GiB': 2, 'minimum_admission_free_GiB': 4,
            'max_parallel_jobs': 1, 'execution_mode': 'detached'}
ANCHOR = {'repository': 'AyobamiH/clawsweeper',
          'source_head': 'ebfa7e26c396d155a785540c6ed75814fe5c5e4f',
          'manifest_sha256': '369ef76f497f6cfd1b70f5c59405b8d06aec8591595687d60a19661689f596a5'}
SOURCE_FILES = ('local_ci.py', 'fleet_ci.py', 'fleet_detached.py')
EXPECTED_PROJECTIONS = {'fleet_ci.py:bounded_command:physical_watchdog': 'fc771e4dc03bf99a272a344e8521f78e685f6b8a2f4c1801cff0ae6b6844301d',
 'fleet_ci.py:bounded_command:physical_watchdog:placement': 'ef1ba65d859cc93b56ea5449f002948aaef82b243854212c3524b166687f2371',
 'fleet_ci.py:configured_parallelism': '2ea1ed2492a478dfe1a04a6cefaee1b7a5acfa215e10bd89ee0fa6c4c487f2cf',
 'fleet_ci.py:constant:ROOT': '5f34973a5039938451d7a6ab778561dea2d00f604854b06964b46be32bce8493',
 'fleet_ci.py:guard': 'c4495ee22791716a3cea988a0170b1efd3a9c0be52efcb3a3d9719c08cf118b9',
 'fleet_ci.py:import:core': 'dfef6d30e819e35e66d87401286e571960a73811de19d2d2d3b965273531458c',
 'fleet_ci.py:parallel_work': '57c2699413c8d63ebc9b44e1e7b65b093f2ad40b5529bb743674cba8cd903ab3',
 'fleet_ci.py:parallel_work:assign:available_disk': 'fa3c53483fb09304277622dd58b2e26401ed46fd063882c7f07f00c4aff96588',
 'fleet_ci.py:parallel_work:assign:disk_budget': 'c920b91a58371a368d07b5425d03542541a499dc4f9c48bdec5931739c58cad8',
 'fleet_ci.py:parallel_work:assign:disk_need': 'a570a7c6923d7ccb3f37b2418c2a61fce8b305bfa65fafe1a57943370c4b2f83',
 'fleet_ci.py:parallel_work:assign:limit': 'b8a3f92ddcb7f24853c8db931193a6fda67c4a02ef5346ef350466a3d00eb2ef',
 'fleet_ci.py:parallel_work:assign:workers': '140a47293aa1f6edfe323c38cf6c5c6ea0ad7758f9cfee899bee3ff306c09ae4',
 'fleet_ci.py:parallel_work:disk_admission': '1708bb2c0b42b90d9e9eb76c15281abd18a17ce7268d7dd06ad4b8192467579d',
 'fleet_ci.py:parallel_work:worker_limit': '371208d1058cc7c296ac136f821a0a5297e6f41e61228724105692c4b3c04390',
 'fleet_detached.py:dispatch': '007d7cdab7581d1395f5a18a3ae78cad36cee0546c7a041985898901aa5a1322',
 'fleet_detached.py:dispatch:assign:available_disk': '1a60ef591c093c6aec25d343294b730aa6180fbe58819b13ff25ca75829135be',
 'fleet_detached.py:dispatch:assign:budget': 'a7740260c589094446ed2c56978ac2933f9fd3c9393474d6fa39251fff40980f',
 'fleet_detached.py:dispatch:assign:disk': 'a86b0bc05a7b6a7c64ed89777fa2f05429a185ed6110f1915dcb82f312b4180a',
 'fleet_detached.py:dispatch:assign:leases': '834f86c92a9b74355f62678a52a01bc260a75ef814da533ab8628f564e12f2b0',
 'fleet_detached.py:dispatch:assign:limit': '8b579f5edfd5e88b4bc5ab6d952b2809284f845f7205e64d830e7819180fe152',
 'fleet_detached.py:dispatch:disk_admission': '658993e4ad1499ed7314c968924cb7934255a88a6fd9e59eee37f0cbc4e11929',
 'fleet_detached.py:dispatch:profile_guard': '8b854ee61926fd6ed4f20caab92f1e883775583947618a8e276205a2b357b0a9',
 'fleet_detached.py:dispatch:worker_limit': 'abeb0bdf0feebca46e9f06ec50bb983ee47e52ba99f9d9041dfd5ade55154aee',
 'fleet_detached.py:import:fleet': '945a80c97314e581da8e0ab0c266715a7a40c5cc6e6438af4b825b6be88632bf',
 'local_ci.py:admission': '7f6e15d814b24c93a263029ee7e1e47ba20852598b3a89154e6cb601805ecaf6',
 'local_ci.py:constant:GIB': '261b7062f48a9b6ee570f89f0d4ef195c49327ffacb49050cfcb56c4e4d899f2',
 'local_ci.py:constant:MIB': 'af991fa2a6fb8ca1c5875ff394a0aa4421b7c8d20038bbe0b4173c47de0380e9',
 'local_ci.py:constant:ROOT': 'a0f977ba59d722f8b1d88ed18ee06da3ad1b432e0e16930ec06d4cced4725d50',
 'local_ci.py:disk_policy': '18afa2f88e3505f8f6f7c7da13bd0444ca23026d075b52d1c6ceac1b347b6047',
 'local_ci.py:run_job:physical_watchdog': '79cd3280174cdf2909cc1fc7472e15f5998c450f4cf1e74690df8fe7c595393d',
 'local_ci.py:run_job:physical_watchdog:placement': '6d670fd40b9ab5a5eb52977e3ae2daaa77d2264bf25bab57937b01eb8067dedd'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def safe_path(path):
    path = Path(path)
    require(path.is_absolute(), 'relative_path')
    for item in reversed([path, *path.parents]):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'symlink:' + item.name)
        require(info.st_uid in (0, os.getuid()), 'foreign_owner:' + item.name)
        require(not info.st_mode & 0o002, 'world_writable:' + item.name)
        if info.st_mode & 0o020:
            members = set(grp.getgrgid(info.st_gid).gr_mem)
            members.update(p.pw_name for p in pwd.getpwall() if p.pw_gid == info.st_gid)
            require(item in (OWNER/'.local/state', OWNER/'.local/opt')
                    and info.st_gid == OWNER_UID and members == {'johnh'},
                    'shared_writable_path:' + item.name)
        if item != path:
            require(stat.S_ISDIR(info.st_mode), 'nondirectory_ancestor')
    require(path.resolve() == path, 'noncanonical_path')


def read_regular(path, limit=1024*1024):
    path = Path(path)
    safe_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and 0 < before.st_size <= limit,
                'unsafe_regular_file:' + path.name)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode')
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k)
                for k in fields), 'file_changed_during_read:' + path.name)
        return raw
    finally:
        os.close(fd)


def signed(path, signers):
    """One verification call only. Never loads a private key or retries."""
    path, signers = Path(path), Path(signers)
    signature = Path(str(path) + '.sig')
    raw = read_regular(path)
    before_sig = read_regular(signature, 4096)
    before_signers = read_regular(signers, 8192)
    result = subprocess.run(['/usr/bin/ssh-keygen','-Y','verify','-f',str(signers),
        '-I',SIGNER,'-n',NAMESPACE,'-s',str(signature)], input=raw,
        capture_output=True, check=False, timeout=15,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':str(OWNER)})
    require(result.returncode == 0, 'invalid_owner_signature:' + path.name)
    require(FINGERPRINT in (result.stdout + result.stderr).decode(errors='replace'),
            'unexpected_owner_signing_key')
    require(read_regular(path) == raw and read_regular(signature,4096) == before_sig
            and read_regular(signers,8192) == before_signers,
            'signature_inputs_changed')
    return raw


class WithoutDocstrings(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            node.body = node.body[1:]
        return node


def ast_digest(nodes):
    nodes = [WithoutDocstrings().visit(copy.deepcopy(n)) for n in nodes]
    return digest(ast.dump(ast.Module(body=nodes,type_ignores=[]),
                           include_attributes=False).encode())


def function(tree, name):
    found = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    require(len(found) == 1, 'capacity_function_missing_or_duplicated:' + name)
    return found[0]


def assigned(node):
    if isinstance(node, ast.Assign): targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)): targets = [node.target]
    else: return set()
    return {n.id for target in targets for n in ast.walk(target) if isinstance(n, ast.Name)}


def calls(node, name):
    return [n for n in ast.walk(node) if isinstance(n,ast.Call) and
            ((isinstance(n.func,ast.Name) and n.func.id == name) or
             (isinstance(n.func,ast.Attribute) and n.func.attr == name))]


def watchdog_ancestry(root, target):
    """Bind loop/branch placement, without hashing unrelated inspection code."""
    def walk(node, path):
        if node is target:
            return path
        marker = None
        if isinstance(node,ast.FunctionDef):
            marker = ['function',node.name,ast.dump(node.args,include_attributes=False)]
        elif isinstance(node,(ast.If,ast.While)):
            marker = [type(node).__name__,ast.dump(node.test,include_attributes=False)]
        elif isinstance(node,(ast.For,ast.AsyncFor)):
            marker = [type(node).__name__,ast.dump(node.target,include_attributes=False),
                      ast.dump(node.iter,include_attributes=False)]
        elif isinstance(node,(ast.With,ast.AsyncWith)):
            marker = [type(node).__name__,[ast.dump(item,include_attributes=False) for item in node.items]]
        elif isinstance(node,ast.Try):
            marker = ['Try',[(ast.dump(h.type,include_attributes=False) if h.type else None,h.name)
                             for h in node.handlers],bool(node.finalbody)]
        elif isinstance(node,(ast.Lambda,ast.ClassDef,ast.AsyncFunctionDef,ast.Match)):
            marker = ['unsupported_control_flow',type(node).__name__]
        for field,value in ast.iter_fields(node):
            values = value if isinstance(value,list) else [value]
            for child in values:
                if isinstance(child,ast.AST):
                    result = walk(child,path+[[field,marker]] if marker else path)
                    if result is not None:
                        return result
        return None
    path = walk(root,[])
    require(path is not None,'watchdog_placement_missing')
    return digest(json.dumps(path,separators=(',',':')).encode())


def capacity_projections(sources):
    """Parse only. Projection shape is intentionally closed to unknown rewrites.

    Hashing targeted statements allows unrelated container-inspection repairs.
    Full signed release validation and technical review still cover other code.
    """
    require(set(sources) == set(SOURCE_FILES), 'capacity_source_inventory')
    trees = {name:ast.parse(raw,filename=name) for name,raw in sources.items()}
    result = {}
    def put(key, nodes, count=None):
        require(nodes and (count is None or len(nodes) == count), 'projection_shape:' + key)
        result[key] = ast_digest(nodes)
    for filename, names in (('local_ci.py',('disk_policy','admission')),
                            ('fleet_ci.py',('guard','configured_parallelism','parallel_work')),
                            ('fleet_detached.py',('dispatch',))):
        tree = trees[filename]
        for name in names:
            put(filename + ':' + name, [function(tree,name)], 1)
            require(not any(name in assigned(n) for n in tree.body),
                    'capacity_function_rebound:' + name)
    for name in ('GIB','MIB','ROOT'):
        put('local_ci.py:constant:' + name,
            [n for n in trees['local_ci.py'].body if name in assigned(n)], 1)
    for filename,module,alias in (('fleet_ci.py','local_ci','core'),
                                  ('fleet_detached.py','fleet_ci','fleet')):
        tree = trees[filename]
        put(filename + ':import:' + alias,
            [n for n in tree.body if isinstance(n,ast.Import) and
             any(a.name == module and a.asname == alias for a in n.names)], 1)
        require(not any(alias in assigned(n) for n in tree.body),'capacity_module_rebound:' + alias)
    put('fleet_ci.py:constant:ROOT',
        [n for n in trees['fleet_ci.py'].body if 'ROOT' in assigned(n)], 1)
    for filename, name in (('local_ci.py','run_job'),('fleet_ci.py','bounded_command')):
        f = function(trees[filename],name)
        found = [n for n in ast.walk(f) if isinstance(n,ast.If) and calls(n.test,'disk_usage')]
        key = filename + ':' + name + ':physical_watchdog'
        put(key,found,1)
        result[key + ':placement'] = watchdog_ancestry(f,found[0])
    selections = (
        ('fleet_ci.py','parallel_work',('limit','workers','disk_budget','disk_need','available_disk')),
        ('fleet_detached.py','dispatch',('limit','budget','leases','available_disk','disk')),
    )
    for filename, name, variables in selections:
        f = function(trees[filename],name)
        for variable in variables:
            put(filename + ':' + name + ':assign:' + variable,
                [n for n in ast.walk(f) if variable in assigned(n)])
        # Preserve the actual limit and resource comparisons that consume budgets.
        for label, identifiers in (('worker_limit', {'active','selected'} if name=='parallel_work'
                                   else {'leases','admitted'}),
                                  ('disk_admission', {'available_disk'})):
            nodes = []
            for n in ast.walk(f):
                if not isinstance(n,ast.If): continue
                tested = {x.id for x in ast.walk(n.test) if isinstance(x,ast.Name)}
                if label == 'worker_limit':
                    lengths = {x.args[0].id for x in calls(n.test,'len')
                               if x.args and isinstance(x.args[0],ast.Name)}
                    if lengths & identifiers: nodes.append(n)
                elif tested & identifiers: nodes.append(n)
            put(filename + ':' + name + ':' + label, nodes, 1)
    f = function(trees['fleet_detached.py'],'dispatch')
    put('fleet_detached.py:dispatch:profile_guard',
        [n for n in ast.walk(f) if isinstance(n,ast.If) and calls(n.test,'guard')], 1)
    return result


def inspect_runtime(runtime):
    runtime = Path(runtime)
    safe_path(runtime)
    info = runtime.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o022, 'unsafe_runtime_directory')
    config_raw = read_regular(runtime/'config.json',65536)
    config = json.loads(config_raw,object_pairs_hook=unique)
    require(isinstance(config,dict), 'capacity_config_not_object')
    for key, value in CAPACITY.items():
        require(key in config and type(config[key]) is type(value) and config[key] == value,
                'standing_capacity_setting_changed:' + key)
    sources = {name:read_regular(runtime/name) for name in SOURCE_FILES}
    projections = capacity_projections(sources)
    require(projections == EXPECTED_PROJECTIONS, 'standing_capacity_code_regression')
    # Keep reads stable across the complete static verification.
    require(read_regular(runtime/'config.json',65536) == config_raw
            and all(read_regular(runtime/name) == raw for name,raw in sources.items()),
            'runtime_changed_during_policy_check')
    return projections


def contract_for(guard_sha256):
    require(re.fullmatch(r'[0-9a-f]{64}',guard_sha256), 'invalid_guard_digest')
    return {'schema':SCHEMA,'policy_id':POLICY_ID,'host':HOST,'owner_uid':OWNER_UID,
            'signature_namespace':NAMESPACE,'capacity':dict(CAPACITY),
            'anchor':dict(ANCHOR),'guard_sha256':guard_sha256,
            'capacity_projections':dict(EXPECTED_PROJECTIONS)}


def build_contract(runtime, guard_path=None):
    """Packaging helper; caller signs the returned policy and the guard file."""
    inspect_runtime(runtime)
    guard_path = Path(__file__) if guard_path is None else Path(guard_path)
    return contract_for(digest(read_regular(guard_path)))


def verify(policy, runtime, signers):
    require(os.getuid() == OWNER_UID and socket.gethostname() == HOST, 'wrong_host_or_owner')
    policy_raw = signed(Path(policy),Path(signers))
    document = json.loads(policy_raw,object_pairs_hook=unique)
    guard = Path(__file__)
    # Both signatures are verified before any candidate source is parsed.
    guard_raw = signed(guard,Path(signers))
    expected = contract_for(digest(guard_raw))
    require(json.dumps(document,sort_keys=True) == json.dumps(expected,sort_keys=True),
            'standing_policy_scope_or_guard_changed')
    projections = inspect_runtime(Path(runtime))
    require(read_regular(Path(policy)) == policy_raw, 'policy_changed_during_check')
    return {'gate':'STANDING_CAPACITY_POLICY_VERIFIED','policy_id':POLICY_ID,
            'policy_sha256':digest(policy_raw),'guard_sha256':digest(guard_raw),
            'capacity':dict(CAPACITY),'capacity_projections_verified':len(projections),
            'candidate_code_executed':False,'runtime_mutated':False,
            'full_release_preflight_still_required':True}


def unit_bytes(guard, policy, runtime, signers):
    paths = [str(Path(p)) for p in (guard,policy,runtime,signers)]
    require(all(re.fullmatch(r'/[A-Za-z0-9_./-]+',p) and '..' not in Path(p).parts
                for p in paths), 'unsafe_fixed_unit_path')
    g,p,r,s = paths
    command = (f'/usr/bin/python3 -I -B {g} --policy {p} --runtime {r} '
               f'--signers {s} || exit 255')
    return ('[Service]\nExecCondition=/bin/sh -c "'+command+'"\n').encode()


def main(argv=None):
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        for name in ('policy','runtime','signers'):
            parser.add_argument('--'+name,type=Path,required=True)
        args = parser.parse_args(argv)
        print(json.dumps(verify(**vars(args)),sort_keys=True))
        return 0
    except BaseException as exc:
        if isinstance(exc,SystemExit) and exc.code == 0:
            return 0
        print(json.dumps({'gate':'STANDING_CAPACITY_POLICY_FAILED',
                          'reason':type(exc).__name__,'detail':str(exc)[:220],
                          'runtime_mutated':False,'job_launch_attempted':False}),file=sys.stderr)
        return 255


if __name__ == '__main__':
    sys.exit(main())
