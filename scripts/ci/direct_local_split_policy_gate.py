#!/usr/bin/env python3
"""Source-only, exact-controller split-suite allowlist patch. Never installs."""
from __future__ import annotations

import ast
import hashlib
import re

from direct_local_workflow import SPLIT, aggregate_suite_spec, split_suite_spec

ANCHOR = (
    b"            if not re.fullmatch(r'(linux-node(20|22|24)|linux-node24-provider|linux-node20-bridge|linux-python310|linux-python312)',name): raise RuntimeError('Invalid suite')\n"
)
LOOP = b"        for name,suite in entry['suites'].items():\n"
LEGACY_MARKER = b"Source-bound ClawSweeper split-suite validation v1"
MARKER = b"Source-bound ClawSweeper split-suite validation v2"

LEGACY_REPLACEMENT = """            # Source-bound ClawSweeper split-suite validation v1
            _dl_names = ('linux-node24-claw-check', 'linux-node24-claw-sparse')
            _dl_standard = re.fullmatch(
                r'(linux-node(20|22|24)|linux-node24-provider|linux-node20-bridge|linux-python310|linux-python312)', name)
            if not _dl_standard and not (
                    repo == 'AyobamiH/clawsweeper' and name in _dl_names):
                raise RuntimeError('Invalid suite')
            if repo == 'AyobamiH/clawsweeper' and name in _dl_names:
                _dl_suites = entry['suites']
                _dl_base = _dl_suites.get('linux-node24')
                _dl_fields = ('node', 'image', 'cpus', 'memory_mib',
                              'pids', 'writable_mib', 'execution_environment_revision')
                if (not set(_dl_names) <= set(_dl_suites)
                        or not isinstance(_dl_base, dict)
                        or set(_dl_base) != set(_dl_fields) | {'steps'}
                        or not isinstance(suite, dict)
                        or set(suite) != set(_dl_fields) | {'steps'}
                        or any(suite[field] != _dl_base[field] for field in _dl_fields)):
                    raise RuntimeError('Untrusted ClawSweeper split sandbox')
                _dl_commands = (
                    ('Workflow semantic validation',
                     'actionlint -shellcheck= -ignore \\'unexpected key "queue" for "concurrency" section\\' .github/workflows/*.yml', 900),
                    ('Pinned pnpm dependency install', 'pnpm install --frozen-lockfile', 900),
                    ('Full repository validation', 'pnpm run check', 1500),
                    ('Sparse repair checkout smoke', 'pnpm run test:workflow-sparse-checkout', 600),
                )
                _dl_steps = [{'name': n, 'command': c, 'timeout': t}
                             for n, c, t in _dl_commands]
                if (_dl_base['steps'] != _dl_steps
                        or suite['steps'] != [
                            _dl_steps[0], _dl_steps[1],
                            _dl_steps[_dl_names.index(name) + 2]]):
                    raise RuntimeError('Unreviewed ClawSweeper split commands')
"""

# Emit the same exact profile contract as the source planner. No imports of
# mutable project files are required in the generated fleet runtime.
_EXACT = {suite: split_suite_spec(key) for key, (suite, _) in SPLIT.items()}
_AGGREGATE = aggregate_suite_spec()
REPLACEMENT = """            # Source-bound ClawSweeper split-suite validation v2
            _dl_names = ('linux-node24-claw-check', 'linux-node24-claw-sparse')
            _dl_standard = re.fullmatch(
                r'(linux-node(20|22|24)|linux-node24-provider|linux-node20-bridge|linux-python310|linux-python312)', name)
            if not _dl_standard and not (
                    repo == 'AyobamiH/clawsweeper' and name in _dl_names):
                raise RuntimeError('Invalid suite')
            if repo == 'AyobamiH/clawsweeper' and name in _dl_names:
                _dl_expected = """ + repr(_EXACT) + """[name]
                if (not isinstance(suite, dict) or set(suite) != set(_dl_expected)
                        or any(type(suite[k]) is not type(v) or suite[k] != v
                               for k, v in _dl_expected.items() if k != 'steps')):
                    raise RuntimeError('Untrusted ClawSweeper split sandbox')
                if (type(suite['steps']) is not list
                        or suite['steps'] != _dl_expected['steps']
                        or any(type(step['timeout']) is not int for step in suite['steps'])):
                    raise RuntimeError('Unreviewed ClawSweeper split commands')
                if 'linux-node24' in entry['suites']:
                    _dl_base = entry['suites']['linux-node24']
                    _dl_aggregate = """ + repr(_AGGREGATE) + """
                    if (not isinstance(_dl_base, dict) or _dl_base != _dl_aggregate
                            or any(type(_dl_base[k]) is not type(v)
                                   for k, v in _dl_aggregate.items())
                            or any(type(step['timeout']) is not int for step in _dl_base['steps'])):
                        raise RuntimeError('Unreviewed ClawSweeper historical aggregate')
"""


def compile_split_policy_gate(current: bytes, *, expected_sha256: str) -> dict:
    """Produce an in-memory patch to the existing owner-controlled fleet."""
    if (not isinstance(current, bytes) or not isinstance(expected_sha256, str)
            or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)
            or hashlib.sha256(current).hexdigest() != expected_sha256):
        raise RuntimeError('split_policy_controller_source_mismatch')
    try:
        tree = ast.parse(current.decode('utf-8'))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise RuntimeError('split_policy_not_python') from exc
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef)
               and node.name == 'load_policy']
    legacy = LEGACY_REPLACEMENT.encode()
    preimage = legacy if LEGACY_MARKER in current else ANCHOR
    if (len(matches) != 1 or current.count(preimage) != 1
            or current.count(LOOP) != 1 or MARKER in current
            or (preimage == legacy and (
                current.count(LEGACY_MARKER) != 1 or ANCHOR in current))):
        raise RuntimeError('split_policy_controller_shape_unreviewed')
    line = current[:current.index(preimage)].count(b'\n') + 1
    if not (matches[0].lineno < line <= matches[0].end_lineno):
        raise RuntimeError('split_policy_allowlist_outside_load_policy')
    content = current.replace(preimage, REPLACEMENT.encode(), 1)
    ast.parse(content.decode('utf-8'))
    return {'schema': 'clawsweeper.split-suite-source-gate.v1',
            'installed': False, 'current_sha256': expected_sha256,
            'proposed_sha256': hashlib.sha256(content).hexdigest(),
            'content': content}
