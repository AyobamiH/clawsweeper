"""Fail-closed suite admission tests, no Docker, provider or installed writes."""
import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/ci'))
SCRIPT = ROOT / 'scripts/ci/direct_local_split_policy_gate.py'
spec = importlib.util.spec_from_file_location('split_suite_source_gate_test', SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SOURCE = (b"import re\n"
          b"def load_policy(p):\n"
          b"    for repo,entry in p['repositories'].items():\n"
          b"        for name,suite in entry['suites'].items():\n"
          + gate.ANCHOR
          + b"    return p\n")

STEPS = [
    {'name': 'Workflow semantic validation',
     'command': 'actionlint -shellcheck= -ignore \'unexpected key "queue" for "concurrency" section\' .github/workflows/*.yml',
     'timeout': 900},
    {'name': 'Pinned pnpm dependency install',
     'command': 'pnpm install --frozen-lockfile', 'timeout': 900},
    {'name': 'Full repository validation', 'command': 'pnpm run check',
     'timeout': 1500},
    {'name': 'Sparse repair checkout smoke',
     'command': 'pnpm run test:workflow-sparse-checkout', 'timeout': 600},
]
FIELDS = {
    'node': '24', 'image': 'sha256:dc7e982df33f88146add5c0f00907c355777ca06f0fc56b568c5c9f9a7ce35e2', 'cpus': 4,
    'memory_mib': 3072, 'pids': 512, 'writable_mib': 4096,
    'execution_environment_revision': 'web-docker-v7-dual-path-pnpm-jq',
}


def policy():
    base = {**FIELDS, 'steps': copy.deepcopy(STEPS)}
    check = {**FIELDS, 'steps': copy.deepcopy(STEPS[:2] + STEPS[2:3])}
    sparse = {**FIELDS, 'steps': copy.deepcopy(STEPS[:2] + STEPS[3:])}
    return {'repositories': {'AyobamiH/clawsweeper': {'suites': {
        'linux-node24': base, 'linux-node24-claw-check': check,
        'linux-node24-claw-sparse': sparse}}}}


def render(src=SOURCE, digest=None):
    return gate.compile_split_policy_gate(
        src, expected_sha256=digest or hashlib.sha256(src).hexdigest())


def validate(p):
    namespace = {}
    exec(compile(render()['content'], '<split-fixture>', 'exec'), namespace)
    return namespace['load_policy'](p)


class SplitSuitePolicyGateTests(unittest.TestCase):
    def test_exact_render_succeeds_without_installing(self):
        r = render()
        self.assertFalse(r['installed'])
        self.assertEqual(hashlib.sha256(r['content']).hexdigest(),
                         r['proposed_sha256'])
        self.assertNotEqual(r['current_sha256'], r['proposed_sha256'])
        ast.parse(r['content'].decode())

    def test_two_reviewed_profiles_allowed(self):
        p = policy()
        self.assertEqual(validate(p), p)

    def test_exact_split_can_be_validated_without_aggregate_or_sibling(self):
        p = policy()
        suites = p['repositories']['AyobamiH/clawsweeper']['suites']
        suites.pop('linux-node24')
        suites.pop('linux-node24-claw-sparse')
        self.assertEqual(validate(p), p)

    def test_matching_but_unreviewed_image_and_timeout_denied(self):
        for kind in ('image', 'timeout', 'revision'):
            p = policy()
            for suite in p['repositories']['AyobamiH/clawsweeper']['suites'].values():
                if kind == 'image':
                    suite['image'] = 'sha256:' + 'f' * 64
                elif kind == 'timeout':
                    suite['steps'][0]['timeout'] = 1
                else:
                    suite['execution_environment_revision'] = 'unreviewed'
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                validate(p)

    def test_exact_legacy_preimage_upgrades_without_install(self):
        before = SOURCE.replace(gate.ANCHOR, gate.LEGACY_REPLACEMENT.encode())
        self.assertEqual(render(src=before)['content'], render()['content'])
        altered = before.replace(b'Unreviewed ClawSweeper split commands',
                                 b'Unreviewed split commands')
        with self.assertRaisesRegex(RuntimeError, 'shape_unreviewed'):
            render(src=altered)

    def test_split_must_not_be_admitted_for_other_repo(self):
        p = policy()
        p['repositories']['AyobamiH/post-once'] = {
            'suites': {'linux-node24-claw-check': copy.deepcopy(
                p['repositories']['AyobamiH/clawsweeper']['suites']['linux-node24-claw-check'])}}
        with self.assertRaisesRegex(RuntimeError, 'Invalid suite'):
            validate(p)

    def test_resources_and_steps_tampering_denied(self):
        for mutation in ('image', 'memory_mib', 'cpus', 'steps', 'base'):
            p = policy()
            suites = p['repositories']['AyobamiH/clawsweeper']['suites']
            if mutation == 'steps':
                suites['linux-node24-claw-check']['steps'][-1]['command'] = 'echo bypass'
            elif mutation == 'base':
                suites['linux-node24']['steps'][-1]['command'] = 'echo bypass'
            elif mutation == 'image':
                suites['linux-node24-claw-sparse']['image'] = 'sha256:' + 'b' * 64
            else:
                suites['linux-node24-claw-sparse'][mutation] = 1
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                validate(p)

    def test_legacy_suite_unchanged(self):
        p = policy()
        p['repositories']['AyobamiH/clawsweeper']['suites'] = {
            'linux-node24': p['repositories']['AyobamiH/clawsweeper']['suites']['linux-node24']}
        self.assertEqual(validate(p), p)

    def test_exact_controller_hash_required(self):
        with self.assertRaisesRegex(RuntimeError, 'source_mismatch'):
            render(digest='0' * 64)

    def test_unrecognised_or_duplicate_controller_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'shape_unreviewed'):
            render(src=render()['content'])
        with self.assertRaisesRegex(RuntimeError, 'shape_unreviewed'):
            render(src=SOURCE.replace(b'load_policy(p)', b'new_policy(p)'))
        with self.assertRaisesRegex(RuntimeError, 'split_policy_not_python'):
            render(src=SOURCE.replace(gate.ANCHOR, b''))


if __name__ == '__main__':
    unittest.main()
