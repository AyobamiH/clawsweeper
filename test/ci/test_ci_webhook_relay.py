"""Crash and ownership acceptance for the local CI GitHub webhook relay.

Uses a mocked GitHub API and isolated files; never creates real webhooks.
"""
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import time
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / 'scripts/ci-webhook-relay.py'
spec = importlib.util.spec_from_file_location('ci_webhook_relay', SCRIPT)
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class Hooks:
    def __init__(self):
        self.hooks = {}
        self.calls = []
        self.next_id = 900

    def api(self, method, path, data=None):
        self.calls.append((method, path))
        if method == 'GET' and path.startswith('hooks?per_page=100&page='):
            page = int(path.rsplit('=', 1)[1])
            hooks = [dict(self.hooks[k]) for k in sorted(self.hooks)]
            return hooks[(page - 1) * 100:page * 100]
        if method == 'GET' and path.startswith('hooks/'):
            return dict(self.hooks[int(path.split('/')[1])])
        if method == 'POST' and path == 'hooks':
            hook_id = self.next_id
            self.next_id += 1
            self.hooks[hook_id] = dict(data, id=hook_id)
            return dict(self.hooks[hook_id])
        if method == 'PATCH' and path.startswith('hooks/'):
            hook_id = int(path.split('/')[1])
            self.hooks[hook_id].update(data)
            return dict(self.hooks[hook_id])
        raise AssertionError((method, path))


class IntentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = pathlib.Path(self.temp.name)
        self.secret_file = self.home / 'hmac'
        self.secret_file.write_text('p' * 40)
        self.state = self.home / 'id'
        self.binding = self.home / 'binding.json'
        self.update_intent = self.home / 'update-intent.json'
        self.intent = self.home / 'intent'
        self.lock = self.home / 'lock'
        self.backend = Hooks()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for attr, value in [('SECRET', self.secret_file), ('STATE', self.state),
                            ('BINDING', self.binding), ('UPDATE_INTENT', self.update_intent),
                            ('INTENT', self.intent), ('LOCK', self.lock)]:
            self.stack.enter_context(patch.object(relay, attr, value))
        self.stack.enter_context(patch.object(relay, 'api', self.backend.api))

    def test_creates_unique_marked_hook_with_durable_state(self):
        self.assertEqual(relay.reconcile('https://fresh.trycloudflare.com'), 900)
        self.assertEqual(self.state.read_text(), '900')
        self.assertEqual(json.loads(self.binding.read_text())['hook_id'], '900')
        self.assertEqual(self.binding.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.intent.exists())
        hook = self.backend.hooks[900]
        self.assertRegex(hook['config']['url'], r'^https://fresh.trycloudflare.com/github\?cs_hook=[a-f0-9]{48}$')
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'POST']), 1)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

    def test_successful_post_then_lost_state_write_adopts_same_hook(self):
        original_write = relay.durable_write
        def crash_after_post(path, content):
            if path == self.state:
                raise OSError('simulated power loss after remote create')
            return original_write(path, content)
        with patch.object(relay, 'durable_write', side_effect=crash_after_post):
            with self.assertRaisesRegex(OSError, 'simulated power loss'):
                relay.reconcile('https://old.trycloudflare.com')
        self.assertFalse(self.state.exists())
        self.assertTrue(self.intent.exists())
        recorded_target = json.loads(self.intent.read_text())['target']
        self.assertEqual(self.backend.hooks[900]['config']['url'], recorded_target)
        self.assertEqual(relay.reconcile('https://new.trycloudflare.com'), 900)
        self.assertEqual(self.state.read_text(), '900')
        self.assertFalse(self.intent.exists())
        new_target = self.backend.hooks[900]['config']['url']
        self.assertTrue(new_target.startswith('https://new.trycloudflare.com/github?cs_hook='))
        self.assertEqual(new_target.split('cs_hook=')[1], recorded_target.split('cs_hook=')[1])
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'POST']), 1)

    def test_uncertain_post_without_readback_never_repeats_creation(self):
        def uncertain_post(method, path, data=None):
            if method == 'POST':
                raise RuntimeError('lost response; remote effect unknown')
            return self.backend.api(method, path, data)
        with patch.object(relay, 'api', side_effect=uncertain_post):
            with self.assertRaisesRegex(RuntimeError, 'lost response'):
                relay.reconcile('https://old.trycloudflare.com')
        self.assertTrue(self.intent.exists())
        with self.assertRaisesRegex(RuntimeError, 'Uncertain webhook creation'):
            relay.reconcile('https://new.trycloudflare.com')
        self.assertFalse(self.state.exists())
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'POST']), 0)

    def test_ambiguous_match_blocks_adoption(self):
        def fail_id_write(path, content):
            if path == self.state:
                raise OSError('crash')
            return relay_write(path, content)
        relay_write = relay.durable_write
        with patch.object(relay, 'durable_write', side_effect=fail_id_write):
            with self.assertRaises(OSError):
                relay.reconcile('https://old.trycloudflare.com')
        self.backend.hooks[901] = dict(self.backend.hooks[900], id=901)
        with self.assertRaisesRegex(RuntimeError, 'no unique owned hook'):
            relay.reconcile('https://new.trycloudflare.com')
        self.assertFalse(self.state.exists())
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'POST']), 1)

    def test_existing_unowned_legacy_destination_is_not_adopted(self):
        self.backend.hooks[60] = {'id': 60, 'name': 'web', 'active': True,
            'events': relay.EVENTS, 'config': {'url': 'https://old.trycloudflare.com/github'}}
        with self.assertRaisesRegex(RuntimeError, 'Existing unowned matching hook'):
            relay.reconcile('https://old.trycloudflare.com')
        self.assertFalse(self.state.exists())
        self.assertFalse(self.intent.exists())

    def test_existing_state_preserves_legacy_path_only_with_accepted_binding(self):
        self.state.write_text('60')
        old = 'https://old.trycloudflare.com/github'
        self.backend.hooks[60] = {'id': 60, 'name': 'web', 'active': True,
            'events': relay.EVENTS, 'config': {'url': old}}
        with self.assertRaisesRegex(RuntimeError, 'lacks owner-approved URL binding'):
            relay.reconcile('https://new.trycloudflare.com')
        self.assertFalse(any(action == 'PATCH' for action, _ in self.backend.calls))
        relay.durable_write(self.binding, json.dumps(relay.bound_entry(60, old)))
        self.assertEqual(relay.reconcile('https://new.trycloudflare.com'), 60)
        self.assertEqual(self.backend.hooks[60]['config']['url'], 'https://new.trycloudflare.com/github')
        self.assertEqual(json.loads(self.binding.read_text())['target'], 'https://new.trycloudflare.com/github')
        self.assertFalse(self.update_intent.exists())
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'POST']), 0)

    def test_marker_does_not_authorise_foreign_webhook_authority(self):
        marker = 'b' * 48
        valid = 'https://old.trycloudflare.com/github?cs_hook=' + marker
        self.assertEqual(relay.marker_of(valid), marker)
        for host in ('evil.example', 'user:pass@old.trycloudflare.com',
                     'old.trycloudflare.com:8443'):
            with self.subTest(host=host), self.assertRaisesRegex(RuntimeError, 'Unexpected webhook host'):
                relay.marker_of('https://' + host + '/github?cs_hook=' + marker)
        self.state.write_text('60')
        original = 'https://old.trycloudflare.com/github?cs_hook=' + marker
        relay.durable_write(self.binding, json.dumps(relay.bound_entry(60, original)))
        for changed in ('https://evil.example/github?cs_hook=' + marker,
                        'https://someone-else.trycloudflare.com/github?cs_hook=' + marker):
            self.backend.hooks[60] = {'id': 60, 'name': 'web', 'active': True,
                'events': relay.EVENTS, 'config': {'url': changed}}
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    RuntimeError, 'Unexpected webhook host|destination drift'):
                relay.reconcile('https://new.trycloudflare.com')
        self.assertFalse(any(method == 'PATCH' for method, _ in self.backend.calls))

    def test_uncertain_patch_readback_recovers_without_repeating_it(self):
        self.assertEqual(relay.reconcile('https://one.trycloudflare.com'), 900)
        prior = json.loads(self.binding.read_text())['target']
        write = self.backend.api
        def lost_patch(method, path, data=None):
            result = write(method, path, data)
            if method == 'PATCH':
                raise RuntimeError('lost PATCH response')
            return result
        with patch.object(relay, 'api', side_effect=lost_patch):
            with self.assertRaisesRegex(RuntimeError, 'lost PATCH'):
                relay.reconcile('https://two.trycloudflare.com')
        self.assertEqual(json.loads(self.binding.read_text())['target'], prior)
        self.assertTrue(self.update_intent.exists())
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'PATCH']), 1)
        # Independently observed new URL reconciles the exact uncertain PATCH.
        # A *different* current tunnel may then issue a new, fenced update.
        self.assertEqual(relay.reconcile('https://three.trycloudflare.com'), 900)
        self.assertFalse(self.update_intent.exists())
        self.assertEqual(json.loads(self.binding.read_text())['target'],
                         self.backend.hooks[900]['config']['url'])
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'PATCH']), 2)

    def test_uncertain_patch_with_no_effect_is_not_blindly_retried(self):
        relay.reconcile('https://one.trycloudflare.com')
        def missing_response(method, path, data=None):
            if method == 'PATCH':
                raise RuntimeError('PATCH outcome unavailable')
            return self.backend.api(method, path, data)
        with patch.object(relay, 'api', side_effect=missing_response):
            with self.assertRaisesRegex(RuntimeError, 'PATCH outcome unavailable'):
                relay.reconcile('https://two.trycloudflare.com')
        self.assertTrue(self.update_intent.exists())
        with self.assertRaisesRegex(RuntimeError, 'Uncertain webhook PATCH'):
            relay.reconcile('https://three.trycloudflare.com')
        self.assertEqual(len([x for x in self.backend.calls if x[0] == 'PATCH']), 0)

    def test_owner_binding_rejects_symlink(self):
        self.state.write_text('60')
        self.backend.hooks[60] = {'id': 60, 'name': 'web', 'active': True,
            'events': relay.EVENTS, 'config': {'url': 'https://old.trycloudflare.com/github'}}
        target = self.home / 'victim'
        target.write_text('private')
        self.binding.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe webhook binding symlink'):
            relay.reconcile('https://new.trycloudflare.com')
        self.assertEqual(target.read_text(), 'private')

    def test_secret_rotation_during_uncertain_create_holds(self):
        def fail_id_write(path, content):
            if path == self.state:
                raise OSError('crash')
            return relay_write(path, content)
        relay_write = relay.durable_write
        with patch.object(relay, 'durable_write', side_effect=fail_id_write):
            with self.assertRaises(OSError):
                relay.reconcile('https://old.trycloudflare.com')
        self.secret_file.write_text('x' * 40)
        with self.assertRaisesRegex(RuntimeError, 'secret rotated'):
            relay.reconcile('https://new.trycloudflare.com')

    def test_symlinked_state_is_rejected(self):
        victim = self.home / 'victim'
        victim.write_text('unowned')
        self.state.symlink_to(victim)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe webhook state symlink'):
            relay.reconcile('https://new.trycloudflare.com')
        self.assertEqual(victim.read_text(), 'unowned')


class RouteAcceptanceTests(unittest.TestCase):
    def test_legacy_and_nonce_marked_routes_keep_hmac_guard(self):
        import hmac
        import hashlib
        from types import SimpleNamespace
        import importlib.util

        server_file = SCRIPT.with_name('ci-webhook-server.py')
        server_spec = importlib.util.spec_from_file_location('ci_webhook_server', server_file)
        server = importlib.util.module_from_spec(server_spec)
        server_spec.loader.exec_module(server)
        payload = json.dumps({'repository': {'full_name': 'AyobamiH/clawsweeper'},
                              'after': 'a' * 40}).encode()
        secret = b'p' * 40
        signature = 'sha256=' + hmac.new(secret, payload, hashlib.sha256).hexdigest()

        def request(path, valid_signature):
            handler = object.__new__(server.Handler)
            handler.path = path
            handler.headers = {'Content-Length': str(len(payload)), 'X-GitHub-Event': 'push',
                               'X-GitHub-Delivery': '0f0f0f0f-1234-4234-bbbb-abcdefabcdef',
                               'X-Hub-Signature-256': signature if valid_signature else 'sha256=' + '0' * 64}
            handler.rfile = io.BytesIO(payload)
            replies = []
            handler.send_error = lambda code: replies.append(('error', code))
            handler.send_response = lambda code: replies.append(('response', code))
            handler.end_headers = lambda: None
            with tempfile.TemporaryDirectory() as temp_ledger:
                handler.server = SimpleNamespace(secret=secret,
                    ledger=server.ledger_module.DeliveryLedger(pathlib.Path(temp_ledger)/'state'))
                with patch.object(server.subprocess, 'run',
                                  return_value=SimpleNamespace(returncode=0)) as run:
                    handler.do_POST()
                return replies, run.called

        for path in ('/github', '/github?cs_hook=' + 'b' * 48):
            self.assertEqual(request(path, True), ([('response', 202)], True))
            self.assertEqual(request(path, False), ([('error', 403)], False))
        for path in ('/github?other=x', '/github?cs_hook=123', '/github/malicious',
                     '/github?cs_hook=' + 'b' * 48 + '&extra=1'):
            self.assertEqual(request(path, True), ([('error', 404)], False))


if __name__ == '__main__':
    unittest.main()
