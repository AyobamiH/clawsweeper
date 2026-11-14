import concurrent.futures
from http.client import HTTPConnection
import hashlib
import hmac
import sqlite3
import importlib.util
from pathlib import Path
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[1] / 'scripts'

def import_file(name, filename):
    spec = importlib.util.spec_from_file_location(name, SOURCE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

ledger_module = import_file('ci_webhook_delivery_ledger_tests', 'ci-webhook-deliveries.py')
server_module = import_file('ci_webhook_server_tests', 'ci-webhook-server.py')
UUID = '62b2ed01-9726-48fc-a119-7a50cd3bcc29'


class DeliveryLedgerTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name) / 'private'
        self.ledger = ledger_module.DeliveryLedger(self.path)

    def test_durable_replay_rejected_after_new_database_instance(self):
        self.assertEqual(self.ledger.claim(UUID, 'push', b'{}', now=10), 'claimed')
        self.ledger.accept(UUID, 'push', b'{}', now=11)
        self.assertEqual(ledger_module.DeliveryLedger(self.path).claim(UUID, 'push', b'{}', now=12), 'duplicate')
        self.assertEqual(self.ledger.claim(UUID, 'push', b'changed', now=12), 'mismatch')
        self.assertEqual(self.ledger.claim('invalid', 'push', b'{}', now=12), 'invalid')
        self.assertEqual(self.ledger.claim(UUID.upper(), 'push', b'{}', now=12), 'duplicate')

    def test_pending_interruption_survives_restart_and_never_expires(self):
        self.assertEqual(self.ledger.claim(UUID, 'push', b'body', now=1), 'claimed')
        new = ledger_module.DeliveryLedger(self.path)
        self.assertEqual(new.claim(UUID, 'push', b'body', now=ledger_module.RETENTION_SECONDS * 10), 'uncertain')
        self.assertEqual(new.claim(UUID, 'issue_comment', b'body', now=100), 'mismatch')

    def test_only_confirmed_old_records_expire(self):
        self.assertEqual(self.ledger.claim(UUID, 'push', b'one', now=1), 'claimed')
        self.ledger.accept(UUID, 'push', b'one', now=2)
        self.assertEqual(self.ledger.claim(UUID, 'push', b'one', now=3), 'duplicate')
        self.assertEqual(self.ledger.claim(UUID, 'push', b'one', now=ledger_module.RETENTION_SECONDS + 4), 'claimed')

    def test_double_concurrent_claim_has_single_effect_authority(self):
        barrier=threading.Barrier(2)
        def submit(_):
            barrier.wait()
            return self.ledger.claim(UUID,'push',b'payload')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit,range(2)))
        self.assertEqual(sorted(results), ['claimed','uncertain'])

    def test_refuses_world_readable_state_dir_and_database(self):
        os.chmod(self.path,0o755)
        with self.assertRaisesRegex(RuntimeError,'unsafe_delivery_state_permissions'):
            ledger_module.DeliveryLedger(self.path)
        os.chmod(self.path,0o700)
        os.chmod(self.path/'deliveries.sqlite3',0o644)
        with self.assertRaisesRegex(RuntimeError,'unsafe_delivery_database_permissions'):
            self.ledger.claim(UUID,'push',b'payload')

    def test_schema_upgrade_preserves_legacy_claims(self):
        old = Path(self.root.name) / 'old-delivery-ledger'
        old.mkdir(mode=0o700)
        db_path = old / 'deliveries.sqlite3'
        with sqlite3.connect(db_path) as db:
            db.execute("""CREATE TABLE deliveries (
                id TEXT PRIMARY KEY NOT NULL, fingerprint TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','accepted')),
                created_at INTEGER NOT NULL, accepted_at INTEGER)""")
            body = b'old'
            db.execute(
                'INSERT INTO deliveries VALUES (?,?,?,?,?)',
                (UUID, ledger_module.DeliveryLedger.fingerprint(
                    'push', body), 'accepted', 10, 11))
        db_path.chmod(0o600)
        migrated = ledger_module.DeliveryLedger(old)
        self.assertEqual(migrated.claim(UUID, 'push', b'old', now=12), 'duplicate')
        self.assertEqual(migrated.claim(UUID, 'push', b'changed', now=12), 'mismatch')
        self.assertEqual(migrated.staged_ordinary(), [])
        with sqlite3.connect(db_path) as db:
            row = db.execute(
                'SELECT id,state,ordinary_state FROM deliveries'
            ).fetchone()
        self.assertEqual(row, (UUID, 'accepted', 'none'))

    def test_staged_ordinary_delivery_retained_after_receiver_restart(self):
        body = b'{"repository":{"full_name":"AyobamiH/clawsweeper"},' + (
            b'"ref":"refs/heads/main","after":"' + b'a' * 40 + b'"}')
        secret = b's' * 40
        signature = 'sha256=' + hmac.new(secret, body, hashlib.sha256).hexdigest()
        self.assertEqual(self.ledger.claim(
            UUID, 'push', body, ordinary_signature=signature,
            ordinary_secret=secret, now=1), 'claimed')
        self.ledger.accept(UUID, 'push', body, now=2)
        restarted = ledger_module.DeliveryLedger(self.path)
        self.assertEqual(restarted.claim(
            UUID, 'push', body, ordinary_signature=signature,
            ordinary_secret=secret, now=ledger_module.RETENTION_SECONDS * 10),
            'duplicate')
        staged = restarted.staged_ordinary()
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0]['delivery_id'], UUID)
        self.assertEqual(staged[0]['event'], 'push')
        self.assertEqual(staged[0]['body'], body)
        self.assertEqual(staged[0]['signature'], signature)
        self.assertFalse(restarted.consume_ordinary(UUID, '0' * 64))
        self.assertTrue(restarted.consume_ordinary(UUID, staged[0]['fingerprint']))
        self.assertFalse(restarted.consume_ordinary(UUID, staged[0]['fingerprint']))
        self.assertEqual(restarted.staged_ordinary(), [])
        with sqlite3.connect(restarted.db) as db:
            state, payload, saved_signature = db.execute(
                'SELECT ordinary_state, ordinary_body, ordinary_signature '
                'FROM deliveries WHERE id=?', (UUID,)).fetchone()
        self.assertEqual(state, 'consumed')
        self.assertIsNone(payload)
        self.assertIsNone(saved_signature)

    def test_bad_hmac_or_wrong_event_cannot_persist_ordinary_payload(self):
        secret = b's' * 40
        body = b'{"repository":{"full_name":"AyobamiH/clawsweeper"}}'
        sig = 'sha256=' + hmac.new(secret, body, hashlib.sha256).hexdigest()
        self.assertEqual(self.ledger.claim(
            UUID, 'push', body, ordinary_signature='sha256=' + '0' * 64,
            ordinary_secret=secret), 'invalid')
        self.assertEqual(self.ledger.claim(
            UUID, 'issues', body, ordinary_signature=sig,
            ordinary_secret=secret), 'invalid')
        self.assertEqual(self.ledger.claim(
            UUID, 'push', body + b' ', ordinary_signature=sig,
            ordinary_secret=secret), 'invalid')
        self.assertEqual(self.ledger.claim(
            UUID, 'push', b'x' * (ledger_module.MAX_ORDINARY_BYTES + 1),
            ordinary_signature=sig, ordinary_secret=secret), 'invalid')
        self.assertEqual(self.ledger.staged_ordinary(), [])
        with sqlite3.connect(self.ledger.db) as db:
            self.assertEqual(db.execute(
                'SELECT count(*) FROM deliveries').fetchone()[0], 0)

    def test_staged_ordinary_capacity_holds_without_dropping_existing(self):
        secret = b's' * 40
        body = b'{}'
        sig = 'sha256=' + hmac.new(secret, body, hashlib.sha256).hexdigest()
        with patch.object(ledger_module, 'MAX_STAGED_ORDINARY', 1):
            self.assertEqual(self.ledger.claim(
                UUID, 'push', body, ordinary_signature=sig,
                ordinary_secret=secret), 'claimed')
            other = '72b2ed01-9726-48fc-a119-7a50cd3bcc29'
            self.assertEqual(self.ledger.claim(
                other, 'push', body, ordinary_signature=sig,
                ordinary_secret=secret), 'ordinary_capacity_held')
        self.assertEqual(len(self.ledger.staged_ordinary()), 1)
        self.assertEqual(self.ledger.claim(UUID, 'push', b'changed'), 'mismatch')
        with self.assertRaisesRegex(RuntimeError, 'unsafe_ordinary_ingress_limit'):
            self.ledger.staged_ordinary(1000)

    def test_legacy_delivery_does_not_create_ordinary_payload(self):
        self.assertEqual(self.ledger.claim(UUID, 'push', b'{}'), 'claimed')
        self.ledger.accept(UUID, 'push', b'{}')
        self.assertEqual(self.ledger.staged_ordinary(), [])
        with sqlite3.connect(self.ledger.db) as db:
            state, body = db.execute(
                'SELECT ordinary_state,ordinary_body FROM deliveries '
                'WHERE id=?', (UUID,)).fetchone()
        self.assertEqual((state, body), ('none', None))

    def test_refuses_symlinked_database(self):
        external=Path(self.root.name)/'external'
        external.write_text('do not write')
        (self.path/'deliveries.sqlite3').unlink()
        (self.path/'deliveries.sqlite3').symlink_to(external)
        with self.assertRaisesRegex(RuntimeError,'unsafe_delivery_database'):
            self.ledger.claim(UUID,'push',b'payload')
        self.assertEqual(external.read_text(),'do not write')


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.secret=b's'*40
        self.payload=b'{"repository":{"full_name":"AyobamiH/clawsweeper"},"ref":"refs/heads/main","forced":false,"deleted":false,"after":"'+b'a'*40+b'"}'
        self.ledger = ledger_module.DeliveryLedger(Path(self.root.name)/'ledger')
        self.server = server_module.ThreadingHTTPServer(('127.0.0.1',0),server_module.Handler)
        self.server.secret=self.secret
        self.server.ledger=self.ledger
        thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(lambda:(self.server.shutdown(),thread.join(timeout=3),self.server.server_close()))
        self.port=self.server.server_port

    def request(self, delivery=UUID, payload=None, signature=None, event='push'):
        body=self.payload if payload is None else payload
        signature=signature or 'sha256='+hmac.new(self.secret,body,hashlib.sha256).hexdigest()
        con=HTTPConnection('127.0.0.1',self.port,timeout=3)
        con.request('POST','/github',body=body,headers={'X-GitHub-Event':event,'X-GitHub-Delivery':delivery,
                         'X-Hub-Signature-256':signature,'Content-Type':'application/json'})
        out=con.getresponse()
        status=out.status
        out.read();con.close()
        return status

    def test_exact_redelivery_never_wakes_twice(self):
        with patch.object(server_module.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(self.request(),202)
            self.assertEqual(self.request(),200)
            self.assertEqual(run.call_count,1)
            self.server.ledger=ledger_module.DeliveryLedger(self.ledger.directory)
            self.assertEqual(self.request(),200)
            self.assertEqual(run.call_count,1)

    def test_simultaneous_delivery_wakes_at_most_once(self):
        def wake(*args,**kwargs):
            time.sleep(.15)
            return SimpleNamespace(returncode=0)
        with patch.object(server_module.subprocess,'run',side_effect=wake) as run:
            barrier=threading.Barrier(2)
            def send(_):
                barrier.wait()
                return self.request()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                statuses=list(pool.map(send,range(2)))
            self.assertEqual(sorted(statuses),[202,503])
            self.assertEqual(run.call_count,1)

    def test_uncertain_start_does_not_repeat_wake(self):
        with patch.object(server_module.subprocess,'run',side_effect=TimeoutError('unknown')) as run:
            self.assertEqual(self.request(),503)
            self.assertEqual(self.request(),503)
            self.assertEqual(run.call_count,1)
        self.server.ledger=ledger_module.DeliveryLedger(self.ledger.directory)
        with patch.object(server_module.subprocess,'run') as run:
            self.assertEqual(self.request(),503)
            run.assert_not_called()

    def test_bad_signature_changed_payload_and_missing_delivery_refuse(self):
        with patch.object(server_module.subprocess,'run') as run:
            self.assertEqual(self.request(signature='sha256='+'0'*64),403)
            self.assertEqual(self.request(delivery=''),403)
            stale_signature='sha256='+hmac.new(self.secret,self.payload,hashlib.sha256).hexdigest()
            self.assertEqual(self.request(payload=self.payload+b' ',signature=stale_signature),403)
            run.assert_not_called()

    def test_persistence_failure_cannot_wake(self):
        with patch.object(self.ledger,'claim',side_effect=OSError('disk denied')):
            with patch.object(server_module.subprocess,'run') as run:
                self.assertEqual(self.request(),503)
                run.assert_not_called()

    def test_failed_post_accept_transaction_holds_future_replays(self):
        with patch.object(self.ledger,'accept',side_effect=OSError('disk full')):
            with patch.object(server_module.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
                self.assertEqual(self.request(),503)
                self.assertEqual(self.request(),503)
                self.assertEqual(run.call_count,1)

    def test_released_ingress_stages_before_wake_without_fleet_writes(self):
        calls = []
        original = self.ledger.claim
        def ledger_claim(*args, **kwargs):
            calls.append('ledger')
            self.assertEqual(kwargs['ordinary_secret'], self.secret)
            self.assertEqual(kwargs['ordinary_signature'][:7], 'sha256=')
            return original(*args, **kwargs)
        def verify():
            calls.append('release')
            return True
        def wake(*args, **kwargs):
            calls.append('wake')
            return SimpleNamespace(returncode=0)
        self.server.direct_local_ingress_verify = verify
        with patch.object(self.ledger,'claim',side_effect=ledger_claim):
            with patch.object(server_module.subprocess,'run',side_effect=wake):
                self.assertEqual(self.request(),202)
        self.assertEqual(calls,['release','ledger','wake'])
        staged = ledger_module.DeliveryLedger(self.ledger.directory).staged_ordinary()
        self.assertEqual(len(staged),1)
        self.assertEqual(staged[0]['delivery_id'],UUID)
        self.assertEqual(staged[0]['body'],self.payload)
        self.assertEqual(staged[0]['event'],'push')

    def test_malformed_delivery_never_reaches_ingress_or_queue(self):
        self.server.direct_local_ingress_verify = lambda: (_ for _ in ()).throw(
            AssertionError('malformed webhook identifier reached ingress'))
        with patch.object(server_module.subprocess,'run') as wake:
            self.assertEqual(self.request(delivery='-' * 36),403)
            wake.assert_not_called()

    def test_revoked_ingress_release_never_marks_webhook_accepted_or_wakes(self):
        self.server.direct_local_ingress_verify = lambda: (_ for _ in ()).throw(
            RuntimeError('stale protected source'))
        with patch.object(self.ledger,'claim') as ledger_claim:
            with patch.object(server_module.subprocess,'run') as wake:
                self.assertEqual(self.request(),503)
                ledger_claim.assert_not_called()
                wake.assert_not_called()

    def test_feature_push_keeps_legacy_wake_without_staged_ordinary(self):
        self.server.direct_local_ingress_verify = lambda: (_ for _ in ()).throw(
            AssertionError('feature push must never stage ordinary ingress'))
        event = (b'{"repository":{"full_name":"AyobamiH/clawsweeper"},'
                 b'"ref":"refs/heads/feature-safe","after":"'+b'b'*40+b'"}')
        with patch.object(server_module.subprocess, 'run',
                          return_value=SimpleNamespace(returncode=0)) as wake:
            self.assertEqual(self.request(payload=event), 202)
            wake.assert_called_once()
        self.assertEqual(self.ledger.staged_ordinary(),[])

    def test_draft_or_fork_pr_keeps_legacy_wake_without_ordinary_ingress(self):
        self.server.direct_local_ingress_verify = lambda: (_ for _ in ()).throw(
            AssertionError('ineligible PR must never enter ordinary ingress'))
        for payload, delivery in [
            ({'draft': True, 'user': {'login': 'AyobamiH'},
              'head': {'repo': {'full_name': 'AyobamiH/clawsweeper'}},
              'base': {'ref': 'main'}},
             '72b2ed01-9726-48fc-a119-7a50cd3bcc29'),
            ({'draft': False, 'user': {'login': 'another-owner'},
              'head': {'repo': {'full_name': 'another-owner/clawsweeper'}},
              'base': {'ref': 'main'}},
             '82b2ed01-9726-48fc-a119-7a50cd3bcc29'),
        ]:
            import json
            body = json.dumps({
                'repository': {'full_name': 'AyobamiH/clawsweeper'},
                'action': 'opened', 'pull_request': payload,
            }).encode()
            with patch.object(server_module.subprocess, 'run',
                              return_value=SimpleNamespace(returncode=0)) as wake:
                self.assertEqual(self.request(
                    delivery=delivery, payload=body, event='pull_request'), 202)
                wake.assert_called_once()
        self.assertEqual(self.ledger.staged_ordinary(), [])

    def test_closed_pr_still_rejected_by_existing_authorisation(self):
        self.server.direct_local_ingress_verify = lambda: (_ for _ in ()).throw(
            AssertionError('unsupported event must not enter new ingress'))
        import json
        pr = {'number': 77, 'state': 'closed', 'draft': False,
              'user': {'login': 'AyobamiH'},
              'head': {'sha': 'a'*40,
                       'repo': {'full_name': 'AyobamiH/clawsweeper'}},
              'base': {'ref': 'main',
                       'repo': {'full_name': 'AyobamiH/clawsweeper'}}}
        body = json.dumps({'repository': {'full_name': 'AyobamiH/clawsweeper'},
                           'action': 'closed', 'pull_request': pr}).encode()
        with patch.object(server_module.subprocess, 'run') as wake:
            self.assertEqual(self.request(delivery='a2b2ed01-9726-48fc-a119-7a50cd3bcc29',
                                          payload=body, event='pull_request'), 403)
            wake.assert_not_called()
        self.assertEqual(self.ledger.staged_ordinary(), [])

    def test_incomplete_source_identity_stays_fail_closed(self):
        self.server.direct_local_ingress_verify = lambda: True
        event = (b'{"repository":{"full_name":"AyobamiH/clawsweeper"},'
                 b'"after":"'+b'b'*40+b'"}')
        with patch.object(self.ledger, 'claim') as claim:
            with patch.object(server_module.subprocess, 'run') as wake:
                self.assertEqual(self.request(payload=event), 403)
                claim.assert_not_called()
                wake.assert_not_called()

    def test_forced_main_push_still_fails_closed_before_ingress(self):
        self.server.direct_local_ingress_verify = lambda: True
        event = (b'{"repository":{"full_name":"AyobamiH/clawsweeper"},'
                 b'"ref":"refs/heads/main","forced":true,"after":"'+b'b'*40+b'"}')
        with patch.object(self.ledger, 'claim') as claim:
            with patch.object(server_module.subprocess, 'run') as wake:
                self.assertEqual(self.request(payload=event), 403)
                claim.assert_not_called()
                wake.assert_not_called()

    def test_ordinary_ingress_survives_uncertain_wake_without_replay(self):
        calls=[]
        def verify():
            calls.append('verify')
            return True
        self.server.direct_local_ingress_verify=verify
        with patch.object(server_module.subprocess,'run',side_effect=TimeoutError('wake uncertain')) as wake:
            self.assertEqual(self.request(),503)
            self.assertEqual(self.request(),503)
            self.assertEqual(wake.call_count,1)
        self.assertEqual(calls,['verify','verify'])
        staged=ledger_module.DeliveryLedger(self.ledger.directory).staged_ordinary()
        self.assertEqual(len(staged),1)
        self.assertEqual(staged[0]['delivery_id'],UUID)

    def test_invalid_ingress_release_refuses_acceptance(self):
        self.server.direct_local_ingress_verify = lambda: False
        with patch.object(server_module.subprocess,'run') as wake:
            self.assertEqual(self.request(),503)
            wake.assert_not_called()

    def test_duplicate_webhook_keys_cannot_stage_ingress(self):
        self.server.direct_local_ingress_verify=lambda:True
        event=(b'{"repository":{"full_name":"AyobamiH/clawsweeper"},'
               b'"repository":{"full_name":"AyobamiH/clawsweeper"},'
               b'"ref":"refs/heads/main","deleted":false,"forced":false,'
               b'"after":"'+b'a'*40+b'"}')
        with patch.object(server_module.subprocess,'run') as wake:
            self.assertEqual(self.request(payload=event),403)
            wake.assert_not_called()
        self.assertEqual(self.ledger.staged_ordinary(),[])

    def test_other_enrolled_repositories_use_existing_path(self):
        self.server.direct_local_ingress_verify = lambda: (_ for _ in ()).throw(
            AssertionError('wrong repository direct-local ingress'))
        other = self.payload.replace(b'AyobamiH/clawsweeper',b'AyobamiH/opstruth')
        with patch.object(server_module.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as wake:
            self.assertEqual(self.request(payload=other),202)
            wake.assert_called_once()

if __name__=='__main__':unittest.main()
