import concurrent.futures
from http.client import HTTPConnection
import hashlib
import hmac
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
        self.payload=b'{"repository":{"full_name":"AyobamiH/clawsweeper"},"after":"'+b'a'*40+b'"}'
        self.ledger = ledger_module.DeliveryLedger(Path(self.root.name)/'ledger')
        self.server = server_module.ThreadingHTTPServer(('127.0.0.1',0),server_module.Handler)
        self.server.secret=self.secret
        self.server.ledger=self.ledger
        thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(lambda:(self.server.shutdown(),thread.join(timeout=3),self.server.server_close()))
        self.port=self.server.server_port

    def request(self, delivery=UUID, payload=None, signature=None):
        body=self.payload if payload is None else payload
        signature=signature or 'sha256='+hmac.new(self.secret,body,hashlib.sha256).hexdigest()
        con=HTTPConnection('127.0.0.1',self.port,timeout=3)
        con.request('POST','/github',body=body,headers={'X-GitHub-Event':'push','X-GitHub-Delivery':delivery,
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

if __name__=='__main__':unittest.main()
