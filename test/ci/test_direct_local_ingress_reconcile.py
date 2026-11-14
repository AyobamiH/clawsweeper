"""No-provider source-only proof that the existing fleet drains its ingress."""
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[2]
SCRIPT_DIR = HERE / "scripts" / "ci"
spec = importlib.util.spec_from_file_location(
    "direct_local_ingress_reconcile_test", SCRIPT_DIR / "direct_local_ingress_reconcile.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
spec = importlib.util.spec_from_file_location(
    "direct_local_release_test_ingress", SCRIPT_DIR / "direct_local_receiver_integration.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
spec = importlib.util.spec_from_file_location(
    "ci_delivery_ledger_test_ingress", HERE / "scripts" / "ci-webhook-deliveries.py")
ledger_type = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger_type)

UUID = "62b2ed01-9726-48fc-a119-7a50cd3bcc29"


class ExistingFleetIngressTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.checkout = self.root / "source"
        self.checkout.mkdir()
        source = self.checkout / "scripts"
        source.mkdir()
        (source / "ci-webhook-deliveries.py").write_bytes(
            (HERE / "scripts" / "ci-webhook-deliveries.py").read_bytes())
        for name in release.SOURCE_FILES:
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# pinned fixture\n")
        subprocess.run(["git", "-C", str(self.checkout), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.checkout), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.checkout), "-c", "commit.gpgsign=false",
                        "-c", "user.name=Fixture", "-c", "user.email=test@example.invalid",
                        "commit", "-qm", "source"], check=True)
        self.fleet = self.root / "fleet"
        self.fleet.mkdir()
        (self.fleet / "control.lock").touch(mode=0o600)
        self.release_file = self.root / "release.json"
        cfg = {"schema": release.SCHEMA, "repo": "AyobamiH/clawsweeper",
               "checkout": str(self.checkout), "fleet_root": str(self.fleet),
               "commit": subprocess.check_output([
                   "git", "-C", str(self.checkout), "rev-parse", "HEAD"],
                   text=True).strip(),
               "sha256": {name: hashlib.sha256((self.checkout / name).read_bytes()).hexdigest()
                          for name in release.SOURCE_FILES}}
        self.release_file.write_text(json.dumps(cfg))
        self.release_file.chmod(0o600)
        self.ledger_dir = self.fleet / "webhook-deliveries"
        self.ledger = ledger_type.DeliveryLedger(self.ledger_dir)
        self.secret = b"s" * 40
        (self.fleet / "secrets").mkdir(mode=0o700)
        self.secret_file = self.fleet / "secrets" / "webhook-hmac"
        self.secret_file.write_bytes(self.secret)
        self.secret_file.chmod(0o600)
        self.body = b'{"ref":"refs/heads/main","after":"' + b"a" * 40 + b'"}'
        self.signature = "sha256=" + hmac.new(self.secret, self.body, hashlib.sha256).hexdigest()

    def stage(self):
        self.assertEqual(self.ledger.claim(
            UUID, "push", self.body, ordinary_signature=self.signature,
            ordinary_secret=self.secret), "claimed")
        self.ledger.accept(UUID, "push", self.body)

    def drain(self, claim):
        return bridge.reconcile_existing_fleet_ingress(
            ledger_dir=self.ledger_dir, release_file=self.release_file,
            secret_file=self.secret_file, claim=claim)

    @staticmethod
    def accepted(**kwargs):
        return {"fresh_provider_source_verified": True,
                "suite": "linux-node24", "admission": "queued",
                "job_executed": False, "github_status_published": False}

    def test_idempotent_verified_claim_consumes_exact_envelope(self):
        self.stage()
        called = []
        def fake(**kw):
            called.append(kw)
            return self.accepted()
        receipt = self.drain(fake)
        self.assertEqual(receipt["consumed"], 1)
        self.assertFalse(receipt["job_execution_proved"])
        self.assertEqual(len(called), 1)
        self.assertEqual(called[0]["body"], self.body)
        self.assertEqual(called[0]["secret"], self.secret)
        self.assertEqual(self.ledger.staged_ordinary(), [])
        self.assertEqual(self.drain(fake)["inspected"], 0)
        self.assertEqual(len(called), 1)

    def test_uncertain_queue_claim_survives_and_retry_uses_same_delivery(self):
        self.stage()
        def uncertain(**kw):
            raise RuntimeError("uncertain queue response")
        self.assertEqual(self.drain(uncertain)["held"], 1)
        self.assertEqual(len(self.ledger.staged_ordinary()), 1)
        result = self.drain(lambda **kw: {**self.accepted(),
                                         "admission": "already_admitted"})
        self.assertEqual(result["consumed"], 1)
        self.assertEqual(self.ledger.staged_ordinary(), [])

    def test_forged_queue_proof_never_consumes(self):
        self.stage()
        for forged in (
            {"fresh_provider_source_verified": False,
             "suite": "linux-node24", "admission": "queued",
             "job_executed": False, "github_status_published": False},
            {**self.accepted(), "job_executed": True},
            {**self.accepted(), "github_status_published": True},
            {**self.accepted(), "suite": "privileged"},
        ):
            self.assertEqual(self.drain(lambda **kw: forged)["held"], 1)
            self.assertEqual(len(self.ledger.staged_ordinary()), 1)

    def test_missing_secret_and_dirty_source_fail_before_any_claim(self):
        self.stage()
        calls = []
        def fn(**kw):
            calls.append(kw)
            return self.accepted()
        self.secret_file.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "secret_permissions"):
            self.drain(fn)
        self.secret_file.chmod(0o600)
        p = self.checkout / "scripts/ci-webhook-deliveries.py"
        p.write_text("# unreviewed change")
        with self.assertRaisesRegex(RuntimeError, "source_not_exact_clean_head"):
            self.drain(fn)
        self.assertEqual(calls, [])
        self.assertEqual(len(self.ledger.staged_ordinary()), 1)

    def test_foreign_ledger_and_missing_existing_file_cannot_create_queue(self):
        self.stage()
        self.assertEqual(len(self.ledger.staged_ordinary()), 1)
        with self.assertRaisesRegex(RuntimeError, "unrecognised_existing_fleet_ingress_paths"):
            bridge.reconcile_existing_fleet_ingress(
                ledger_dir=self.root / "foreign", release_file=self.release_file,
                secret_file=self.secret_file, claim=self.accepted)
        self.assertFalse((self.root / "foreign").exists())
        (self.ledger_dir / "deliveries.sqlite3").rename(
            self.ledger_dir / "preserved-ledger.sqlite3")
        with self.assertRaisesRegex(RuntimeError, "missing_existing_webhook_ingress_ledger"):
            self.drain(self.accepted)
        self.assertFalse((self.ledger_dir / "deliveries.sqlite3").exists())

    def test_canonical_fleet_lock_must_not_be_nested_in_the_same_cycle(self):
        self.stage()
        lock_path = self.fleet / "control.lock"
        calls = []
        def fake_claim(**kwargs):
            calls.append(kwargs)
            return self.accepted()
        fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(
                RuntimeError, "ingress_must_run_before_canonical_fleet_lock"
            ):
                self.drain(fake_claim)
            self.assertEqual(calls, [])
            self.assertEqual(len(self.ledger.staged_ordinary()), 1)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        result = self.drain(fake_claim)
        self.assertEqual(result["consumed"], 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.ledger.staged_ordinary(), [])

    def test_absent_or_symlinked_fleet_lock_holds_before_queue_claim(self):
        self.stage()
        path = self.fleet / "control.lock"
        seen = []
        path.unlink()
        with self.assertRaisesRegex(RuntimeError, "missing_or_untrusted_canonical_fleet_lock"):
            self.drain(lambda **kw: seen.append(kw))
        self.assertEqual(seen, [])
        target = self.root / "foreign-lock"
        target.write_text("")
        path.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "missing_or_untrusted_canonical_fleet_lock"):
            self.drain(lambda **kw: seen.append(kw))
        self.assertEqual(seen, [])
        self.assertEqual(len(self.ledger.staged_ordinary()), 1)

    def test_batch_limit_must_be_small_and_no_separate_scheduler(self):
        with self.assertRaisesRegex(RuntimeError, "reconciliation_batch"):
            bridge.reconcile_existing_fleet_ingress(
                ledger_dir=self.ledger_dir, release_file=self.release_file,
                secret_file=self.secret_file, batch_limit=128, claim=self.accepted)
        self.assertFalse(hasattr(bridge, "main"))
