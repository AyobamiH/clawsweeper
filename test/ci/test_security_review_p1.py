"""Adversarial regressions for the independently reproduced ClawSweeper P1s.

All GitHub, Docker, systemd, and provider operations are mocked. No live effects.
"""
import importlib.util
import json
import io
import os
import sqlite3
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import self_hosted_executor as jit

spec = importlib.util.spec_from_file_location("ci_webhook_review", ROOT / "scripts/ci-webhook-relay.py")
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class WebhookContractReviewTests(unittest.TestCase):
    def test_drifted_json_or_tls_contract_refuses_noop(self):
        target = "https://review-only.trycloudflare.com/github"
        for config in (
            {"url": target, "content_type": "form", "insecure_ssl": "0"},
            {"url": target, "content_type": "json", "insecure_ssl": "1"},
            {"url": target, "content_type": "form", "insecure_ssl": "1"},
            {"url": target, "content_type": "json"},
            {"url": target, "insecure_ssl": "0"},
        ):
            with self.subTest(config=config), tempfile.TemporaryDirectory() as td:
                paths = {name: Path(td) / name for name in
                         ("SECRET", "STATE", "BINDING", "UPDATE_INTENT", "INTENT", "LOCK")}
                with patch.multiple(relay, **paths):
                    relay.SECRET.write_text("audit-secret-with-more-than-thirty-two-characters")
                    relay.STATE.write_text("42")
                    relay.BINDING.write_text(json.dumps(relay.bound_entry(42, target)))
                    relay.BINDING.chmod(0o600)
                    hook = {"id": 42, "name": "web", "active": True,
                            "events": ["push", "pull_request"], "config": config}
                    requests = []
                    def fake_api(method, path, data=None):
                        requests.append((method, path))
                        if method == "GET" and path.startswith("hooks?"):
                            return [hook]
                        if method == "GET" and path == "hooks/42":
                            return hook
                        self.fail("Unexpected external write attempted")
                    with patch.object(relay, "api", side_effect=fake_api):
                        with self.assertRaisesRegex(RuntimeError, "JSON/TLS contract"):
                            relay.reconcile("https://review-only.trycloudflare.com")
                    self.assertTrue(requests)
                    self.assertEqual({method for method, _ in requests}, {"GET"})

    def test_valid_remote_contract_is_accepted(self):
        url = "https://review-only.trycloudflare.com/github"
        hook = {"id": 42, "name": "web", "active": True,
                "events": ["push", "pull_request"],
                "config": {"url": url, "content_type": "json", "insecure_ssl": "0"}}
        with patch.object(relay, "api", return_value=hook):
            self.assertEqual(relay.verify_hook(42, url), hook)



class WebhookOwnershipReviewTests(unittest.TestCase):
    def test_concurrent_controller_refused_during_tunnel_wait(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(relay, 'LOCK', Path(td) / 'controller.lock'):
                calls = []
                def tunnel_wait():
                    with self.assertRaisesRegex(RuntimeError, 'already running'):
                        with relay.exclusive_reconcile():
                            self.fail('Second controller acquired live first-controller lock')
                    calls.append('second_refused')
                    return 0
                fake_tunnel = SimpleNamespace(
                    stderr=None, poll=lambda: 0, wait=tunnel_wait)
                with (patch.object(relay.subprocess, 'Popen', return_value=fake_tunnel),
                      patch.object(relay, 'wait_for_tunnel_url',
                                   return_value='https://review-only.trycloudflare.com'),
                      patch.object(relay, '_reconcile_locked', return_value=42)):
                    self.assertEqual(relay.main(), 0)
                self.assertEqual(calls, ['second_refused'])

    def test_unsafe_controller_lock_refused_before_tunnel(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / 'controller.lock'
            target.write_text('')
            target.chmod(0o644)
            with (patch.object(relay, 'LOCK', target),
                  patch.object(relay.subprocess, 'Popen') as start):
                with self.assertRaisesRegex(RuntimeError, 'owner-private'):
                    relay.main()
                start.assert_not_called()
            target.unlink()
            target.symlink_to(Path(td) / 'does-not-exist')
            with (patch.object(relay, 'LOCK', target),
                  patch.object(relay.subprocess, 'Popen') as start):
                with self.assertRaisesRegex(RuntimeError, 'symlink'):
                    relay.main()
                start.assert_not_called()


class JitReceiptReviewTests(unittest.TestCase):
    def candidate(self):
        return SimpleNamespace(run_id=999601, job_id=999602, run_attempt=1,
                               sha="0" * 40, workflow=".github/workflows/ci.yml",
                               event="push", role="ops", label="audit-local-only")

    def test_keyboard_interrupt_and_system_exit_leave_held_receipts(self):
        for raised in (KeyboardInterrupt("interruption"), SystemExit("stop")):
            with self.subTest(raised=type(raised).__name__), tempfile.TemporaryDirectory() as temp:
                dest = Path(temp) / "receipts"
                with (patch.object(jit, "RECEIPTS", dest),
                      patch.object(jit, "approved_job_image", return_value=jit.IMAGE),
                      patch.object(jit, "stop_owned"),
                      patch.object(jit, "lookup_owned_runner", return_value=None),
                      patch.object(jit, "runner_absent_verified", return_value=True),
                      patch.object(jit, "gh", side_effect=raised)):
                    with self.assertRaises(type(raised)):
                        jit.runner_job(self.candidate(), {})
                receipt = json.loads((dest / "run-999601-job-999602-attempt-1" /
                                      "receipt.json").read_text())
                self.assertEqual(receipt["state"], "held")
                self.assertTrue(any("interrupted" in x for x in receipt["issues"]))
                self.assertNotIn("github_job", receipt)

    def test_incomplete_registration_response_never_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "receipts"
            with (patch.object(jit, "RECEIPTS", dest),
                  patch.object(jit, "approved_job_image", return_value=jit.IMAGE),
                  patch.object(jit, "stop_owned"),
                  patch.object(jit, "lookup_owned_runner", return_value=None),
                  patch.object(jit, "runner_absent_verified", return_value=True),
                  patch.object(jit, "gh", return_value={"runner": {"id": 42}})):
                result = jit.runner_job(self.candidate(), {})
                receipt = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(result["state"], "held")
            self.assertNotEqual(receipt["state"], "passed")
            self.assertNotIn("github_job", receipt)


class JitPersistenceBoundaryReviewTests(unittest.TestCase):
    def test_every_registration_persistence_interruption_is_nonpassing(self):
        # The initial durable intent is outside cleanup protection, but it
        # precedes any POST. All later writes are in cleanup protection.
        # A failed final pass-write must leave only a nonpassing prior state.
        original_atomic = jit.atomic
        fake_result = {
            "id": 710002, "run_id": 710001, "runner_name": "csw-ci-710001-710002-1",
            "status": "completed", "conclusion": "success",
        }
        candidate = SimpleNamespace(
            run_id=710001, job_id=710002, run_attempt=1,
            sha="0" * 40, workflow=".github/workflows/ci.yml",
            event="push", role="ops", label="audit-local-only",
        )
        for boundary in (1, 2, 3, 4):
            for interruption_class in (KeyboardInterrupt, SystemExit):
                with self.subTest(boundary=boundary, interruption=interruption_class.__name__):
                    with tempfile.TemporaryDirectory() as td:
                        receipts = Path(td) / "receipts"
                        calls = []
                        def atomic_fault(path, record):
                            if path.name == 'receipt.json':
                                calls.append(record.get('state'))
                                if len(calls) == boundary:
                                    raise interruption_class("synthetic_persistence_interruption")
                            return original_atomic(path, record)
                        def fake_gh(path, method="GET", body=None):
                            if path.endswith("/generate-jitconfig") and method == "POST":
                                return {"encoded_jit_config": "synthetic-only",
                                        "runner": {"id": 711001}}
                            if path.endswith("/jobs/710002") and method == "GET":
                                return dict(fake_result)
                            if method == "DELETE":
                                return {}
                            raise AssertionError("Unexpected mocked GitHub operation")
                        process = SimpleNamespace(
                            stdin=io.StringIO(), poll=lambda: 0,
                            wait=lambda timeout=None: 0)
                        with (patch.object(jit, "RECEIPTS", receipts),
                              patch.object(jit, "atomic", side_effect=atomic_fault),
                              patch.object(jit, "approved_job_image", return_value=jit.IMAGE),
                              patch.object(jit, "prepare_network", return_value=jit.NETWORK_IMAGE),
                              patch.object(jit.subprocess, "Popen", return_value=process),
                              patch.object(jit, "stop_owned"),
                              patch.object(jit, "lookup_owned_runner", return_value=None),
                              patch.object(jit, "runner_absent_verified", return_value=True),
                              patch.object(jit, "gh", side_effect=fake_gh)):
                            with self.assertRaises(interruption_class):
                                jit.runner_job(candidate, {})
                        record_path = (receipts / "run-710001-job-710002-attempt-1" /
                                       "receipt.json")
                        if boundary == 1:
                            self.assertFalse(record_path.exists())
                        else:
                            self.assertTrue(record_path.exists())
                            recorded = json.loads(record_path.read_text())
                            self.assertNotEqual(recorded.get('state'), 'passed')
                            if boundary in (2, 3):
                                self.assertEqual(recorded.get('state'), 'held')
                        self.assertEqual(len(calls) >= boundary, True)



class DetachedFleetReviewTests(unittest.TestCase):
    def candidate(self):
        return SimpleNamespace(role="ops")

    def evaluate(self, *, units="", jobs="", containers="", fail_command=None):
        calls = []
        def systemctl(argv, **_):
            calls.append(tuple(argv))
            if argv[:3] == ["systemctl", "--user", "is-active"]:
                return SimpleNamespace(stdout="inactive\n", returncode=3, stderr="")
            raise AssertionError("Unexpected subprocess command")
        def command(argv, **_):
            calls.append(tuple(argv))
            if fail_command and argv[:len(fail_command)] == fail_command:
                raise RuntimeError("Simulated inventory outage")
            if argv[:3] == ["systemctl", "--user", "list-units"]:
                return units
            if argv[:3] == ["systemctl", "--user", "list-jobs"]:
                return jobs
            if argv[:2] == ["docker", "ps"]:
                return containers
            if argv[:2] == ["docker", "info"]:
                return "29.0.2"
            if argv[:3] == ["docker", "image", "inspect"]:
                return jit.IMAGE
            raise AssertionError(f"Unexpected command: {argv}")
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'fleet.sqlite3'
            with sqlite3.connect(db) as c:
                c.execute("CREATE TABLE detached_leases (job_id TEXT)")
            db.chmod(0o600)
            with (patch.object(jit, 'FLEET_DB', db),
                  patch.object(jit.subprocess, "run", side_effect=systemctl),
                  patch.object(jit, "run_cli", side_effect=command),
                  patch.object(jit, "approved_job_image", return_value=jit.IMAGE),
                  patch.object(jit.shutil, "disk_usage", return_value=SimpleNamespace(free=100*1024**3))):
                result = jit.capacity(self.candidate(), {})
        return result, calls

    def test_active_detached_service_blocks_admission(self):
        with self.assertRaisesRegex(jit.AdmissionHold, "detached_ci_unit_busy"):
            self.evaluate(units="local-ci-job-123.service loaded active running testing")

    def test_transitioning_job_blocks_admission(self):
        with self.assertRaisesRegex(jit.AdmissionHold, "detached_ci_unit_transition"):
            self.evaluate(jobs="123 local-ci-job-456.service start running")

    def test_detached_container_blocks_admission(self):
        for prefix in ("local-ci-job-", "csw-ci-", "local-fleet-", "clawsweeper-ci-"):
            for state in ("running", "exited"):
                with self.subTest(prefix=prefix, state=state), self.assertRaisesRegex(
                        jit.AdmissionHold, "detached_ci_container_present"):
                    self.evaluate(containers=f"{prefix}abc|{state}\n")

    def test_pending_detached_lease_blocks_even_with_no_unit_or_container(self):
        # A committed lease can precede creation of a visible systemd unit.
        # Mock every external query and read a private temporary SQLite DB.
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'fleet.sqlite3'
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE detached_leases (job_id TEXT)")
                conn.execute("INSERT INTO detached_leases VALUES ('reserved-owner')")
            db.chmod(0o600)
            def fake_command(argv, **_):
                if argv[:3] == ["systemctl", "--user", "list-units"]:
                    return ""
                if argv[:3] == ["systemctl", "--user", "list-jobs"]:
                    return ""
                if argv[:2] == ["docker", "ps"]:
                    return ""
                raise AssertionError(f"Unexpected external call: {argv}")
            with (patch.object(jit, 'FLEET_DB', db),
                  patch.object(jit, 'run_cli', side_effect=fake_command)):
                with self.assertRaisesRegex(jit.AdmissionHold, "detached_ci_lease_reserved"):
                    jit.detached_fleet_quiescent()

    def test_missing_or_unsafe_fleet_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'fleet.sqlite3'
            for state in ('missing', 'world_readable', 'symlink'):
                with self.subTest(state=state):
                    if db.exists() or db.is_symlink():
                        db.unlink()
                    if state == 'world_readable':
                        with sqlite3.connect(db) as c:
                            c.execute("CREATE TABLE detached_leases (job_id TEXT)")
                        db.chmod(0o644)
                    elif state == 'symlink':
                        db.symlink_to(Path(tmp) / 'gone')
                    def fake_command(argv, **_):
                        if argv[:3] == ["systemctl", "--user", "list-units"]:
                            return ""
                        if argv[:3] == ["systemctl", "--user", "list-jobs"]:
                            return ""
                        self.fail("Fleet database must be checked before Docker")
                    with (patch.object(jit, 'FLEET_DB', db),
                          patch.object(jit, 'run_cli', side_effect=fake_command)):
                        with self.assertRaises(jit.AdmissionHold):
                            jit.detached_fleet_quiescent()

    def test_incomplete_inventory_blocks_admission(self):
        for command in (["systemctl", "--user", "list-units"],
                        ["systemctl", "--user", "list-jobs"],
                        ["docker", "ps"]):
            with self.subTest(command=command), self.assertRaisesRegex(
                    jit.AdmissionHold, "detached_ci_inventory_unavailable"):
                self.evaluate(fail_command=command)

    def test_quiescent_inventory_is_actually_checked(self):
        result, calls = self.evaluate(units="local-ci-job-done.service loaded inactive dead\n",
                                      containers="unrelated-service|running\n")
        self.assertTrue(result)
        self.assertTrue(any(c[:3] == ("systemctl", "--user", "list-units") for c in calls))
        self.assertTrue(any(c[:2] == ("docker", "ps") for c in calls))


if __name__ == "__main__":
    unittest.main()

