"""Adversarial JIT registration and fleet-ownership tests with no external effects."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts" / "ci"))
import estate_controller as ctl
import self_hosted_executor as exe
from estate_policy import Hold, Admission, REPO, CLASSES
from estate_slots import SlotLedger

SHA = "a" * 40


def job():
    return SimpleNamespace(run_id=6123, job_id=7234, run_attempt=1, sha=SHA,
        workflow=".github/workflows/codeql.yml", event="workflow_dispatch",
        role="security", label="clawsweeper-ci-security-6123-actions")


def run_test(case):
    with tempfile.TemporaryDirectory() as root:
        receipts = Path(root) / "receipts"
        with patch.object(exe, "RECEIPTS", receipts), \
             patch.object(exe, "approved_job_image", return_value="sha256:" + "a" * 64), \
             patch.object(exe, "stop_owned", return_value=None) as stop:
            return case(receipts, stop)


class JitRegistrationRecovery(unittest.TestCase):
    def test_unknown_post_outcome_never_retries_registration(self):
        requests = []
        def case(receipts, stop):
            def api(path, method="GET", body=None):
                requests.append((path, method))
                if method == "POST":
                    raise RuntimeError("network uncertain and token must stay private")
                return {"total_count": 0, "runners": []}
            with patch.object(exe, "gh", side_effect=api):
                result = exe.runner_job(job(), {})
            self.assertEqual(result["state"], "held")
            self.assertEqual(stop.call_count, 2)
            receipt = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(receipt["state"], "held")
            self.assertTrue(receipt["uncertain_registration_absent"])
            self.assertNotIn("token must", json.dumps(receipt))
            self.assertEqual(sum(m == "POST" for _, m in requests), 1)
        run_test(case)

    def test_registered_opaque_runner_may_only_be_cleaned_if_owner_label_matches(self):
        requests = []
        deleted = False
        def case(receipts, stop):
            nonlocal deleted
            def api(path, method="GET", body=None):
                nonlocal deleted
                requests.append((path, method))
                if method == "POST":
                    raise RuntimeError("response lost after POST")
                if method == "DELETE":
                    self.assertTrue(path.endswith("/91"))
                    deleted = True
                    return {}
                if "actions/runners?" in path:
                    rows = [] if deleted else [{
                        "id": 91, "name": "csw-ci-6123-7234-1",
                        "labels": [{"name": x} for x in (
                            "self-hosted", "Linux", "X64",
                            "clawsweeper-ci-security-6123-actions")],
                    }]
                    return {"total_count": len(rows), "runners": rows}
                raise AssertionError(path)
            with patch.object(exe, "gh", side_effect=api):
                result = exe.runner_job(job(), {})
            receipt = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(result["state"], "held")
            self.assertTrue(deleted)
            self.assertTrue(receipt["uncertain_registration_matched"])
            self.assertEqual(receipt["runner_id"], 91)
            self.assertEqual(sum(method == "POST" for _, method in requests), 1)
        run_test(case)

    def test_foreign_label_is_not_silently_deleted(self):
        requests = []
        def case(receipts, stop):
            def api(path, method="GET", body=None):
                requests.append((path, method))
                if method == "POST":
                    raise RuntimeError("uncertain response")
                if method == "DELETE":
                    self.fail("foreign runner must not be deregistered")
                return {"total_count": 1, "runners": [{
                    "id": 92, "name": "csw-ci-6123-7234-1",
                    "labels": [{"name": "self-hosted"}, {"name": "different-owner"}],
                }]}
            with patch.object(exe, "gh", side_effect=api):
                result = exe.runner_job(job(), {})
            self.assertEqual(result["state"], "held")
            self.assertIn("runner_deregistration_unverified", result["issues"])
        run_test(case)

    def test_early_response_parse_failure_still_runs_deregistration(self):
        methods = []
        def case(receipts, stop):
            def api(path, method="GET", body=None):
                methods.append(method)
                if method == "POST":
                    return {"runner": {"id": 88}}  # encoded config missing
                if method == "DELETE":
                    self.assertTrue(path.endswith("/88"))
                    return {}
                return {"total_count": 0, "runners": []}
            with patch.object(exe, "gh", side_effect=api):
                result = exe.runner_job(job(), {})
            self.assertEqual(result["state"], "held")
            self.assertIn("execution_error_RuntimeError", result["issues"])
            # An already-absent ephemeral runner is independently verified
            # absent, not deleted merely because its former ID is known.
            self.assertGreaterEqual(methods.count("GET"), 2)
            stop.assert_any_call("csw-ci-6123-7234-1-worker", "csw-ci-6123-7234-1")
        run_test(case)

    def test_receipt_persist_failure_after_registration_still_cleans(self):
        requests = []
        def case(receipts, stop):
            original = exe.atomic
            def persist(path, payload):
                if payload.get("state") == "registered":
                    raise OSError("disk write refused")
                return original(path, payload)
            def api(path, method="GET", body=None):
                requests.append(method)
                if method == "POST":
                    return {"runner": {"id": 88}, "encoded_jit_config": "private"}
                if method == "DELETE":
                    return {}
                return {"total_count": 0, "runners": []}
            with patch.object(exe, "gh", side_effect=api), patch.object(exe, "atomic", side_effect=persist):
                result = exe.runner_job(job(), {})
            self.assertEqual(result["state"], "held")
            self.assertEqual(requests.count("POST"), 1)
            self.assertGreaterEqual(requests.count("GET"), 2)
            self.assertIn("execution_error_OSError", result["issues"])
        run_test(case)


class EstateInventoryPreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.ledger = SlotLedger(self.folder / "ledger")
        self.legacy = self.folder / "old-controller.json"

    def tearDown(self):
        self.temp.cleanup()

    def api(self, rows):
        return lambda path: {"total_count": len(rows), "runners": rows}

    def test_empty_inventory_and_disabled_legacy_controller_is_safe(self):
        self.legacy.write_text('{"enabled":false}')
        self.legacy.chmod(0o600)
        result = ctl.preflight_runtime_inventory(self.ledger, api=self.api([]),
            list_containers=lambda: [], legacy_controls=self.legacy)
        self.assertEqual(result["runners"], 0)

    def test_legacy_controller_or_untracked_runner_refuses(self):
        self.legacy.write_text('{"enabled":true}')
        self.legacy.chmod(0o600)
        with self.assertRaisesRegex(Hold, "legacy_controller_still_enabled"):
            ctl.preflight_runtime_inventory(self.ledger, api=self.api([]),
                list_containers=lambda: [], legacy_controls=self.legacy)
        self.legacy.write_text('{"enabled":false}')
        with self.assertRaisesRegex(Hold, "competing_or_untracked_jit_runner"):
            ctl.preflight_runtime_inventory(self.ledger, api=self.api([{
                "name": "csw-ci-900-901-1", "id": 7}]),
                list_containers=lambda: [], legacy_controls=self.legacy)

    def test_unknown_owned_container_refuses_even_if_runner_absent(self):
        with self.assertRaisesRegex(Hold, "competing_or_untracked_container"):
            ctl.preflight_runtime_inventory(self.ledger, api=self.api([]),
                list_containers=lambda: ["csw-ci-900-901-1-worker"],
                legacy_controls=self.legacy)

    def test_known_running_attempt_is_not_mistaken_for_foreign_owner(self):
        c = Admission("x#ordinary", "ordinary", 900, 901, 1, SHA,
                      "x", "push", "testlabel", "check", "main")
        ctrl = {"enabled": True, "repo": REPO, "max_parallel": 2,
                "class_parallel_caps": {k: 2 for k in CLASSES}}
        self.ledger.reserve(c, ctrl, memory_available_mib=20000, disk_free_gib=100)
        name = "csw-ci-900-901-1"
        result = ctl.preflight_runtime_inventory(self.ledger,
            api=self.api([{"name": name, "id": 99}]),
            list_containers=lambda: [name + "-worker", name + "-net"],
            legacy_controls=self.legacy)
        self.assertEqual(result["known_active_attempts"], 1)
        self.assertEqual(result["owned_containers"], 2)

    def test_incomplete_inventory_is_not_treated_as_absence(self):
        with self.assertRaisesRegex(Hold, "runner_inventory_incomplete"):
            ctl.preflight_runtime_inventory(self.ledger, api=lambda p: {
                "runners": [], "total_count": 5}, list_containers=lambda: [],
                legacy_controls=self.legacy)
