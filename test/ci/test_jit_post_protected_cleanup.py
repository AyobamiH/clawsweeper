"""Non-idempotent JIT registration failure boundaries; no real GitHub/Docker calls."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as executor
import self_hosted_policy as policy


class JitPostBoundaryTests(unittest.TestCase):
    def candidate(self):
        run = {"repository": {"full_name": policy.REPOSITORY, "id": 42},
               "id": 123456789, "run_attempt": 1, "path": ".github/workflows/codeql.yml",
               "head_sha": "a" * 40, "head_branch": "feature", "event": "pull_request",
               "actor": {"login": "external"},
               "pull_requests": [{"number": 123, "base": {"ref": "main",
                    "sha": "a" * 40, "repo": {"id": 42}},
                    "head": {"ref": "feature", "sha": "a" * 40, "repo": {"id": 42}}}]}
        job = {"id": 888, "run_id": 123456789, "name": "Analyze (actions)",
               "status": "queued", "labels": ["self-hosted", "Linux", "X64",
                                              "clawsweeper-ci-security-123456789-actions"]}
        return policy.classify(run, job)

    @staticmethod
    def registered_runner():
        # GitHub may return a runner registered by the uncertain POST. Only
        # this exact name AND all expected labels grant cleanup authority.
        return {"id": 481, "name": "csw-ci-123456789-888-1", "busy": False,
                "labels": [{"name": x} for x in (
                    "self-hosted", "Linux", "X64",
                    "clawsweeper-ci-security-123456789-actions")]}

    def boundary(self, gh, expected, assert_receipt):
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            receipts.mkdir(mode=0o700)
            with (patch.object(executor, "RECEIPTS", receipts),
                  patch.object(executor, "gh", side_effect=gh),
                  patch.object(executor, "approved_job_image", return_value="sha256:" + "f" * 64),
                  patch.object(executor, "prepare_network") as network,
                  patch.object(executor, "stop_owned") as stop):
                response = executor.runner_job(candidate, {})
                self.assertEqual(response["state"], "held")
                self.assertEqual(set(response["issues"]), set(expected))
                self.assertEqual(stop.call_count, 2)
                network.assert_not_called()
                saved = json.loads(Path(response["receipt"]).read_text())
                self.assertEqual(saved["state"], "held")
                assert_receipt(saved, candidate)
                # Nothing with this exact intent can be registered again.
                with self.assertRaisesRegex(policy.AdmissionHold,
                                            "existing_or_uncertain_runner_intent"):
                    executor.runner_job(candidate, {})
            return saved

    def test_incomplete_post_response_deregisters_known_runner(self):
        observed = []
        def gh(path, method="GET", body=None):
            observed.append((method, path))
            if method == "POST":
                return {"runner": {"id": 481}}
            if method == "DELETE":
                self.assertTrue(path.endswith("/actions/runners/481"))
                return {}
            if method == "GET":
                if sum(m == "GET" for m, _ in observed) == 1:
                    return {"total_count": 1, "runners": [self.registered_runner()]}
                return {"total_count": 0, "runners": []}
            self.fail("unexpected operation")
        self.boundary(gh, ["execution_error_RuntimeError"],
                      lambda r, c: self.assertEqual(r["runner_id"], 481))
        self.assertEqual([m for m, _ in observed].count("POST"), 1)
        self.assertEqual([m for m, _ in observed].count("DELETE"), 1)
        self.assertEqual([m for m, _ in observed].count("GET"), 2)
        self.assertEqual([m for m, _ in observed],
                         ["POST", "GET", "DELETE", "GET"])

    def test_ambiguous_post_keeps_intent_and_refuses_unverified_delete(self):
        observed = []
        def gh(path, method="GET", body=None):
            observed.append(method)
            if method == "POST":
                raise RuntimeError("upstream_timeout")
            if method == "GET":
                return {"total_count": 1, "runners": [{
                    "id": 481, "name": "csw-ci-123456789-888-1",
                    "labels": [{"name": "clawsweeper-ci-security-123456789-actions"}]}]}
            self.fail("must not DELETE a guessed runner ID")
        self.boundary(gh, ["execution_error_RuntimeError", "runner_deregistration_unverified"],
                      lambda r, c: self.assertNotIn("runner_id", r))
        self.assertEqual(observed, ["POST", "GET"])

    def test_failed_post_with_verified_absence_stays_held(self):
        observed = []
        def gh(path, method="GET", body=None):
            observed.append(method)
            if method == "POST":
                raise RuntimeError("upstream_timeout")
            if method == "GET":
                return {"total_count": 0, "runners": []}
            self.fail("must not DELETE or repeat uncertain registration")
        self.boundary(gh, ["execution_error_RuntimeError"],
                      lambda r, c: self.assertNotIn("runner_id", r))
        # One complete inventory authorises cleanup; an independent
        # second inventory confirms absence and seals the held receipt.
        self.assertEqual(observed, ["POST", "GET", "GET"])

    def test_keyboard_interrupt_during_post_stays_held_without_retry(self):
        candidate = self.candidate()
        observed = []
        def gh(path, method="GET", body=None):
            observed.append(method)
            if method == "POST":
                raise KeyboardInterrupt()
            if method == "GET":
                return {"total_count": 0, "runners": []}
            self.fail("unexpected mutation")
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            receipts.mkdir(mode=0o700)
            with (patch.object(executor, "RECEIPTS", receipts),
                  patch.object(executor, "gh", side_effect=gh),
                  patch.object(executor, "approved_job_image", return_value="sha256:" + "f" * 64),
                  patch.object(executor, "stop_owned") as stop):
                with self.assertRaises(KeyboardInterrupt):
                    executor.runner_job(candidate, {})
                saved = json.loads((receipts / "run-123456789-job-888-attempt-1" / "receipt.json").read_text())
                self.assertEqual(saved["state"], "held")
                self.assertIn("execution_interrupted_KeyboardInterrupt", saved["issues"])
                self.assertEqual(stop.call_count, 2)
                with self.assertRaisesRegex(policy.AdmissionHold, "existing_or_uncertain_runner_intent"):
                    executor.runner_job(candidate, {})
        # One complete inventory authorises cleanup; an independent
        # second inventory confirms absence and seals the held receipt.
        self.assertEqual(observed, ["POST", "GET", "GET"])

    def test_registered_receipt_write_failure_still_cleans_up(self):
        original_atomic = executor.atomic
        writes = []
        def atomic(path, record):
            writes.append(record["state"])
            if record["state"] == "registered":
                raise OSError("simulated_disk_failure")
            return original_atomic(path, record)
        observed = []
        def gh(path, method="GET", body=None):
            observed.append(method)
            if method == "POST":
                return {"runner": {"id": 481}, "encoded_jit_config": "untrusted-sensitive-value"}
            if method == "DELETE":
                return {}
            if method == "GET":
                if observed.count("GET") == 1:
                    return {"total_count": 1, "runners": [self.registered_runner()]}
                return {"total_count": 0, "runners": []}
            self.fail("unexpected operation")
        with patch.object(executor, "atomic", side_effect=atomic):
            self.boundary(gh, ["execution_error_OSError"],
                          lambda r, c: self.assertEqual(r["runner_id"], 481))
        self.assertEqual(writes, ["registration_uncertain", "registered", "held"])
        self.assertEqual(observed, ["POST", "GET", "DELETE", "GET"])


if __name__ == "__main__":
    unittest.main()
