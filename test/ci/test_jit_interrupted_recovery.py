"""Adversarial, local-only interrupted JIT registration and recovery checks."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as executor
import reconcile_interrupted_jit as recovery
from self_hosted_policy import Candidate


RUN = 123
JOB = 456
ATTEMPT = 1
NAME = "csw-ci-123-456-1"
LABEL = "clawsweeper-ci-security-123-actions"
HEAD = "a" * 40
WORKFLOW = ".github/workflows/codeql.yml"


def candidate():
    return Candidate(
        RUN, JOB, ATTEMPT, HEAD, WORKFLOW, "workflow_dispatch",
        "security", "actions", LABEL, "Analyze (actions)", "main"
    )


def runner_response(name=NAME, rid=99, label=LABEL, busy=False):
    return {
        "id": rid, "name": name, "busy": busy,
        "labels": [{"name": x} for x in ("self-hosted", "Linux", "X64", label)],
    }


class InterruptedJitTests(unittest.TestCase):
    def fixture(self, parent, state="registration_uncertain", runner_id=None):
        root = Path(parent) / "receipts"
        root.mkdir(mode=0o700)
        directory = root / "run-123-job-456-attempt-1"
        directory.mkdir(mode=0o700)
        receipt = {
            "schema": "clawsweeper.selfhosted-jit.v1", "run_id": RUN,
            "job_id": JOB, "attempt": ATTEMPT, "head_sha": HEAD,
            "workflow": WORKFLOW, "event": "workflow_dispatch",
            "role": "security", "label": LABEL, "runner_name": NAME,
            "state": state, "created_at": "2026-11-07T10:00:00Z",
        }
        if runner_id is not None:
            receipt["runner_id"] = runner_id
        executor.atomic(directory / "receipt.json", receipt)
        run = {
            "id": RUN, "run_attempt": ATTEMPT, "head_sha": HEAD,
            "path": WORKFLOW, "repository": {"full_name": "AyobamiH/clawsweeper"},
        }
        job = {
            "id": JOB, "run_id": RUN, "status": "queued",
            "runner_name": None, "conclusion": None,
        }
        return root, directory, run, job

    def test_ambiguous_post_in_live_executor_is_cleanup_protected_not_retried(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "receipts"
            root.mkdir(mode=0o700)
            calls = []
            def gh(path, method="GET", body=None):
                calls.append((path, method))
                if method == "POST":
                    raise RuntimeError("ambiguous POST/timeout after remote registration")
                return {}
            with patch.object(executor, "RECEIPTS", root), \
                 patch.object(executor, "approved_job_image", return_value="sha256:fixture"), \
                 patch.object(executor, "gh", side_effect=gh), \
                 patch.object(executor, "lookup_owned_runner", return_value=99) as lookup, \
                 patch.object(executor, "stop_owned") as stop, \
                 patch.object(executor, "runner_absent_verified", return_value=True):
                result = executor.runner_job(candidate(), {})
            self.assertEqual(result["state"], "held")
            self.assertEqual(sum(method == "POST" for _, method in calls), 1)
            self.assertEqual(sum(method == "DELETE" for _, method in calls), 1)
            lookup.assert_called_once()
            self.assertEqual(stop.call_count, 2)
            data = json.loads((root / "run-123-job-456-attempt-1" / "receipt.json").read_text())
            self.assertEqual(data["state"], "held")
            self.assertIn("execution_error_RuntimeError", data["issues"])
            self.assertNotIn("runner_started_at", data)

    def test_exact_runner_lookup_rejects_partial_foreign_and_busy_inventory(self):
        good = runner_response()
        query = "repos/AyobamiH/clawsweeper/actions/runners?per_page=100"
        with patch.object(executor, "gh", return_value={"runners": [good], "total_count": 1}) as gh:
            self.assertEqual(executor.lookup_owned_runner(NAME, LABEL), 99)
            gh.assert_called_with(query)
        bad_cases = (
            {"runners": [good], "total_count": 2},  # truncated inventory
            {"runners": [runner_response(label="owner-host")], "total_count": 1},
            {"runners": [runner_response(name="foreign", rid=99)], "total_count": 1},
            {"runners": [runner_response(busy=True)], "total_count": 1},
        )
        for payload in bad_cases:
            with self.subTest(payload=payload), patch.object(executor, "gh", return_value=payload):
                with self.assertRaises(RuntimeError):
                    executor.lookup_owned_runner(NAME, LABEL, known_id=99)
        with patch.object(executor, "gh", return_value={"runners": [], "total_count": 0}):
            self.assertIsNone(executor.lookup_owned_runner(NAME, LABEL))

    def test_crash_window_idempotently_reconciles_exact_owned_runner(self):
        with tempfile.TemporaryDirectory() as td:
            root, directory, run, job = self.fixture(td, runner_id=99)
            original = (directory / "receipt.json").read_bytes()
            calls = []
            def gh(path, method="GET", body=None):
                calls.append((path, method))
                if method == "DELETE":
                    return {}
                return run if f"runs/{RUN}" in path else job
            with patch.object(recovery, "RECEIPTS", root), \
                 patch.object(recovery, "LOCK", Path(td) / "executor.lock"), \
                 patch.object(recovery, "gh", side_effect=gh), \
                 patch.object(recovery, "inspect_owned", return_value=None), \
                 patch.object(recovery, "stop_owned") as stopped, \
                 patch.object(recovery, "lookup_owned_runner", side_effect=[99, None]), \
                 patch.object(recovery, "runner_absent_verified", return_value=True):
                first = recovery.recover(directory)
                second = recovery.recover(directory)
            self.assertEqual(first["decision"], "cleanup_verified_no_replay")
            self.assertEqual(second, first)
            self.assertFalse(first["release_acceptance"])
            self.assertEqual(sum(method == "DELETE" for _, method in calls), 1)
            self.assertEqual(sum(method == "POST" for _, method in calls), 0)
            self.assertEqual(stopped.call_count, 2)
            self.assertEqual((directory / "receipt.json").read_bytes(), original)
            intent = json.loads((directory / "interrupted-recovery-intent.json").read_text())
            self.assertEqual(intent["original_receipt_sha256"], hashlib.sha256(original).hexdigest())
            self.assertFalse(intent["replay_registration"])

    def test_crash_after_remote_post_before_local_response_is_recoverable_without_id(self):
        with tempfile.TemporaryDirectory() as td:
            root, directory, run, job = self.fixture(td, runner_id=None)
            calls = []
            def gh(path, method="GET", body=None):
                calls.append((path, method))
                return {} if method == "DELETE" else run if f"runs/{RUN}" in path else job
            with patch.object(recovery, "RECEIPTS", root), \
                 patch.object(recovery, "LOCK", Path(td) / "executor.lock"), \
                 patch.object(recovery, "gh", side_effect=gh), \
                 patch.object(recovery, "lookup_owned_runner", return_value=99), \
                 patch.object(recovery, "inspect_owned", return_value=None), \
                 patch.object(recovery, "stop_owned") as stop, \
                 patch.object(recovery, "runner_absent_verified", return_value=True):
                outcome = recovery.recover(directory)
            self.assertTrue(outcome["runner_absent"])
            self.assertEqual(stop.call_count, 2)
            self.assertEqual([method for _, method in calls].count("POST"), 0)
            self.assertEqual([method for _, method in calls].count("DELETE"), 1)

    def test_busy_runner_or_foreign_container_prevents_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root, directory, run, job = self.fixture(td)
            def gh(path, method="GET", body=None):
                if method != "GET":
                    raise AssertionError("must fail before mutation")
                return run if f"runs/{RUN}" in path else job
            for target in ("busy", "foreign"):
                with self.subTest(target=target), \
                     patch.object(recovery, "RECEIPTS", root), \
                     patch.object(recovery, "LOCK", Path(td) / "executor.lock"), \
                     patch.object(recovery, "gh", side_effect=gh), \
                     patch.object(recovery, "lookup_owned_runner",
                                  side_effect=RuntimeError("runner_still_busy_unverified") if target == "busy" else None), \
                     patch.object(recovery, "inspect_owned",
                                  side_effect=RuntimeError("container_ownership_mismatch") if target == "foreign" else None), \
                     patch.object(recovery, "stop_owned") as stop:
                    if target == "busy":
                        # Exact owned container inspection precedes runner lookup.
                        with patch.object(recovery, "inspect_owned", return_value=None):
                            with self.assertRaises(RuntimeError):
                                recovery.recover(directory)
                    else:
                        with self.assertRaises(RuntimeError):
                            recovery.recover(directory)
                    stop.assert_not_called()
            self.assertFalse((directory / "interrupted-recovery-proof.json").exists())

    def test_original_identity_change_blocks_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            root, directory, run, job = self.fixture(td)
            p = directory / "receipt.json"
            data = json.loads(p.read_text())
            data["label"] = "clawsweeper-ci-ops-123-other"
            executor.atomic(p, data)
            with patch.object(recovery, "RECEIPTS", root), \
                 patch.object(recovery, "LOCK", Path(td) / "executor.lock"), \
                 patch.object(recovery, "gh") as gh:
                with self.assertRaisesRegex(RuntimeError, "identity_mismatch"):
                    recovery.recover(directory)
                gh.assert_not_called()


if __name__ == "__main__":
    unittest.main()
