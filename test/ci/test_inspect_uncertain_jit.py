"""Uncertain JIT inspections must be read-only, bound and fail closed."""
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import inspect_uncertain_jit as diag


class UncertainIntentTests(unittest.TestCase):
    def fixture(self, root, state="registration_uncertain", runner_id=None):
        receipts = Path(root) / "receipts"
        receipts.mkdir(mode=0o700)
        entry = receipts / "run-123-job-456-attempt-1"
        entry.mkdir(mode=0o700)
        record = {
            "schema": "clawsweeper.selfhosted-jit.v1",
            "run_id": 123, "job_id": 456, "attempt": 1,
            "head_sha": "a" * 40, "runner_name": "csw-ci-123-456-1",
            "label": "clawsweeper-ci-security-123-actions", "role": "security",
            "state": state,
        }
        if runner_id is not None:
            record["runner_id"] = runner_id
        original = entry / "receipt.json"
        original.write_text(json.dumps(record))
        original.chmod(0o600)
        return receipts, entry, original

    def github(self, *, present=False, full=True, wrong_runner=False):
        calls = []
        def gh(path):
            calls.append(path)
            if "/actions/runs/" in path:
                return {"id": 123, "head_sha": "a" * 40, "run_attempt": 1,
                        "repository": {"full_name": "AyobamiH/clawsweeper"}}
            if "/actions/jobs/" in path:
                return {"id": 456, "run_id": 123, "runner_name": None, "status": "queued"}
            if "/actions/runners?" in path:
                runners = ([{"id": 901, "name": "foreign" if wrong_runner else "csw-ci-123-456-1",
                             "labels": [{"name": "clawsweeper-ci-security-123-actions"}]}]
                           if present else [])
                return {"total_count": len(runners) + (1 if not full else 0),
                        "runners": runners}
            self.fail("unexpected network request")
        return gh, calls

    def test_unknown_effect_never_becomes_retry_permission(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, entry, original = self.fixture(td)
            raw = original.read_bytes()
            gh, calls = self.github()
            with (patch.object(diag, "RECEIPTS", receipts),
                  patch.object(diag, "gh", side_effect=gh),
                  patch.object(diag, "inspect_owned", return_value=None) as docker):
                evidence = diag.inspect(entry)
            self.assertEqual(evidence["decision"], "manual_reconciliation_required")
            self.assertFalse(evidence["runner_present"])
            self.assertFalse(evidence["may_retry_registration"])
            self.assertFalse(evidence["mutations_performed"])
            self.assertEqual(evidence["original_receipt_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(raw, original.read_bytes())
            self.assertEqual(docker.call_count, 2)
            self.assertEqual(len(calls), 3)

    def test_present_unnamed_runner_id_does_not_trigger_guess_or_delete(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, entry, original = self.fixture(td)
            gh, calls = self.github(present=True)
            with patch.object(diag, "RECEIPTS", receipts), patch.object(diag, "gh", side_effect=gh), \
                 patch.object(diag, "inspect_owned", return_value={"owned": True}):
                evidence = diag.inspect(entry)
            self.assertTrue(evidence["runner_present"])
            self.assertTrue(evidence["container_present"]["worker"])
            self.assertFalse(evidence["may_retry_registration"])
            self.assertTrue(all("DELETE" not in x for x in calls))

    def test_conflicting_id_and_incomplete_inventory_are_held(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, entry, original = self.fixture(td, state="registered", runner_id=901)
            gh, _ = self.github(present=True, wrong_runner=True)
            with patch.object(diag, "RECEIPTS", receipts), patch.object(diag, "gh", side_effect=gh):
                with self.assertRaisesRegex(RuntimeError, "runner_identity_conflict"):
                    diag.inspect(entry)
            gh, _ = self.github(present=True, full=False)
            with patch.object(diag, "RECEIPTS", receipts), patch.object(diag, "gh", side_effect=gh):
                with self.assertRaisesRegex(RuntimeError, "runner_inventory_not_complete"):
                    diag.inspect(entry)

    def test_receipt_permissions_and_symlink_refused_before_network(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, entry, original = self.fixture(td)
            gh, calls = self.github()
            original.chmod(0o644)
            with patch.object(diag, "RECEIPTS", receipts), patch.object(diag, "gh", side_effect=gh):
                with self.assertRaisesRegex(RuntimeError, "unsafe_intent_receipt"):
                    diag.inspect(entry)
            self.assertEqual(calls, [])
            original.chmod(0o600)
            link = receipts / "run-123-job-457-attempt-1"
            link.symlink_to(entry, target_is_directory=True)
            with patch.object(diag, "RECEIPTS", receipts), patch.object(diag, "gh", side_effect=gh):
                with self.assertRaisesRegex(RuntimeError, "unowned_intent_directory"):
                    diag.inspect(link)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
