"""Held CodeQL JIT may disable its own run scope, never replay a JIT POST."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as ex
from self_hosted_policy import Candidate, AdmissionHold

RUN, JOB = 123, 456
HEAD = "a" * 40
NAME = "csw-ci-123-456-1"
LABEL = "clawsweeper-ci-security-123-actions"
WORKFLOW = ".github/workflows/codeql.yml"


def candidate():
    return Candidate(RUN, JOB, 1, HEAD, WORKFLOW, "workflow_dispatch",
                     "security", "actions", LABEL, "Analyze (actions)", "main")


def active_scope():
    return {"repo": "AyobamiH/clawsweeper", "enabled": True,
            "enabled_roles": ["security"], "allowed_run_ids": [RUN],
            "allowed_branches": ["main"], "operations_accepted": False,
            "max_jobs_per_cycle": 1,
            "security_image_sha256": "sha256:" + "b" * 64}


class HeldNoIdScopeFence(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        receipts = root / "receipts"
        receipts.mkdir(mode=0o700)
        original = receipts / "run-123-job-456-attempt-1"
        original.mkdir(mode=0o700)
        payload = {
            "schema": "clawsweeper.selfhosted-jit.v1",
            "run_id": RUN, "job_id": JOB, "attempt": 1,
            "head_sha": HEAD, "role": "security", "workflow": WORKFLOW,
            "event": "workflow_dispatch", "label": LABEL, "runner_name": NAME,
            "image_sha256": "sha256:" + "b" * 64,
            "state": "held", "issues": ["execution_error_RuntimeError"],
            "uncertain_registration_absent": True,
            "finished_at": "2026-11-11T08:29:35Z",
        }
        ex.atomic(original / "receipt.json", payload)
        controls = root / "controls.json"
        ex.atomic(controls, active_scope())
        lock = root / "owner-codeql-acceptance.lock"
        lock.write_text("")
        lock.chmod(0o600)
        return receipts, controls, lock, original / "receipt.json"

    def context(self, receipts, controls, lock):
        return (patch.object(ex, "RECEIPTS", receipts),
                patch.object(ex, "CONTROLS", controls),
                patch.object(ex, "OWNER_CODEQL_LOCK", lock))

    def test_terminal_uncertain_failure_disarms_only_own_scope(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            original = rpath.read_bytes()
            with self.context(receipts, controls, lock)[0] as _, \
                 self.context(receipts, controls, lock)[1] as _, \
                 self.context(receipts, controls, lock)[2] as _, \
                 patch.object(ex, "gh") as gh, patch.object(ex, "runner_job") as runner:
                result = ex.disarm_security_after_held(candidate(), active_scope(), rpath)
            self.assertEqual(result["state"], "security_scope_disarmed")
            updated = json.loads(controls.read_text())
            self.assertFalse(updated["enabled"])
            self.assertFalse(updated["enabled_roles"])
            self.assertFalse(updated["allowed_run_ids"])
            self.assertFalse(updated["allowed_branches"])
            self.assertFalse(updated["operations_accepted"])
            self.assertEqual(updated["security_image_sha256"], active_scope()["security_image_sha256"])
            self.assertEqual(rpath.read_bytes(), original)
            self.assertTrue((rpath.parent / "held-scope-disarm-intent.json").is_file())
            self.assertTrue((rpath.parent / "held-scope-disarm-result.json").is_file())
            gh.assert_not_called()
            runner.assert_not_called()

    def test_wrong_scope_and_changed_controls_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            cases = [
                dict(active_scope(), allowed_run_ids=[999]),
                dict(active_scope(), operations_accepted=True),
                dict(active_scope(), enabled_roles=["security", "ops"]),
                dict(active_scope(), allowed_branches=["other"]),
            ]
            for scope in cases:
                with self.subTest(scope=scope), \
                     patch.object(ex, "RECEIPTS", receipts), \
                     patch.object(ex, "CONTROLS", controls), \
                     patch.object(ex, "OWNER_CODEQL_LOCK", lock):
                    with self.assertRaises((AdmissionHold, RuntimeError)):
                        ex.disarm_security_after_held(candidate(), scope, rpath)
                    self.assertEqual(json.loads(controls.read_text()), active_scope())
                    self.assertFalse((rpath.parent / "held-scope-disarm-intent.json").exists())

    def test_tampered_receipt_refused_before_scope_change(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            data = json.loads(rpath.read_text())
            data["job_id"] = 888
            ex.atomic(rpath, data)
            with patch.object(ex, "RECEIPTS", receipts), \
                 patch.object(ex, "CONTROLS", controls), \
                 patch.object(ex, "OWNER_CODEQL_LOCK", lock):
                with self.assertRaises((AdmissionHold, RuntimeError)):
                    ex.disarm_security_after_held(candidate(), active_scope(), rpath)
            self.assertTrue(json.loads(controls.read_text())["enabled"])

    def test_repeated_disarm_rejected_without_overwriting_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            with patch.object(ex, "RECEIPTS", receipts), \
                 patch.object(ex, "CONTROLS", controls), \
                 patch.object(ex, "OWNER_CODEQL_LOCK", lock):
                ex.disarm_security_after_held(candidate(), active_scope(), rpath)
                first = (rpath.parent / "held-scope-disarm-intent.json").read_bytes()
                with self.assertRaises((AdmissionHold, RuntimeError)):
                    ex.disarm_security_after_held(candidate(), active_scope(), rpath)
                self.assertEqual(first, (rpath.parent / "held-scope-disarm-intent.json").read_bytes())

    def test_failed_replacement_is_detected_without_new_registration(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, original = self.fixture(td)
            first = json.loads(original.read_text())
            first["state"] = "runner_started"
            first.pop("finished_at", None)
            first.pop("issues", None)
            ex.atomic(original, first)
            child = receipts / "run-123-job-456-attempt-1-replacement-1"
            child.mkdir(mode=0o700)
            second = dict(first, state="held",
                          runner_name=NAME + "-replacement-1",
                          issues=["execution_error_RuntimeError"],
                          finished_at="2026-11-11T08:44:00Z")
            ex.atomic(child / "receipt.json", second)
            with patch.object(ex, "RECEIPTS", receipts), patch.object(ex, "gh") as gh:
                seen = ex.existing_security_held_receipt(candidate())
            self.assertEqual(seen, child / "receipt.json")
            gh.assert_not_called()

    def test_symlinked_receipt_root_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, original = self.fixture(td)
            link = Path(td) / "linked-receipts"
            link.symlink_to(receipts, target_is_directory=True)
            with patch.object(ex, "RECEIPTS", link):
                with self.assertRaisesRegex(AdmissionHold, "unsafe_prior_receipt_root"):
                    ex.existing_security_held_receipt(candidate())

    def test_main_prior_held_scope_never_registers_another_runner(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, owner_lock, receipt = self.fixture(td)
            root = Path(td)
            executor_lock = root / "executor.lock"
            executor_lock.write_text("")
            executor_lock.chmod(0o600)
            result = {"state": "security_scope_disarmed", "run_id": RUN}
            with patch.object(ex, "ROOT", root), \
                 patch.object(ex, "LOCK", executor_lock), \
                 patch.object(ex, "discover", return_value=[candidate()]), \
                 patch.object(ex, "load_controls", return_value=active_scope()), \
                 patch.object(ex, "category_enabled"), \
                 patch.object(ex, "source_authorised"), \
                 patch.object(ex, "existing_security_held_receipt", return_value=receipt), \
                 patch.object(ex, "disarm_security_after_held", return_value=result) as disarm, \
                 patch.object(ex, "runner_job") as runner, \
                 patch.object(sys, "argv", ["self_hosted_executor.py", "cycle"]), \
                 patch("sys.stdout", new_callable=io.StringIO) as stdout:
                ex.main()
            self.assertEqual(json.loads(stdout.getvalue())["state"], "security_scope_disarmed")
            disarm.assert_called_once()
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
