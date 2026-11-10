"""Bounded, owner-reconciled JIT replacement tests; never contact GitHub or Docker."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as executor
import reconcile_interrupted_jit as recovery
from self_hosted_policy import Candidate, AdmissionHold

RUN, JOB, ATTEMPT = 123, 456, 1
HEAD = "a" * 40
NAME = "csw-ci-123-456-1"
KEY = "run-123-job-456-attempt-1"
LABEL = "clawsweeper-ci-security-123-actions"
WORKFLOW = ".github/workflows/codeql.yml"


def candidate():
    return Candidate(RUN, JOB, ATTEMPT, HEAD, WORKFLOW, "workflow_dispatch",
                     "security", "actions", LABEL, "Analyze (actions)", "main")


class ReplacementAdmissionTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory) / "receipts"
        root.mkdir(mode=0o700)
        prior = root / KEY
        prior.mkdir(mode=0o700)
        original = {
            "schema": "clawsweeper.selfhosted-jit.v1",
            "run_id": RUN, "job_id": JOB, "attempt": ATTEMPT,
            "head_sha": HEAD, "workflow": WORKFLOW,
            "event": "workflow_dispatch", "role": "security",
            "label": LABEL, "runner_name": NAME,
            "runner_id": 99, "state": "runner_started",
            "image_sha256": "sha256:" + "a" * 64,
            "created_at": "2026-11-10T00:00:00Z",
        }
        executor.atomic(prior / "receipt.json", original)
        original_bytes = (prior / "receipt.json").read_bytes()
        proof = {
            "schema": "clawsweeper.jit-interrupted-recovery.v1",
            "decision": "cleanup_verified_no_replay",
            "original_state": original["state"],
            "original_receipt_sha256": hashlib.sha256(original_bytes).hexdigest(),
            "run_id": RUN, "job_id": JOB, "attempt": ATTEMPT,
            "runner_name": NAME, "head_sha": HEAD,
            "github_job": {"id": JOB, "run_id": RUN, "status": "queued",
                           "conclusion": None, "runner_name": None},
            "runner_absent": True, "owned_containers_absent": True,
            "new_registration_attempted": False, "release_acceptance": False,
            "verified_at": "2026-11-10T01:00:00Z",
        }
        executor.atomic(prior / "interrupted-recovery-proof.json", proof)
        executor.atomic(prior / "interrupted-recovery-intent.json", {
            "schema": "clawsweeper.jit-interrupted-intent.v1",
            "original_receipt_sha256": proof["original_receipt_sha256"],
            "runner_name": NAME, "head_sha": HEAD, "run_id": RUN,
            "job_id": JOB, "attempt": ATTEMPT, "replay_registration": False,
        })
        return root, prior

    @staticmethod
    def remote(path, method="GET", body=None):
        if method != "GET":
            raise AssertionError("read-only selection must not create runner")
        if path.endswith("/actions/runs/123"):
            return {"id": RUN, "run_attempt": ATTEMPT, "head_sha": HEAD,
                    "path": WORKFLOW, "repository": {"full_name": "AyobamiH/clawsweeper"}}
        if path.endswith("/actions/jobs/456"):
            return {"id": JOB, "run_id": RUN, "status": "queued",
                    "runner_name": "", "conclusion": None}
        raise AssertionError(path)

    def select(self, root, **kwargs):
        with patch.object(executor, "RECEIPTS", root), \
             patch.object(executor, "gh", side_effect=kwargs.get("gh", self.remote)), \
             patch.object(executor, "inspect_owned", side_effect=kwargs.get("inspect_owned", lambda *args: None)), \
             patch.object(executor, "runner_absent_verified", side_effect=kwargs.get("absent", lambda *args: True)):
            return executor.select_runner_intent(candidate())

    def test_fresh_job_retains_existing_single_registration_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "receipts"
            root.mkdir(mode=0o700)
            path, name, lineage = self.select(root)
            self.assertEqual((path.name, name, lineage), (KEY, NAME, None))

    def test_verified_cleanup_allows_one_distinct_replacement_not_original_replay(self):
        with tempfile.TemporaryDirectory() as td:
            root, original = self.fixture(td)
            path, name, lineage = self.select(root)
            self.assertEqual(path.name, KEY + "-replacement-1")
            self.assertEqual(name, NAME + "-replacement-1")
            self.assertEqual(lineage["original_receipt_sha256"],
                             hashlib.sha256((original / "receipt.json").read_bytes()).hexdigest())
            self.assertFalse(path.exists())
            self.assertEqual(json.loads((original / "receipt.json").read_text())["state"], "runner_started")

    def test_missing_or_unverified_cleanup_never_retries_post(self):
        with tempfile.TemporaryDirectory() as td:
            root, original = self.fixture(td)
            proof = original / "interrupted-recovery-proof.json"
            for corruption in ("missing", "forged", "incomplete"):
                with self.subTest(corruption=corruption):
                    saved = proof.read_bytes()
                    if corruption == "missing":
                        proof.unlink()
                    elif corruption == "forged":
                        data = json.loads(saved);data["original_receipt_sha256"] = "0" * 64
                        executor.atomic(proof, data)
                    else:
                        data = json.loads(saved);data["runner_absent"] = False
                        executor.atomic(proof, data)
                    with self.assertRaises((AdmissionHold, RuntimeError)):
                        self.select(root)
                    executor.atomic(proof, json.loads(saved))

    def test_existing_replacement_intent_blocks_another_registration(self):
        with tempfile.TemporaryDirectory() as td:
            root, original = self.fixture(td)
            replacement = root / (KEY + "-replacement-1")
            replacement.mkdir(mode=0o700)
            with self.assertRaises((AdmissionHold, RuntimeError)):
                self.select(root)

    def test_stale_or_uncertain_github_job_blocks_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root, original = self.fixture(td)
            def completed(path, method="GET", body=None):
                data = self.remote(path,method,body)
                if "/jobs/" in path:
                    data["status"] = "completed"
                return data
            with self.assertRaises((AdmissionHold, RuntimeError)):
                self.select(root, gh=completed)

    def test_reappearing_prior_runner_or_container_blocks_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root, original = self.fixture(td)
            with self.assertRaises((AdmissionHold, RuntimeError)):
                self.select(root, absent=lambda *args: (_ for _ in ()).throw(RuntimeError("runner returned")))
            with self.assertRaises((AdmissionHold, RuntimeError)):
                self.select(root, inspect_owned=lambda *args: {"id": "still_present"})

    def test_exact_replacement_receipt_can_be_crash_reconciled_once(self):
        with tempfile.TemporaryDirectory() as td:
            root, original = self.fixture(td)
            second = root / (KEY + "-replacement-1")
            second.mkdir(mode=0o700)
            prior = json.loads((original / "receipt.json").read_text())
            prior["runner_name"] = NAME + "-replacement-1"
            prior["state"] = "registration_uncertain"
            prior["replacement_for"] = NAME
            prior["replacement_proof_sha256"] = hashlib.sha256(
                (original / "interrupted-recovery-proof.json").read_bytes()
            ).hexdigest()
            executor.atomic(second / "receipt.json", prior)
            with patch.object(recovery, "RECEIPTS", root):
                received, digest = recovery.verify_identity(second)
            self.assertEqual(received["runner_name"], NAME + "-replacement-1")
            self.assertEqual(digest, hashlib.sha256((second / "receipt.json").read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
