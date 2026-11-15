"""Manual-origin receipt contract: never use a GitHub status as local proof."""
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
sys.path.insert(0, str(ROOT / "test/ci"))
import test_direct_local_job_receipts as fixture_helpers
import direct_local_manual_run as manual
import direct_local_job_receipts as readback
from estate_policy import Hold


class ManualReceiptReadbackTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture_helpers.ExistingFleetOrdinaryEvidenceTests("test_authenticated_main_push_is_only_one_job")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.case.ref = manual.REF
        self.case.make_evidence(with_claim=False)
        self.proof = {
            "job_id": self.case.job_id, "source_sha": self.case.sha,
            "ref": manual.REF, "source_ref": manual.PROVIDER_REF,
            "suite": manual.claims.SUITE, "event": "local-manual",
            "repo": manual.REPO, "owner_principal": manual.PRINCIPAL,
            "request_sha256": "f"*64, "nonce_sha256": "e"*64,
            "job_intents": list(manual.JOBS), "proof_kind": manual.PROOF,
        }
        with sqlite3.connect(self.case.db) as db:
            db.execute("INSERT INTO observations VALUES(?,?,?)",
                       ("direct-local-manual:bound", json.dumps(self.proof), "now"))
        self.case.receipt.update({
            "origin": "owner-signed-local-manual",
            "provider_status": "suppressed-local-manual",
            "manual_request_sha256": self.proof["request_sha256"],
        })
        self.case.save_receipt()

    def verify(self):
        with mock.patch.object(manual, "read_fresh_develop_sha",
                               return_value=self.case.sha):
            return self.case.prove()

    def test_complete_distinct_manual_receipt_maps_two_ordinary_jobs(self):
        proof = self.verify()
        self.assertEqual(len(proof["verified_local_job_steps"]), 2)
        self.assertEqual(proof["source_kind"], "owner-signed-local-manual")
        self.assertEqual(proof["authenticated_owner_manual_claim_count"], 1)
        self.assertEqual(proof["authenticated_event_claim_count"], 0)
        self.assertTrue(proof["provider_status_suppressed_in_receipt"])
        self.assertFalse(proof["github_provider_check_independently_verified"])

    def test_manual_success_without_suppression_marker_is_not_accepted(self):
        self.case.receipt.pop("provider_status")
        self.case.save_receipt()
        with self.assertRaisesRegex(Hold, "provider_status_not_proven"):
            self.verify()

    def test_manual_receipt_with_github_status_is_not_accepted(self):
        self.case.receipt["github_status"] = {
            "state": "success", "context": "local-ci/linux-node24"}
        self.case.save_receipt()
        with self.assertRaisesRegex(Hold, "provider_status_not_proven"):
            self.verify()

    def test_relabelled_request_digest_is_not_accepted(self):
        self.case.receipt["manual_request_sha256"] = "a"*64
        self.case.save_receipt()
        with self.assertRaisesRegex(Hold, "provider_status_not_proven"):
            self.verify()

    def test_manual_receipt_with_a_failed_sparse_step_is_not_accepted(self):
        self.case.receipt["steps"][-1]["exit_code"] = 1
        self.case.save_receipt()
        with self.assertRaisesRegex(Hold, "failed_or_relabelled"):
            self.verify()

    def test_manual_receipt_fails_if_develop_moved_after_completion(self):
        with mock.patch.object(manual, "read_fresh_develop_sha",
                               return_value="a"*40):
            with self.assertRaisesRegex(Hold, "fresh_develop_mismatch"):
                self.case.prove()

    def test_manual_receipt_cannot_inherit_a_github_webhook_observation(self):
        with sqlite3.connect(self.case.db) as db:
            db.execute("INSERT INTO observations VALUES(?,?,?)", (
                "direct-local:foreign", json.dumps({
                    "job_id": self.case.job_id, "event": "push",
                    "proof_kind": "authenticated_queue_admission_not_execution",
                }), "now"))
        with self.assertRaisesRegex(Hold, "missing_or_ambiguous"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
