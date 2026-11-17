"""Signed local-manual admission must create two *real* queue identities, not one aggregate."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_signed_split_manual as subject
from estate_policy import Hold

BASE = ROOT / "test/ci/test_direct_local_distinct_admission.py"
spec = importlib.util.spec_from_file_location("reviewed_split_test_fixture", BASE)
fixture_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_mod)

class OwnerSignedSplitManualTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_mod.DistinctExistingFleetAdmissionTests(
            "test_policy_proposal_adds_only_two_exact_isolated_suites")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.sha = self.fixture.head
        now = int(time.time())
        self.doc = {
            "schema": subject.SCHEMA, "repo": subject.REPO,
            "source_sha": self.sha, "source_ref": "develop",
            "host": os.uname().nodename, "suite": subject.SUITE,
            "job_intents": list(subject.JOBS),
            "purpose": "ordinary-source-validation",
            "nonce": "a" * 32, "issued_at": now,
            "expires_at": now + 600,
        }
        self.request = self.base/"owner-intent.json"
        self.signature = self.base/"owner-intent.sig"
        self.signers = self.base/"allowed_signers"
        self.signers.write_text("fake-test-owner")
        self.signers.chmod(0o600)
        self.signature.write_bytes(b"untrusted-fixture-signature")
        self.signature.chmod(0o600)
        self.save_doc()
        self.stubs = [
            mock.patch.object(subject.fleet,"checked_fleet_root",
                              return_value=self.base),
            mock.patch.object(subject.auth,"owner_allowed_signers",
                              return_value=self.signers),
            mock.patch.object(subject.auth,"verify_owner_signature_bytes",
                              return_value=None),
            mock.patch.object(subject.auth,"read_fresh_develop_sha",
                              return_value=self.sha),
        ]
        for patcher in self.stubs:
            patcher.start()
            self.addCleanup(patcher.stop)

    def save_doc(self):
        self.request.write_text(json.dumps(self.doc))
        self.request.chmod(0o600)

    def claim(self):
        return subject.claim_owner_signed_split_manual_run(
            checkout=ROOT, fleet_root=self.base,
            request_file=self.request, signature_file=self.signature)

    def jobs(self):
        with sqlite3.connect(self.base/"fleet.sqlite3") as db:
            return db.execute(
                "SELECT id,sha,suite,policy,ref,state FROM jobs ORDER BY suite"
            ).fetchall()

    def observations(self):
        with sqlite3.connect(self.base/"fleet.sqlite3") as db:
            return db.execute("SELECT key,value FROM observations").fetchall()

    def test_real_sqlite_atomic_pair_and_idempotent_claim(self):
        outcome = self.claim()
        self.assertEqual(outcome["admission"],"queued")
        self.assertEqual(outcome["jobs_executed"],0)
        self.assertFalse(outcome["github_actions_dispatched"])
        jobs=self.jobs()
        self.assertEqual(len(jobs),2)
        self.assertEqual(len({j[0] for j in jobs}),2)
        self.assertEqual({j[2] for j in jobs},
                         {"linux-node24-claw-check","linux-node24-claw-sparse"})
        self.assertEqual({j[4] for j in jobs},{"local-manual"})
        self.assertEqual({j[1] for j in jobs},{self.sha})
        self.assertEqual(len(self.observations()),1)
        for row in jobs:
            proof=subject.verify_existing_split_manual_claim(
                fleet_root=self.base,job_id=row[0])
            self.assertTrue(proof["verified_owner_origin"])
            self.assertFalse(proof["provider_status_authorised"])
        again = self.claim()
        self.assertEqual(again["admission"],"already_admitted")
        self.assertEqual(again["jobs"],outcome["jobs"])
        self.assertEqual(len(self.jobs()),2)

    def test_wrong_intent_scope_is_rejected_before_db_mutation(self):
        for change in ("suite", "jobs", "source", "expiry", "schema"):
            old=copy.deepcopy(self.doc)
            if change=="suite":self.doc["suite"]="linux-node24"
            elif change=="jobs":self.doc["job_intents"]=[".github/workflows/ci.yml#check"]
            elif change=="source":self.doc["source_sha"]="b"*40
            elif change=="expiry":self.doc["expires_at"]=self.doc["issued_at"]-1
            elif change=="schema":self.doc["schema"]="clawsweeper.owner-signed-local-manual-request.v1"
            self.save_doc()
            with self.subTest(change=change), self.assertRaises(Hold):
                self.claim()
            self.assertEqual(self.jobs(),[])
            self.assertEqual(self.observations(),[])
            self.doc=old
        self.save_doc()

    def test_missing_sibling_queue_row_rejects_worker_and_replay(self):
        first=self.claim()
        with sqlite3.connect(self.base/"fleet.sqlite3") as db:
            db.execute("DELETE FROM jobs WHERE id=?",(first["jobs"][1]["job_id"],))
        for method in (lambda:subject.verify_existing_split_manual_claim(
                           fleet_root=self.base,job_id=first["jobs"][0]["job_id"]),
                       self.claim):
            with self.assertRaises(Hold): method()

    def test_changed_sibling_policy_or_ledger_rejected(self):
        first=self.claim()
        with sqlite3.connect(self.base/"fleet.sqlite3") as db:
            db.execute("UPDATE jobs SET policy=? WHERE id=?",
                       ("a"*64,first["jobs"][1]["job_id"]))
        with self.assertRaises(Hold):
            subject.verify_existing_split_manual_claim(
                fleet_root=self.base,job_id=first["jobs"][0]["job_id"])

    def test_nonce_collision_is_not_a_second_execution(self):
        self.claim()
        self.doc["purpose"]="another-authority"
        self.save_doc()
        with self.assertRaises(Hold):
            self.claim()
        self.assertEqual(len(self.jobs()),2)

    def test_old_aggregate_request_not_accepted(self):
        self.doc["schema"]="clawsweeper.owner-signed-local-manual-request.v1"
        self.doc["suite"]="linux-node24"
        self.save_doc()
        with self.assertRaises(Hold):
            self.claim()
        self.assertFalse(self.jobs())
        self.assertFalse(self.observations())

    def test_requires_real_signer_verification(self):
        with mock.patch.object(subject.auth,"verify_owner_signature_bytes",
                               side_effect=Hold("bad_owner_signature")):
            with self.assertRaisesRegex(Hold,"bad_owner_signature"):
                self.claim()
        self.assertFalse(self.jobs())

if __name__=="__main__":
    unittest.main()
