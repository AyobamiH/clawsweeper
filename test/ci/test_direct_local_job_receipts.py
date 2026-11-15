"""No-provider verification of exact job-level proof from the existing fleet."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_fleet_claim as claims
import direct_local_job_receipts as readback
import direct_local_workflow as router
from estate_policy import Hold


class ExistingFleetOrdinaryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.sha = router.git_head(ROOT)
        self.ref = "main"
        self.job_id = "local-fleet-123456789abc"
        self.log = b"real isolated local step logs\n"
        self.policy = {
            "version": 4, "image": "sha256:" + "b"*64,
            "node_versions": {"24": "/ci-tools/node24/bin/node"},
            "execution_hosts": {router.REPO: os.uname().nodename},
            "repositories": {router.REPO: {
                "branch": "main", "enrolled_head": self.sha,
                "contract": router.sha256(ROOT / ".github/workflows/ci.yml"),
                "suites": {"linux-node24": {
                    "node": "24", "image": "sha256:" + "a"*64,
                    "steps": [{"command": v, "timeout": 600} for v in
                              list(readback.STEP_COMMANDS.values())[1:]],
                }},
            }},
        }
        (self.base / "OWNED_BY_LOCAL_CI").touch()
        (self.base / "control.lock").touch()
        (self.base / "fleet-policy.json").write_text(json.dumps(self.policy))
        (self.base / "evidence" / "fleet").mkdir(parents=True)
        (self.base / "logs" / "fleet").mkdir(parents=True)
        self.db = self.base / "fleet.sqlite3"
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY,repo TEXT,sha TEXT,suite TEXT,policy TEXT,ref TEXT,state TEXT,outcome TEXT,attempt INTEGER,receipt TEXT)")
            db.execute("CREATE TABLE observations (key TEXT PRIMARY KEY,value TEXT,updated_at TEXT)")
        self.receipt_path = self.base / "evidence" / "fleet" / (self.job_id + ".json")
        self.log_path = self.base / "logs" / "fleet" / (self.job_id + ".log")
        self.make_evidence()

    def make_evidence(self, *, with_claim=True):
        names = list(readback.STEP_COMMANDS)
        commands = [
            ("git init -q; git remote add origin https://github.com/AyobamiH/clawsweeper.git; "
             "git -c credential.helper= fetch --quiet --depth=1 origin " + self.sha +
             '; git checkout --quiet --detach FETCH_HEAD; test "$(git rev-parse HEAD)" = "$GITHUB_SHA"'),
            *list(readback.STEP_COMMANDS.values())[1:],
        ]
        self.receipt = {
            "id": self.job_id, "repo": router.REPO, "sha": self.sha,
            "suite": "linux-node24", "policy": claims.reviewed_policy_hash(self.policy),
            "ref": self.ref, "attempt": 1, "outcome": "success",
            "started_at": "2026-11-13T22:00:00Z",
            "finished_at": "2026-11-13T22:01:00Z",
            "mode": "local-scheduler-not-github-actions",
            "cleanup": {"container_absent": True},
            "steps": [{"name": n, "command": c, "exit_code": 0,
                       "started_at": "2026-11-13T22:00:00Z",
                       "finished_at": "2026-11-13T22:01:00Z"}
                      for n, c in zip(names, commands)],
            "log_bytes": len(self.log),
            "log_sha256": hashlib.sha256(self.log).hexdigest(),
        }
        self.save_receipt()
        self.log_path.write_bytes(self.log)
        with sqlite3.connect(self.db) as db:
            db.execute("DELETE FROM jobs")
            db.execute("DELETE FROM observations")
            db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (self.job_id, router.REPO, self.sha, "linux-node24",
                        self.receipt["policy"], self.ref, "completed",
                        "success", 1, str(self.receipt_path)))
            if with_claim:
                record = {
                    "job_id": self.job_id, "source_sha": self.sha,
                    "ref": self.ref, "suite": "linux-node24",
                    "event": "push" if self.ref == "main" else "pull_request",
                    "delivery_sha256": "d"*64,
                    "proof_kind": "authenticated_queue_admission_not_execution",
                    "job_intents": [".github/workflows/ci.yml#check"]
                    if self.ref == "main" else sorted(readback.STEP_FOR_JOB),
                }
                db.execute("INSERT INTO observations VALUES(?,?,?)",
                           ("direct-local:fixture", json.dumps(record), "today"))

    def save_receipt(self):
        self.receipt_path.write_text(json.dumps(self.receipt))

    def prove(self):
        return readback.verify_existing_ordinary_job_receipts(
            fleet_root=self.base, fleet_job_id=self.job_id,
            source_sha=self.sha, source_ref=self.ref)

    def test_authenticated_main_push_is_only_one_job(self):
        verified = self.prove()
        self.assertEqual([x["job"] for x in verified["verified_local_job_steps"]],
                         [".github/workflows/ci.yml#check"])
        self.assertFalse(verified["github_provider_check_independently_verified"])
        self.assertFalse(verified["protected_codeql_satisfied"])

    def test_authenticated_pr_maps_two_steps_to_two_jobs(self):
        self.ref = "pr/113"
        self.make_evidence()
        result = self.prove()
        self.assertEqual(len(result["verified_local_job_steps"]), 2)
        self.assertEqual(len({x["step"] for x in result["verified_local_job_steps"]}), 2)

    def test_legacy_success_without_direct_local_event_is_held(self):
        self.make_evidence(with_claim=False)
        with self.assertRaisesRegex(Hold, "legacy_suite_has_no_authenticated"):
            self.prove()

    def test_missing_step_or_claimed_passing_aggregate_is_held(self):
        self.receipt["steps"][4]["exit_code"] = 1
        self.save_receipt()
        with self.assertRaisesRegex(Hold, "failed_or_relabelled"):
            self.prove()
        self.receipt["steps"][4]["exit_code"] = 0
        self.receipt["steps"][4]["command"] = "echo fake-green"
        self.save_receipt()
        with self.assertRaisesRegex(Hold, "failed_or_relabelled"):
            self.prove()

    def test_log_tampering_is_held(self):
        self.log_path.write_text("changed log")
        with self.assertRaisesRegex(Hold, "log_digest_mismatch"):
            self.prove()

    def test_wrong_source_ref_is_held(self):
        with self.assertRaisesRegex(Hold, "policy_not_pinned_to_exact_source"):
            readback.verify_existing_ordinary_job_receipts(
                fleet_root=self.base, fleet_job_id=self.job_id,
                source_sha="1"*40, source_ref="main")

    def test_changed_event_intents_are_held(self):
        with sqlite3.connect(self.db) as db:
            record = json.loads(db.execute("SELECT value FROM observations").fetchone()[0])
            record["job_intents"].append(".github/workflows/ci.yml#sparse-repair-builds")
            db.execute("UPDATE observations SET value=?", (json.dumps(record),))
        with self.assertRaisesRegex(Hold, "event_job_identity_mismatch"):
            self.prove()

    def test_source_readback_proves_only_authenticated_main_job(self):
        result = readback.verify_current_source_ordinary_jobs(
            fleet_root=self.base, source_sha=self.sha, source_ref="main")
        self.assertEqual(len(result["verified_local_job_steps"]), 1)
        self.assertEqual(result["fleet_job_id"], self.job_id)

    def test_source_readback_proves_two_distinct_pr_steps(self):
        self.ref = "pr/113"
        self.make_evidence()
        result = readback.verify_current_source_ordinary_jobs(
            fleet_root=self.base, source_sha=self.sha, source_ref="pr/113")
        self.assertEqual(len(result["verified_local_job_steps"]), 2)
        self.assertNotEqual(result["verified_local_job_steps"][0]["step"],
                            result["verified_local_job_steps"][1]["step"])

    def test_source_readback_does_not_relabel_legacy_success(self):
        self.make_evidence(with_claim=False)
        with self.assertRaisesRegex(Hold, "legacy_suite_has_no_authenticated"):
            readback.verify_current_source_ordinary_jobs(
                fleet_root=self.base, source_sha=self.sha, source_ref="main")

    def test_source_readback_holds_ambiguous_verified_executions(self):
        second_id = "local-fleet-abcdef123456"
        second_path = self.base / "evidence" / "fleet" / (second_id + ".json")
        second_log = self.base / "logs" / "fleet" / (second_id + ".log")
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO jobs SELECT ?,repo,sha,suite,policy,ref,"
                       "state,outcome,attempt,? FROM jobs WHERE id=?",
                       (second_id, str(second_path), self.job_id))
            claim = json.loads(db.execute("SELECT value FROM observations").fetchone()[0])
            claim["job_id"] = second_id
            db.execute("INSERT INTO observations VALUES (?,?,?)",
                       ("direct-local:another", json.dumps(claim), "today"))
        receipt = dict(self.receipt)
        receipt["id"] = second_id
        second_path.write_text(json.dumps(receipt))
        second_log.write_bytes(self.log)
        with self.assertRaisesRegex(Hold, "ambiguous_multiple_authenticated"):
            readback.verify_current_source_ordinary_jobs(
                fleet_root=self.base, source_sha=self.sha, source_ref="main")

    def test_readback_holds_duplicate_observations_for_one_execution(self):
        with sqlite3.connect(self.db) as db:
            claim = db.execute("SELECT value FROM observations").fetchone()[0]
            db.execute("INSERT INTO observations VALUES (?,?,?)",
                       ("direct-local:duplicated-delivery", claim, "today"))
        with self.assertRaisesRegex(Hold, "ambiguous_authenticated_ordinary_event"):
            self.prove()

    def test_source_readback_holds_failed_parallel_execution(self):
        second_id = "local-fleet-abcdef123456"
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO jobs SELECT ?,repo,sha,suite,policy,ref,"
                       "state,?,attempt,receipt FROM jobs WHERE id=?",
                       (second_id, "failure", self.job_id))
        with self.assertRaisesRegex(Hold, "ambiguous_multiple_authenticated"):
            readback.verify_current_source_ordinary_jobs(
                fleet_root=self.base, source_sha=self.sha, source_ref="main")

    def test_foreign_receipt_path_is_held(self):
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE jobs SET receipt=?", ("/tmp/forged.json",))
        with self.assertRaisesRegex(Hold, "foreign_existing_fleet_receipt_path"):
            self.prove()


if __name__ == "__main__":
    unittest.main()
