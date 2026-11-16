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
        self.assertEqual([x["workflow_job"] for x in verified["verified_aggregate_command_steps"]],
                         [".github/workflows/ci.yml#check"])
        self.assertFalse(verified["github_provider_check_independently_verified"])
        self.assertFalse(verified["protected_codeql_satisfied"])

    def test_authenticated_pr_two_steps_are_not_two_independent_executions(self):
        self.ref = "pr/113"
        self.make_evidence()
        result = self.prove()
        self.assertEqual(len(result["verified_aggregate_command_steps"]), 2)
        self.assertEqual(len({x["step"] for x in result["verified_aggregate_command_steps"]}), 2)
        self.assertEqual(len({x["fleet_job_id"] for x in result["verified_aggregate_command_steps"]}), 1)
        self.assertEqual(result["aggregate_fleet_execution_id_count"], 1)
        self.assertEqual(result["independent_definition_execution_ids"], [])
        self.assertEqual(result["independent_definition_sandboxes_verified"], 0)
        self.assertEqual(result["accepted_independent_ordinary_jobs"], 0)
        self.assertEqual(result["acceptance_hold"],
                         "distinct_per_definition_job_ids_and_sandboxes_not_proven")

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
        self.assertEqual(len(result["verified_aggregate_command_steps"]), 1)
        self.assertEqual(result["fleet_job_id"], self.job_id)

    def test_source_readback_proves_two_distinct_pr_steps(self):
        self.ref = "pr/113"
        self.make_evidence()
        result = readback.verify_current_source_ordinary_jobs(
            fleet_root=self.base, source_sha=self.sha, source_ref="pr/113")
        self.assertEqual(len(result["verified_aggregate_command_steps"]), 2)
        self.assertNotEqual(result["verified_aggregate_command_steps"][0]["step"],
                            result["verified_aggregate_command_steps"][1]["step"])

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




class DistinctOrdinaryTerminalReceiptTests(unittest.TestCase):
    def setUp(self):
        from test_direct_local_distinct_admission import DistinctExistingFleetAdmissionTests
        import direct_local_distinct_admission as split
        self.split = split
        self.fixture = DistinctExistingFleetAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.sha = self.fixture.head
        self.controller_data = b"exact-reviewed-test-fleet-controller\n"
        self.controller_hash = hashlib.sha256(self.controller_data).hexdigest()
        (self.base / "fleet_ci.py").write_bytes(self.controller_data)
        (self.base / "evidence" / "fleet").mkdir(parents=True)
        (self.base / "logs" / "fleet").mkdir(parents=True)
        result = self.fixture.claim()
        self.assertEqual(result["admission"], "queued")
        self.entries = result["jobs"]
        self.receipts = {}
        for entry in self.entries:
            job_id = entry["job_id"]
            definition = entry["workflow_job"]
            data = b"real direct local job evidence " + job_id.encode()
            checkout = ("git init -q; git remote add origin https://github.com/AyobamiH/clawsweeper.git; "
                        "git -c credential.helper= fetch --quiet --depth=1 origin " + self.sha +
                        '; git checkout --quiet --detach FETCH_HEAD; test "$(git rev-parse HEAD)" = "$GITHUB_SHA"')
            steps = [{"name": "Exact commit checkout", "command": checkout, "exit_code": 0}]
            steps += [{"name": label, "command": command, "exit_code": 0}
                      for label, command in
                      (*split.SETUP, (split.TERMINAL_NAME[definition], split.SPLIT[definition][1]))]
            receipt = {
                "id": job_id, "repo": router.REPO, "sha": self.sha,
                "ref": "pr/101", "suite": entry["suite"],
                "policy": entry["policy"], "attempt": 1,
                "outcome": "success", "mode": "local-scheduler-not-github-actions",
                "executor": "web/docker", "sandbox_identity": job_id,
                "engine_container_id": hashlib.sha256(job_id.encode()).hexdigest(),
                "image": self.fixture.policy["repositories"][router.REPO][
                    "suites"][entry["suite"]]["image"],
                "isolation": "unprivileged Docker container with no host socket or personal files",
                "resource_limits": {field: self.fixture.policy["repositories"][router.REPO][
                    "suites"][entry["suite"]][field]
                    for field in ("cpus", "memory_mib", "pids", "writable_mib")}
                    | {"host_cpu_affinity": [0, 1, 2, 3]},
                "controller_sha256": self.controller_hash,
                "started_at": "2026-11-16T18:00:00Z",
                "finished_at": "2026-11-16T18:01:00Z",
                "cleanup": {"container_absent": True,
                            "workspace_and_dependency_cache_removed": True},
                "steps": steps, "log_bytes": len(data),
                "log_sha256": hashlib.sha256(data).hexdigest(),
            }
            self.receipts[job_id] = receipt
            self.save_receipt(job_id)
            (self.base / "logs" / "fleet" / (job_id + ".log")).write_bytes(data)
            with sqlite3.connect(self.base / "fleet.sqlite3") as db:
                db.execute("UPDATE jobs SET state='completed',outcome='success',"
                           "attempt=1,receipt=? WHERE id=?",
                           (str(self.base / "evidence" / "fleet" / (job_id + ".json")), job_id))

    def save_receipt(self, job_id):
        (self.base / "evidence" / "fleet" / (job_id + ".json")).write_text(
            json.dumps(self.receipts[job_id]))

    def prove(self, **overrides):
        return readback.verify_distinct_ordinary_definition_receipts(
            checkout=ROOT, fleet_root=self.base, source_sha=self.sha,
            source_ref="pr/101",
            reviewed_controller_sha256=overrides.get("controller_hash", self.controller_hash))

    def test_two_real_job_ids_and_independent_sandbox_receipts(self):
        result = self.prove()
        self.assertEqual(result["accepted_independent_ordinary_jobs"], 2)
        self.assertEqual(len(result["independent_definition_jobs"]), 2)
        self.assertEqual(len({r["sandbox_identity"] for r in result["independent_definition_jobs"]}), 2)
        self.assertFalse(result["github_provider_checks_verified"])
        self.assertFalse(result["protected_codeql_satisfied"])

    def test_single_aggregate_success_cannot_replace_two_jobs(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute("UPDATE jobs SET suite='linux-node24' WHERE id=?",
                       (self.entries[0]["job_id"],))
        with self.assertRaisesRegex(Hold, "unrecognised_or_ambiguous"):
            self.prove()

    def test_independent_sandbox_identity_missing_or_reused(self):
        a, b = (e["job_id"] for e in self.entries)
        for replacement in (None, a):
            self.receipts[b]["sandbox_identity"] = replacement
            self.save_receipt(b)
            with self.assertRaisesRegex(Hold, "incomplete_distinct_sandbox"):
                self.prove()

    def test_failed_or_unreviewed_command_never_passes(self):
        ident = self.entries[0]["job_id"]
        for replacement in (1, True):
            self.receipts[ident]["steps"][-1]["exit_code"] = replacement
            self.save_receipt(ident)
            with self.assertRaisesRegex(Hold, "distinct_sandbox_command"):
                self.prove()

    def test_modified_provenance_or_duplicate_ownership_holds(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            key, raw = db.execute("SELECT key,value FROM observations").fetchone()
            data = json.loads(raw)
            data["jobs"][0]["policy"] = "0" * 64
            db.execute("UPDATE observations SET value=? WHERE key=?",
                       (json.dumps(data), key))
        with self.assertRaisesRegex(Hold, "distinct_job_policy"):
            self.prove()

    def test_controller_mismatch_or_log_tampering_holds(self):
        with self.assertRaisesRegex(Hold, "controller_digest"):
            self.prove(controller_hash="0" * 64)
        ident = self.entries[0]["job_id"]
        (self.base / "logs" / "fleet" / (ident + ".log")).write_bytes(b"changed")
        with self.assertRaisesRegex(Hold, "incomplete_distinct_sandbox"):
            self.prove()

    def test_engine_container_identity_must_be_distinct_and_trusted(self):
        a, b = (e["job_id"] for e in self.entries)
        self.receipts[b]["engine_container_id"] = self.receipts[a]["engine_container_id"]
        self.save_receipt(b)
        with self.assertRaisesRegex(Hold, "shared_distinct_fleet_sandbox"):
            self.prove()
        self.receipts[b]["engine_container_id"] = "not-an-engine-id"
        self.save_receipt(b)
        with self.assertRaisesRegex(Hold, "incomplete_distinct_sandbox"):
            self.prove()

    def test_resource_or_image_expansion_cannot_be_accepted(self):
        job = self.entries[0]["job_id"]
        self.receipts[job]["resource_limits"]["memory_mib"] *= 2
        self.save_receipt(job)
        with self.assertRaisesRegex(Hold, "incomplete_distinct_sandbox"):
            self.prove()

    def test_pending_or_retried_attempt_cannot_claim_acceptance(self):
        ident = self.entries[0]["job_id"]
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute("UPDATE jobs SET attempt=2 WHERE id=?", (ident,))
        with self.assertRaisesRegex(Hold, "not_terminal_first_attempt"):
            self.prove()


if __name__ == "__main__":
    unittest.main()
