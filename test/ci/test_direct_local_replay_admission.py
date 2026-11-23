"""SQLite, signature, rollback and no-provider gates for the third job."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_replay_admission as a
from estate_policy import Hold
from test_direct_local_offline_replay_suite import policy as baseline


class ReplayAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sha = a.estate.git_head(ROOT)
        p = baseline()
        p["version"] = 1
        p["image"] = a.suite.PINNED_IMAGE
        p["node_versions"] = {"24": "v24.9.0"}
        p["repositories"][a.REPO]["enrolled_head"] = self.sha
        with mock.patch.object(a.suite, "source_clean"):
            p["repositories"][a.REPO]["suites"][a.SUITE] = (
                a.suite.prepare(ROOT, p)["suite"])
        self.policy = p
        for name in ("OWNED_BY_LOCAL_CI", "control.lock"):
            (self.root/name).write_text("existing-fleet")
        self.anchor_dir = self.root / "state/fleet/repository-evidence-holds"
        self.anchor_dir.mkdir(parents=True, mode=0o700)
        self.write_policy()
        self.dbpath = self.root / "fleet.sqlite3"
        with sqlite3.connect(self.dbpath) as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE jobs(
                    id TEXT PRIMARY KEY, repo TEXT NOT NULL,
                    sha TEXT NOT NULL, suite TEXT NOT NULL, policy TEXT NOT NULL,
                    ref TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
                    attempt INTEGER NOT NULL DEFAULT 0,
                    ready_at REAL NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    outcome TEXT, receipt TEXT, reported INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(repo,sha,suite,policy));
                CREATE TABLE observations(
                    key TEXT PRIMARY KEY, value TEXT NOT NULL,
                    updated_at TEXT NOT NULL);
                CREATE TABLE repository_evidence_holds(
                    repo TEXT PRIMARY KEY NOT NULL,
                    job_id TEXT NOT NULL,
                    source_sha TEXT NOT NULL,
                    suite TEXT NOT NULL,
                    policy_sha TEXT NOT NULL,
                    reason TEXT NOT NULL
                        CHECK(reason = 'generation_mixed_or_untrusted_sources'),
                    controller_sha TEXT NOT NULL,
                    proof_sha TEXT NOT NULL,
                    recorded_at TEXT NOT NULL);
            """)
        now = int(time.time())
        self.intent = {
            "schema": a.contract.INTENT_SCHEMA, "repo": a.REPO,
            "source_sha": self.sha, "source_ref": "main", "host": "web",
            "suite": a.SUITE, "job_intents": [a.JOB],
            "purpose": "effect-free-offline-replay-validation",
            "nonce": "a" * 32, "issued_at": now, "expires_at": now + 600,
        }
        self.request = self.root / "intent.json"
        self.signature = self.root / "intent.sig"
        self.signature.write_bytes(b"-----BEGIN SSH SIGNATURE-----\nTEST\n")
        self.signature.chmod(0o600)
        self.write_intent()
        patchers = [
            mock.patch.object(a.contract, "verify_owner_intent"),
            mock.patch.object(a.contract, "read_fresh_main_sha", return_value=self.sha),
            mock.patch.object(a.suite, "source_clean"),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def write_intent(self):
        self.request.write_bytes(a.contract.canonical(self.intent))
        self.request.chmod(0o600)

    def write_policy(self):
        file = self.root / "fleet-policy.json"
        file.write_text(json.dumps(self.policy, sort_keys=True))
        file.chmod(0o600)

    def call(self):
        return a.claim_owner_signed_replay(
            checkout=ROOT, fleet_root=self.root,
            request_file=self.request, signature_file=self.signature)

    def mutate_db(self, sql, params=()):
        with sqlite3.connect(self.dbpath) as db:
            db.execute(sql, params)

    def counts(self):
        with sqlite3.connect(self.dbpath) as db:
            return (
                db.execute("SELECT count(*) FROM jobs").fetchone()[0],
                db.execute("SELECT count(*) FROM observations").fetchone()[0],
            )

    def test_existing_durable_repository_hold_prevents_any_claim(self):
        self.mutate_db(
            "INSERT INTO repository_evidence_holds("
            "repo,job_id,source_sha,suite,policy_sha,reason,"
            "controller_sha,proof_sha,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (a.REPO, "local-fleet-bf40e3b5fe1b", "9" * 40,
             "linux-node24-claw-check", "a" * 64,
             "generation_mixed_or_untrusted_sources", "b" * 64,
             "c" * 64, "2026-11-23T06:00:00+00:00"))
        with self.assertRaisesRegex(Hold, "replay_repository_evidence_held"):
            self.call()
        self.assertEqual(self.counts(), (0, 0))
        with sqlite3.connect(self.dbpath) as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM repository_evidence_holds").fetchone()[0], 1)

    def test_orphaned_hold_anchor_rejects_new_claim(self):
        marker = self.anchor_dir / (
            hashlib.sha256(a.REPO.encode()).hexdigest() + ".json")
        marker.write_text("incomplete-after-crash")
        with self.assertRaisesRegex(Hold, "replay_repository_evidence_held"):
            self.call()
        self.assertEqual(self.counts(), (0, 0))

    def test_orphaned_hold_signature_rejects_new_claim(self):
        marker = self.anchor_dir / (
            hashlib.sha256(a.REPO.encode()).hexdigest() + ".sig")
        marker.write_text("partially-recovered-signed-hold")
        with self.assertRaisesRegex(Hold, "replay_repository_evidence_held"):
            self.call()
        self.assertEqual(self.counts(), (0, 0))

    def test_existing_claim_cannot_start_after_hold_anchor_arrives(self):
        job_id = self.call()["jobs"][0]["job_id"]
        marker = self.anchor_dir / (
            hashlib.sha256(a.REPO.encode()).hexdigest() + ".json")
        marker.write_text("signed-hold-recovery-is-still-in-progress")
        with self.assertRaisesRegex(Hold, "replay_repository_evidence_held"):
            a.verify_existing_replay(
                checkout=ROOT, fleet_root=self.root, job_id=job_id)
        self.assertEqual(self.counts(), (1, 1))

    def test_hold_anchor_directory_permissions_fail_closed(self):
        self.anchor_dir.chmod(0o755)
        with self.assertRaisesRegex(Hold, "replay_repository_hold_anchor_untrusted"):
            self.call()
        self.assertEqual(self.counts(), (0, 0))

    def test_missing_hold_schema_fails_closed_before_admission(self):
        self.mutate_db("DROP TABLE repository_evidence_holds")
        with self.assertRaisesRegex(Hold, "replay_repository_hold_schema_unverifiable"):
            self.call()
        self.assertEqual(self.counts(), (0, 0))

    def test_one_real_sqlite_admission_is_idempotent_not_execution(self):
        first = self.call()
        second = self.call()
        self.assertEqual(first["admission"], "queued")
        self.assertEqual(second["admission"], "already_admitted")
        self.assertEqual(first["jobs"], second["jobs"])
        self.assertEqual(self.counts(), (1, 1))
        self.assertFalse(first["runner_started"])
        self.assertFalse(first["github_provider_status_published"])
        verified = a.verify_existing_replay(
            checkout=ROOT, fleet_root=self.root,
            job_id=first["jobs"][0]["job_id"])
        self.assertTrue(verified["verified_owner_origin"])
        self.assertFalse(verified["provider_status_authorised"])
        self.assertEqual(verified["queue_state"], "queued")

    def test_new_nonce_cannot_replay_a_prior_unique_suite_job(self):
        self.call()
        self.intent["nonce"] = "b" * 32
        self.write_intent()
        with self.assertRaisesRegex(Hold, "unrelated_job"):
            self.call()
        self.assertEqual(self.counts(), (1, 1))

    def test_nonce_collision_rejects_changed_signed_payload(self):
        self.call()
        self.intent["expires_at"] += 1
        self.write_intent()
        with self.assertRaises(Hold):
            self.call()
        self.assertEqual(self.counts(), (1, 1))

    def test_old_two_job_nonce_is_not_transferable(self):
        old_key = a.OLD_PREFIX + a._nonce_key(self.intent)
        self.mutate_db(
            "INSERT INTO observations(key,value,updated_at) VALUES(?,?,?)",
            (old_key, "{}", "2026-11-20"))
        with self.assertRaisesRegex(Hold, "prior_split_owner_nonce"):
            self.call()
        self.assertEqual(self.counts(), (0, 1))

    def test_fresh_main_drift_is_terminal_hold_before_insert(self):
        with mock.patch.object(a.contract, "read_fresh_main_sha",
                               return_value="b" * 40):
            with self.assertRaisesRegex(Hold, "no_longer_main"):
                self.call()
        self.assertEqual(self.counts(), (0, 0))

    def test_sandbox_policy_source_or_command_drift_blocks_admission(self):
        for mutate in (
            lambda p: p["repositories"][a.REPO].update(
                {"enrolled_head": "f"*40}),
            lambda p: p["repositories"][a.REPO]["suites"][a.SUITE]
                ["steps"][2].update({"command": "echo pretend"}),
            lambda p: p["repositories"][a.REPO]["suites"][a.SUITE]
                .update({"memory_mib": 9999}),
        ):
            with self.subTest(mutate=repr(mutate)):
                current = copy.deepcopy(self.policy)
                mutate(self.policy)
                self.write_policy()
                with self.assertRaises(Hold):
                    self.call()
                self.policy = current
                self.write_policy()
        self.assertEqual(self.counts(), (0, 0))

    def test_worker_cannot_accept_changed_existing_job_or_envelope(self):
        job_id = self.call()["jobs"][0]["job_id"]
        self.mutate_db("UPDATE jobs SET ref=? WHERE id=?", ("main", job_id))
        with self.assertRaisesRegex(Hold, "relabelled"):
            a.verify_existing_replay(
                checkout=ROOT, fleet_root=self.root, job_id=job_id)
        self.mutate_db("UPDATE jobs SET ref=? WHERE id=?", (a.REF, job_id))
        self.mutate_db(
            "UPDATE observations SET value=?",
            ('{"proof_kind":"invented","jobs":[]}',))
        with self.assertRaises(Hold):
            a.verify_existing_replay(
                checkout=ROOT, fleet_root=self.root, job_id=job_id)

    def test_worker_fails_closed_on_remote_main_drift(self):
        job_id = self.call()["jobs"][0]["job_id"]
        with mock.patch.object(a.contract, "read_fresh_main_sha",
                               return_value="c"*40):
            with self.assertRaisesRegex(Hold, "before_worker_start"):
                a.verify_existing_replay(
                    checkout=ROOT, fleet_root=self.root, job_id=job_id)

    def test_collision_with_existing_unproved_job_refused(self):
        self.mutate_db(
            "INSERT INTO jobs(id,repo,sha,suite,policy,ref,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            ("local-fleet-abcdef123456", a.REPO, self.sha, a.SUITE,
             a._policy_hash(self.policy), "main", "2026", "2026"))
        with self.assertRaisesRegex(Hold, "unrelated_job"):
            self.call()
        self.assertEqual(self.counts(), (1, 0))

    def test_missing_signature_and_duplicate_json_are_holds(self):
        self.signature.unlink()
        with self.assertRaises(Hold):
            self.call()
        self.signature.write_text("present")
        self.signature.chmod(0o600)
        self.request.write_bytes(
            self.request.read_bytes().replace(
                b'"nonce":', b'"nonce":"f","nonce":'))
        with self.assertRaises(Hold):
            self.call()
        self.assertEqual(self.counts(), (0, 0))

    def test_bad_installed_suite_and_state_prevent_relabelling(self):
        job_id = self.call()["jobs"][0]["job_id"]
        self.mutate_db("UPDATE jobs SET state=? WHERE id=?", ("cancelled", job_id))
        with self.assertRaisesRegex(Hold, "relabelled"):
            self.call()
        self.assertEqual(self.counts(), (1, 1))


if __name__ == "__main__":
    unittest.main()
