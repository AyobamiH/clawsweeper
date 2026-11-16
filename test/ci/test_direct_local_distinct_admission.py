"""Source-only two-job atomic admission using existing local fleet (no workers)."""
import copy
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_distinct_admission as split
import direct_local_fleet_claim as fleet
import direct_local_workflow as router
from estate_policy import Hold


class DistinctExistingFleetAdmissionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.head = router.git_head(ROOT)
        self.secret = b"bounded-signature-fixture-" * 3
        profile = {
            "node": "24", "image": "sha256:" + "a" * 64,
            "cpus": 4, "memory_mib": 3072, "pids": 512,
            "writable_mib": 4096, "execution_environment_revision": "reviewed-local-test",
        }
        base = {**profile, "steps": [
            {"name": n, "command": c, "timeout": 600}
            for n, c in [*split.SETUP,
                         (split.TERMINAL_NAME[".github/workflows/ci.yml#check"], "pnpm run check"),
                         (split.TERMINAL_NAME[".github/workflows/ci.yml#sparse-repair-builds"],
                          "pnpm run test:workflow-sparse-checkout")]]}
        suites = {"linux-node24": base}
        for name, (suite, final) in split.SPLIT.items():
            suites[suite] = {
                **profile, "steps": [
                    {"name": n, "command": c, "timeout": 600}
                    for n, c in [*split.SETUP, (split.TERMINAL_NAME[name], final)]
                ]}
        self.policy = {
            "version": 4, "image": "sha256:" + "b" * 64,
            "node_versions": {"24": "/ci-tools/node24/bin/node"},
            "execution_hosts": {router.REPO: os.uname().nodename},
            "repositories": {router.REPO: {
                "branch": "main", "enrolled_head": self.head,
                "contract": router.sha256(ROOT / ".github/workflows/ci.yml"),
                "suites": suites,
            }},
        }
        self.policy_path = self.base / "fleet-policy.json"
        self.write_policy()
        (self.base / "OWNED_BY_LOCAL_CI").touch()
        (self.base / "control.lock").touch()
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE jobs (
                    id TEXT PRIMARY KEY, repo TEXT NOT NULL, sha TEXT NOT NULL,
                    suite TEXT NOT NULL, policy TEXT NOT NULL, ref TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'queued', attempt INTEGER NOT NULL DEFAULT 0,
                    ready_at REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, outcome TEXT, receipt TEXT,
                    reported INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(repo,sha,suite,policy));
                CREATE TABLE observations (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
            """)
        self.delivery = "01234567-89ab-cdef-0123-456789abcdef"
        self.payload = {
            "repository": {"full_name": router.REPO}, "action": "synchronize",
            "pull_request": {
                "number": 101, "state": "open", "draft": False,
                "user": {"login": "AyobamiH"},
                "head": {"sha": self.head, "repo": {"full_name": router.REPO}},
                "base": {"ref": "main", "repo": {"full_name": router.REPO}},
            },
        }

    def write_policy(self):
        self.policy_path.write_text(json.dumps(self.policy))

    def claim(self, *, body_payload=None, event_name="pull_request", signature=None,
              delivery_id=None, ref_sha=None):
        body = json.dumps(body_payload or self.payload).encode()
        signed = signature or "sha256=" + hmac.new(
            self.secret, body, hashlib.sha256).hexdigest()
        return split.claim_distinct_existing_fleet_jobs(
            checkout=ROOT, fleet_root=self.base, body=body,
            event_name=event_name, signature=signed,
            delivery_id=delivery_id or self.delivery, secret=self.secret,
            fresh_ref_sha=ref_sha or self.head)

    def rows(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            return db.execute("SELECT id,suite,state FROM jobs ORDER BY suite").fetchall()

    def test_pr_claims_two_independently_identified_jobs_atomically(self):
        first = self.claim()
        rows = self.rows()
        self.assertEqual(first["admission"], "queued")
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({r[0] for r in rows}), 2)
        self.assertEqual({r[1] for r in rows},
                         {s for s, _ in split.SPLIT.values()})
        self.assertEqual(first["accepted_independent_jobs"], 0)
        self.assertEqual(first["independent_jobs_executed"], 0)
        self.assertFalse(first["github_actions_dispatched"])
        replay = self.claim()
        self.assertEqual(replay["admission"], "already_admitted")
        self.assertEqual(replay["jobs"], first["jobs"])
        self.assertEqual(self.rows(), rows)
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM observations").fetchone()[0], 1)

    def test_main_only_claims_check_not_sparse(self):
        event = {
            "repository": {"full_name": router.REPO},
            "ref": "refs/heads/main", "after": self.head,
            "deleted": False, "forced": False, "size": 1,
            "distinct_size": 1,
            "commits": [{"id": self.head, "added": [], "removed": [],
                         "modified": ["src/clawsweeper.ts"]}],
            "head_commit": {"id": self.head},
        }
        result = self.claim(body_payload=event, event_name="push")
        self.assertEqual(len(result["jobs"]), 1)
        self.assertEqual(result["jobs"][0]["workflow_job"],
                         ".github/workflows/ci.yml#check")
        self.assertEqual(len(self.rows()), 1)

    def test_missing_or_mutable_split_profile_holds_without_queue_write(self):
        policy = copy.deepcopy(self.policy)
        del policy["repositories"][router.REPO]["suites"]["linux-node24-claw-sparse"]
        self.policy = policy
        self.write_policy()
        with self.assertRaisesRegex(Hold, "suite_not_installed"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_unexpected_code_or_privilege_injected_into_split_suite_holds(self):
        cfg = self.policy["repositories"][router.REPO]["suites"]["linux-node24-claw-sparse"]
        cfg["steps"].append({"name": "extra", "command": "echo bypass", "timeout": 5})
        self.write_policy()
        with self.assertRaisesRegex(Hold, "command_contract_drift"):
            self.claim()
        self.assertEqual(self.rows(), [])
        cfg["steps"].pop()
        cfg["secrets"] = ["unexpected"]
        self.write_policy()
        with self.assertRaisesRegex(Hold, "resource_or_image_drift"):
            self.claim()
        self.assertEqual(self.rows(), [])
        del cfg["secrets"]
        cfg["steps"][0]["env"] = {"UNREVIEWED_CODE": "1"}
        self.write_policy()
        with self.assertRaisesRegex(Hold, "command_contract_drift"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_recycled_delivery_id_changed_signed_payload_holds(self):
        self.claim()
        other = copy.deepcopy(self.payload)
        other["unexpected"] = "changed"
        with self.assertRaisesRegex(Hold, "changed_signed_distinct"):
            self.claim(body_payload=other)
        self.assertEqual(len(self.rows()), 2)

    def test_new_delivery_id_cannot_relabel_existing_split_jobs(self):
        self.claim()
        with self.assertRaisesRegex(Hold, "foreign_independent_execution"):
            self.claim(delivery_id="11234567-89ab-cdef-0123-456789abcdef")
        self.assertEqual(len(self.rows()), 2)

    def test_legacy_aggregate_or_delivery_cannot_be_relabelled(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute(
                "INSERT INTO jobs(id,repo,sha,suite,policy,ref,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                ("local-fleet-111111111111", router.REPO, self.head, fleet.SUITE,
                 fleet.reviewed_policy_hash(self.policy), "pr/101", "now", "now"))
        with self.assertRaisesRegex(Hold, "aggregate_execution"):
            self.claim()
        self.assertEqual(len(self.rows()), 1)

    def test_hmac_and_fresh_remote_sha_required(self):
        with self.assertRaisesRegex(Hold, "invalid_webhook_hmac"):
            self.claim(signature="sha256=" + "0" * 64)
        with self.assertRaises(Hold):
            self.claim(ref_sha="1" * 40)
        self.assertEqual(self.rows(), [])

    def test_owner_lock_and_untrusted_queue_schema_hold(self):
        fd = os.open(self.base / "control.lock", os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaisesRegex(Hold, "owner_is_active"):
                self.claim()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute("DROP TABLE observations")
        with self.assertRaisesRegex(Hold, "queue_schema"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_partial_existing_split_job_is_not_claimed_or_retired(self):
        suite = "linux-node24-claw-check"
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute(
                "INSERT INTO jobs(id,repo,sha,suite,policy,ref,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                ("local-fleet-111111111111", router.REPO, self.head, suite,
                 "0" * 64, "pr/101", "now", "now"))
        with self.assertRaisesRegex(Hold, "foreign_independent_execution"):
            self.claim()
        self.assertEqual(len(self.rows()), 1)


if __name__ == "__main__":
    unittest.main()
