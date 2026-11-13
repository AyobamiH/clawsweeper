"""No-provider proof: reuse the existing fleet WAL queue, not a second scheduler."""
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
import direct_local_fleet_claim as claims
import direct_local_workflow as router
from estate_policy import Hold


class ExistingFleetAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.head = router.git_head(ROOT)
        self.secret = b"local-HMAC-fixture-" * 4
        self.policy = {
            "version": 4, "image": "sha256:" + "b" * 64,
            "node_versions": {"24": "/ci-tools/node24/bin/node"},
            "execution_hosts": {router.REPO: os.uname().nodename},
            "repositories": {router.REPO: {
                "branch": "main", "enrolled_head": self.head,
                "contract": router.sha256(ROOT / ".github/workflows/ci.yml"),
                "suites": {"linux-node24": {
                    "node": "24", "image": "sha256:" + "a" * 64,
                    "steps": [
                        {"command": """actionlint -shellcheck= -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml""", "timeout": 600},
                        {"command": "pnpm install --frozen-lockfile", "timeout": 600},
                        {"command": "pnpm run check", "timeout": 1800},
                        {"command": "pnpm run test:workflow-sparse-checkout", "timeout": 600},
                    ],
                }},
            }},
        }
        (self.base / "OWNED_BY_LOCAL_CI").touch()
        (self.base / "control.lock").touch()
        (self.base / "fleet-policy.json").write_text(json.dumps(self.policy))
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
        self.payload = {
            "repository": {"full_name": router.REPO},
            "ref": "refs/heads/main", "after": self.head,
            "deleted": False, "forced": False,
        }

    def claim(self, *, payload=None, event_name="push", secret=None,
              signature=None, ref_sha=None, delivery_id=None):
        body = json.dumps(payload or self.payload).encode()
        secret = secret if secret is not None else self.secret
        signature = (signature if signature is not None else
                     "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest())
        return claims.claim_existing_fleet_delivery(
            checkout=ROOT, fleet_root=self.base, body=body,
            event_name=event_name, signature=signature, secret=secret,
            delivery_id=delivery_id or "01234567-89ab-cdef-0123-456789abcdef",
            fresh_ref_sha=ref_sha or self.head)

    def rows(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            return db.execute("SELECT id,repo,sha,suite,ref,state FROM jobs").fetchall()

    def test_exact_main_push_durable_queue_then_idempotent_redelivery(self):
        first = self.claim()
        second = self.claim()
        self.assertEqual(first["admission"], "queued")
        self.assertEqual(second["admission"], "already_admitted")
        self.assertEqual(first["existing_fleet_job_id"], second["existing_fleet_job_id"])
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0][-1], "queued")
        self.assertFalse(first["job_executed"])
        self.assertFalse(first["github_status_published"])
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            records = db.execute("SELECT key,value FROM observations").fetchall()
        self.assertEqual(len(records), 1)
        self.assertNotIn(self.secret.decode(), repr(records))
        self.assertNotIn('"repository":', repr(records))

    def test_same_delivery_id_cannot_change_signed_body_after_claim(self):
        self.claim()
        changed = {**self.payload, "harmless": "changed"}
        with self.assertRaisesRegex(Hold, "changed_signed_payload"):
            self.claim(payload=changed)
        self.assertEqual(len(self.rows()), 1)

    def test_recycled_delivery_uuid_cannot_switch_event_or_source_identity(self):
        self.claim()
        pr = {
            "repository": {"full_name": router.REPO}, "action": "synchronize",
            "pull_request": {
                "number": 101, "state": "open", "draft": False,
                "user": {"login": "AyobamiH"},
                "head": {"sha": self.head, "repo": {"full_name": router.REPO}},
                "base": {"ref": "main", "repo": {"full_name": router.REPO}},
            },
        }
        with self.assertRaisesRegex(Hold, "same_delivery_identity_with_changed_signed_payload"):
            self.claim(payload=pr, event_name="pull_request")
        self.assertEqual(len(self.rows()), 1)
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 1)

    def test_distinct_delivery_uuid_reconciles_same_suite_without_second_job(self):
        first = self.claim()
        second = self.claim(delivery_id="11234567-89ab-cdef-0123-456789abcdef")
        self.assertEqual(second["admission"], "already_admitted")
        self.assertEqual(first["existing_fleet_job_id"], second["existing_fleet_job_id"])
        self.assertEqual(len(self.rows()), 1)
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 2)

    def test_pr_two_intents_but_one_existing_suite(self):
        pr = {
            "repository": {"full_name": router.REPO}, "action": "synchronize",
            "pull_request": {
                "number": 101, "state": "open", "draft": False,
                "user": {"login": "AyobamiH"},
                "head": {"sha": self.head, "repo": {"full_name": router.REPO}},
                "base": {"ref": "main", "repo": {"full_name": router.REPO}},
            },
        }
        result = self.claim(payload=pr, event_name="pull_request")
        self.assertEqual(result["source_ref"], "pr/101")
        self.assertEqual(len(result["job_intents"]), 2)
        self.assertEqual(len(self.rows()), 1)
        with self.assertRaisesRegex(Hold, "different_event_ref"):
            self.claim(delivery_id="21234567-89ab-cdef-0123-456789abcdef")
            # A distinct authenticated delivery cannot relabel the same suite/SHA.
        self.assertEqual(len(self.rows()), 1)

    def test_untrusted_event_ref_or_hmac_cannot_admit(self):
        with self.assertRaises(Hold):
            self.claim(signature="sha256=" + "0" * 64)
        with self.assertRaises(Hold):
            self.claim(ref_sha="1" * 40)
        with self.assertRaises(Hold):
            self.claim(payload={**self.payload, "forced": True})
        self.assertEqual(self.rows(), [])

    def test_policy_pin_and_queue_schema_fail_closed(self):
        policy_path = self.base / "fleet-policy.json"
        bad = copy.deepcopy(self.policy)
        bad["repositories"][router.REPO]["enrolled_head"] = "f" * 40
        policy_path.write_text(json.dumps(bad))
        with self.assertRaisesRegex(Hold, "ordinary_job_not_source_pinned"):
            self.claim()
        self.assertEqual(self.rows(), [])
        policy_path.write_text(json.dumps(self.policy))
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute("DROP TABLE observations")
        with self.assertRaisesRegex(Hold, "queue_schema"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_canonical_fleet_lock_refuses_competing_owner(self):
        fd = os.open(self.base / "control.lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(Hold, "owner_is_active"):
                self.claim()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertEqual(self.rows(), [])

    def test_cancelled_or_failed_existing_suite_is_not_replayed(self):
        self.claim()
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute("UPDATE jobs SET state='cancelled'")
        with self.assertRaisesRegex(Hold, "terminal_state_not_replayable"):
            self.claim()
        self.assertEqual(len(self.rows()), 1)

    def test_symlink_or_foreign_root_never_initialises_queue(self):
        alias = self.base.parent / (self.base.name + "-symlink")
        alias.symlink_to(self.base, target_is_directory=True)
        self.addCleanup(alias.unlink)
        with self.assertRaisesRegex(Hold, "unsafe_existing_fleet_root"):
            claims.claim_existing_fleet_delivery(
                checkout=ROOT, fleet_root=alias, body=b"x", event_name="push",
                signature="none", delivery_id="none", secret=self.secret,
                fresh_ref_sha=self.head)
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
