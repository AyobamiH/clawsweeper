"""Disposable, no-provider proof for a generation-aware retention release candidate."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest


MOD_PATH = Path(__file__).resolve().parents[2] / "scripts/ci/fleet_evidence_retention_generation.py"
spec = importlib.util.spec_from_file_location("candidate_retention_v2", MOD_PATH)
ret = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ret)
JOB = "local-fleet-0123456789ab"
SHA = "b" * 40
REPO = "ExampleOrg/disposable-ci-example"
SUITE = "linux-node24-claw-check"


class TestGenerationAwareRetention(unittest.TestCase):
    def setUp(self):
        self.ctx = tempfile.TemporaryDirectory()
        self.addCleanup(self.ctx.cleanup)
        base = Path(self.ctx.name)
        self.root = base / "working"
        self.cold = base / "cold"
        for rel in ("evidence/fleet", "logs/fleet", "state/fleet"):
            (self.root / rel).mkdir(parents=True)
        (self.root / "OWNED_BY_LOCAL_CI").write_text("local-ci-v1\n")
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.execute("""CREATE TABLE jobs (
            id TEXT PRIMARY KEY, repo TEXT, sha TEXT, suite TEXT,
            state TEXT, reported INTEGER, updated_at TEXT,
            attempt INTEGER, outcome TEXT)""")
        self.db.execute("CREATE TABLE detached_leases (job_id TEXT)")
        self.stamp = (dt.datetime.now(dt.timezone.utc) -
                      dt.timedelta(hours=12)).isoformat()
        self.db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
                        (JOB, REPO, SHA, SUITE, "completed", 1, self.stamp, 3, "error"))
        self.old = self.write_current(3, "error", b"old attempt-three trace")
        self.legacy = self.cold / JOB

    def receipt_path(self):
        return self.root / "evidence/fleet" / (JOB + ".json")

    def log_path(self):
        return self.root / "logs/fleet" / (JOB + ".log")

    def write_current(self, attempt, outcome, log_data):
        log = self.log_path()
        log.write_bytes(log_data)
        record = {"id": JOB, "repo": REPO, "sha": SHA, "suite": SUITE,
                  "attempt": attempt, "outcome": outcome,
                  "log_bytes": len(log_data),
                  "log_sha256": hashlib.sha256(log_data).hexdigest()}
        self.receipt_path().write_text(json.dumps(record, sort_keys=True))
        return record

    def first_archive(self):
        out = ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertEqual(out["archived_jobs"], 1)
        self.assertTrue(self.receipt_path().is_symlink())
        self.assertTrue(self.log_path().is_symlink())
        self.assertTrue((self.legacy / "COMPLETED.json").is_file())
        self.legacy_hash = ret.sha256(self.legacy / "plan.json")
        self.legacy_receipt_hash = ret.sha256(self.legacy / (JOB + ".json"))

    def newer(self, *, attempt=4, outcome="success"):
        self.receipt_path().unlink()
        self.log_path().unlink()
        self.write_current(attempt, outcome, b"genuine newer attempt log content")
        (self.root / "evidence/fleet" / (JOB + ".attempt3.json")).write_text(
            json.dumps(self.old, sort_keys=True))
        self.db.execute("UPDATE jobs SET attempt=?,outcome=? WHERE id=?",
                        (attempt, outcome, JOB))

    def test_retains_distinct_attempt_with_immutable_legacy(self):
        self.first_archive()
        self.newer()
        out = ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertEqual(out["archived_jobs"], 1)
        new = self.legacy / "generations" / "attempt4"
        self.assertTrue((new / "COMPLETED.json").is_file())
        self.assertEqual(ret.sha256(self.legacy / "plan.json"), self.legacy_hash)
        self.assertEqual(ret.sha256(self.legacy / (JOB + ".json")), self.legacy_receipt_hash)
        self.assertEqual(self.receipt_path().resolve(), new / (JOB + ".json"))
        self.assertEqual(self.log_path().resolve(), new / (JOB + ".log"))
        self.assertEqual(ret.heal(self.db, root=self.root, cold=self.cold)["archived_jobs"], 0)

    def test_old_archive_blob_corruption_is_always_rejected(self):
        self.first_archive()
        self.newer()
        archived = self.legacy / (JOB + ".json")
        archived.write_text("tampered old immutable blob")
        with self.assertRaisesRegex(ret.RetentionError, "archive_blob_integrity_failure"):
            ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertFalse((self.legacy / "generations").exists())

    def test_new_log_and_receipt_must_match(self):
        self.first_archive()
        self.newer()
        self.log_path().write_bytes(b"altered log not declared in receipt")
        with self.assertRaisesRegex(ret.RetentionError, "generation_log_receipt_mismatch"):
            ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertFalse((self.legacy / "generations").exists())

    def test_same_or_replayed_attempt_is_rejected(self):
        self.first_archive()
        self.newer(attempt=3)
        with self.assertRaisesRegex(ret.RetentionError, "generation_attempt_invalid"):
            ret.heal(self.db, root=self.root, cold=self.cold)

    def test_receipt_source_drift_is_rejected(self):
        self.first_archive()
        self.newer()
        payload = json.loads(self.receipt_path().read_text())
        payload["sha"] = "0" * 40
        self.receipt_path().write_text(json.dumps(payload))
        with self.assertRaisesRegex(ret.RetentionError, "generation_receipt_source_drift"):
            ret.heal(self.db, root=self.root, cold=self.cold)

    def test_v1_marker_mismatch_is_rejected_before_new_archival(self):
        self.first_archive()
        self.newer()
        (self.legacy / "COMPLETED.json").write_text("{}")
        with self.assertRaisesRegex(ret.RetentionError, "generation_marker_mismatch"):
            ret.heal(self.db, root=self.root, cold=self.cold)

    def test_broken_legacy_link_stops_when_no_new_regular_receipt(self):
        self.first_archive()
        self.receipt_path().unlink()
        self.receipt_path().symlink_to(self.legacy / "incorrect.json")
        with self.assertRaisesRegex(ret.RetentionError, "generation_mixed_or_untrusted_sources|generation_current_link_drift"):
            ret.heal(self.db, root=self.root, cold=self.cold)

    def test_interrupt_between_move_and_symlink_recovers_exact_blobs(self):
        self.first_archive()
        self.newer()
        row = dict(self.db.execute("SELECT * FROM jobs WHERE id=?", (JOB,)).fetchone())
        prev_hash = ret.sha256(self.legacy / "plan.json")
        target = self.legacy / "generations" / "attempt4"
        target.mkdir(parents=True)
        sources = [self.receipt_path(), self.log_path(),
                   self.root / "evidence/fleet" / (JOB + ".attempt3.json")]
        entries = [ret._stored_entry(self.root, JOB, path) for path in sources]
        plan = {"version": 2, "job": JOB, "repo": REPO, "sha": SHA,
                "suite": SUITE, "attempt": 4, "previous_plan_sha256": prev_hash,
                "files": entries}
        ret.write_once(target / "plan.json", plan)
        self.receipt_path().rename(target / (JOB + ".json"))
        self.assertFalse(self.receipt_path().exists())
        got = ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertEqual(got["archived_jobs"], 0)
        self.assertTrue(self.receipt_path().is_symlink())
        self.assertTrue(self.log_path().is_symlink())
        self.assertTrue((target / "COMPLETED.json").exists())
        self.assertEqual(ret.heal(self.db, root=self.root, cold=self.cold)["archived_jobs"], 0)


    def test_chained_generation_manifest_drift_is_rejected(self):
        self.first_archive()
        self.newer()
        ret.heal(self.db, root=self.root, cold=self.cold)
        manifest = self.legacy / "generations" / "attempt4" / "plan.json"
        record = json.loads(manifest.read_text())
        record["previous_plan_sha256"] = "0" * 64
        manifest.write_text(json.dumps(record))
        with self.assertRaisesRegex(ret.RetentionError, "generation_chain_drift"):
            ret.heal(self.db, root=self.root, cold=self.cold)

    def test_new_generation_blob_corruption_remains_fatal(self):
        self.first_archive()
        self.newer()
        ret.heal(self.db, root=self.root, cold=self.cold)
        newer = self.legacy / "generations" / "attempt4" / (JOB + ".json")
        newer.write_text("corrupted newest archived receipt")
        with self.assertRaisesRegex(ret.RetentionError, "archive_blob_integrity_failure"):
            ret.heal(self.db, root=self.root, cold=self.cold)

    def test_untrusted_generations_directory_is_rejected(self):
        self.first_archive()
        self.newer()
        (self.legacy / "generations").symlink_to(self.root / "evidence")
        with self.assertRaisesRegex(ret.RetentionError, "untrusted_generations_directory"):
            ret.heal(self.db, root=self.root, cold=self.cold)

    def test_unrelated_owner_evidence_is_never_moved(self):
        other = self.root / "unrelated-foreign-evidence"
        other.write_bytes(b"immutable unrelated private data")
        self.first_archive()
        self.newer()
        ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertEqual(other.read_bytes(), b"immutable unrelated private data")
        self.assertFalse(other.is_symlink())

    def test_pending_drift_is_rejected_before_any_source_move(self):
        self.first_archive()
        self.newer()
        target = self.legacy / "generations" / "attempt4"
        target.mkdir(parents=True)
        sources = [self.receipt_path(), self.log_path()]
        files = [ret._stored_entry(self.root, JOB, p) for p in sources]
        plan = {"version": 2, "job": JOB, "repo": REPO, "sha": "0" * 40,
                "suite": SUITE, "attempt": 4,
                "previous_plan_sha256": ret.sha256(self.legacy / "plan.json"),
                "files": files}
        ret.write_once(target / "plan.json", plan)
        with self.assertRaisesRegex(ret.RetentionError, "generation_pending_source_drift"):
            ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertTrue(ret.regular(self.receipt_path()))
        self.assertTrue(ret.regular(self.log_path()))
        self.assertFalse((target / (JOB + ".json")).exists())

    def test_pending_log_corruption_cannot_partially_move_receipt(self):
        self.first_archive()
        self.newer()
        target = self.legacy / "generations" / "attempt4"
        target.mkdir(parents=True)
        sources = [self.receipt_path(), self.log_path()]
        files = [ret._stored_entry(self.root, JOB, p) for p in sources]
        plan = {"version": 2, "job": JOB, "repo": REPO, "sha": SHA,
                "suite": SUITE, "attempt": 4,
                "previous_plan_sha256": ret.sha256(self.legacy / "plan.json"),
                "files": files}
        ret.write_once(target / "plan.json", plan)
        self.log_path().write_bytes(b"changed after pending plan was signed")
        with self.assertRaisesRegex(ret.RetentionError, "archive_blob_integrity_failure"):
            ret.heal(self.db, root=self.root, cold=self.cold)
        self.assertTrue(ret.regular(self.receipt_path()))
        self.assertFalse((target / (JOB + ".json")).exists())

    def test_attempt_snapshot_drift_is_rejected(self):
        self.first_archive()
        self.newer()
        snapshot = self.root / "evidence/fleet" / (JOB + ".attempt3.json")
        snapshot.write_text(json.dumps({"id": JOB, "sha": SHA, "attempt": 7}))
        with self.assertRaisesRegex(ret.RetentionError, "generation_snapshot_drift"):
            ret.heal(self.db, root=self.root, cold=self.cold)


if __name__ == "__main__":
    unittest.main()
