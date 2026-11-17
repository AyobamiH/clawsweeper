"""Real owner SSH admission followed by source-bound, read-only worker proof."""
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
sys.path.insert(0, str(ROOT / "test/ci"))
import test_direct_local_manual_run as fixture_helpers
import direct_local_manual_run as manual
import direct_local_manual_worker as worker
from estate_policy import Hold


class SignedManualWorkerTests(unittest.TestCase):
    def setUp(self):
        self.owner = fixture_helpers.OwnerSignedManualRunTests("test_real_ssh_signature_one_durable_queue_row_and_replay")
        self.owner.setUp()
        self.addCleanup(self.owner.doCleanups)
        self.first = self.owner.claim()
        self.job_id = self.first["existing_fleet_job_id"]
        # Test-only owner identity; production loads its fixed owner key path.
        signers_patch = mock.patch.object(
            manual, "owner_allowed_signers", return_value=self.owner.signers)
        signers_patch.start()
        self.addCleanup(signers_patch.stop)

    def verify(self):
        return worker.verify_manual_queue_provenance(
            fleet_root=self.owner.base, job_id=self.job_id)

    def test_real_ssh_signed_admission_verifies_one_worker_without_side_effect(self):
        got = self.verify()
        self.assertTrue(got["verified_owner_origin"])
        self.assertEqual(got["source_sha"], self.owner.sha)
        self.assertEqual(got["job_intents"], list(manual.JOBS))
        self.assertFalse(got["provider_status_authorised"])
        self.assertFalse(got["job_executed"])
        self.assertEqual(len(self.owner.rows()), 1)

    def test_unsigned_sqlite_claim_cannot_impersonate_owner(self):
        # Regression: before this fix, a forged row and observation claimed
        # verified_owner_origin=True without a corresponding SSH signature.
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            row = db.execute("SELECT value FROM observations").fetchone()[0]
            spoofed = json.loads(row)
            spoofed.pop("signed_request_b64")
            spoofed.pop("signed_request_signature_b64")
            db.execute("UPDATE observations SET value=?",
                       (json.dumps(spoofed),))
        with self.assertRaisesRegex(
                Hold, "missing_signed_local_manual_request_envelope"):
            self.verify()

    def test_tampered_persisted_signature_is_rejected_at_worker_start(self):
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            row = db.execute("SELECT value FROM observations").fetchone()[0]
            altered = json.loads(row)
            bad = bytearray(base64.b64decode(
                altered["signed_request_signature_b64"], validate=True))
            bad[-20] ^= 0x01
            altered["signed_request_signature_b64"] = (
                base64.b64encode(bad).decode("ascii"))
            db.execute("UPDATE observations SET value=?",
                       (json.dumps(altered),))
        with self.assertRaisesRegex(Hold, "untrusted_owner_signature"):
            self.verify()

    def test_persisted_nonce_and_signed_payload_must_agree(self):
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            row = db.execute("SELECT value FROM observations").fetchone()[0]
            altered = json.loads(row)
            altered["nonce_sha256"] = "b" * 64
            db.execute("UPDATE observations SET value=?",
                       (json.dumps(altered),))
        with self.assertRaisesRegex(Hold, "signed_local_manual_claim_binding"):
            self.verify()

    def test_real_worker_start_checks_fresh_develop_and_full_source_plan(self):
        with mock.patch.object(manual, "read_fresh_develop_sha",
                               return_value=self.owner.sha) as readback, \
             mock.patch.object(worker, "verify_exact_clean_checkout") as clean:
            got = worker.verify_manual_worker_start(
                checkout=ROOT, fleet_root=self.owner.base,
                job_id=self.job_id)
        self.assertTrue(got["live_develop_verified"])
        self.assertTrue(got["exact_clean_source_verified"])
        readback.assert_called_once()
        clean.assert_called_once_with(ROOT, self.owner.sha)

    def test_fresh_develop_drift_holds_before_execution(self):
        with mock.patch.object(manual, "read_fresh_develop_sha",
                               return_value="a"*40):
            with self.assertRaisesRegex(Hold, "develop_moved"):
                worker.verify_manual_worker_start(
                    checkout=ROOT, fleet_root=self.owner.base,
                    job_id=self.job_id)

    def test_legacy_or_foreign_job_identity_cannot_be_relabelled(self):
        with self.assertRaisesRegex(Hold, "invalid_local_manual"):
            worker.verify_manual_queue_provenance(
                fleet_root=self.owner.base, job_id="../../forged")
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            db.execute("UPDATE jobs SET ref=? WHERE id=?", ("main", self.job_id))
        with self.assertRaisesRegex(Hold, "job_identity_or_state"):
            self.verify()

    def test_webhook_provenance_conflicting_with_signed_manual_is_held(self):
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            db.execute("INSERT INTO observations VALUES(?,?,?)", (
                "direct-local:forged", json.dumps({
                    "job_id": self.job_id, "event": "push",
                    "proof_kind": "authenticated_queue_admission_not_execution",
                }), "now"))
        with self.assertRaisesRegex(Hold, "missing_or_ambiguous"):
            self.verify()

    def test_duplicate_owner_provenance_is_held(self):
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            record = db.execute("SELECT value FROM observations").fetchone()[0]
            db.execute("INSERT INTO observations VALUES(?,?,?)",
                       ("direct-local-manual:duplicate", record, "now"))
        with self.assertRaisesRegex(Hold, "missing_or_ambiguous"):
            self.verify()

    def test_tampered_claim_proof_or_eligible_jobs_is_held(self):
        for field, value in [
            ("proof_kind", "unauthenticated"),
            ("job_intents", list(manual.JOBS[:1])),
            ("owner_principal", "unknown"),
            ("source_ref", "main"),
        ]:
            with self.subTest(field=field):
                with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
                    old = db.execute("SELECT value FROM observations").fetchone()[0]
                    altered = json.loads(old)
                    altered[field] = value
                    db.execute("UPDATE observations SET value=?",
                               (json.dumps(altered),))
                with self.assertRaisesRegex(Hold, "untrusted_local_manual"):
                    self.verify()
                with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
                    db.execute("UPDATE observations SET value=?", (old,))

    def test_policy_drift_is_held_without_changing_queue(self):
        policy_path = self.owner.base / "fleet-policy.json"
        policy = json.loads(policy_path.read_text())
        policy["repositories"][manual.REPO]["enrolled_head"] = "e"*40
        policy_path.write_text(json.dumps(policy))
        with self.assertRaisesRegex(Hold, "job_identity_or_state"):
            self.verify()
        self.assertEqual(len(self.owner.rows()), 1)

    def test_worker_does_not_accept_disallowed_terminal_failure(self):
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            db.execute("UPDATE jobs SET state=? WHERE id=?",
                       ("cancelled", self.job_id))
        with self.assertRaisesRegex(Hold, "job_identity_or_state"):
            self.verify()

    def test_completed_job_cannot_restart_even_with_valid_owner_claim(self):
        with sqlite3.connect(self.owner.base / "fleet.sqlite3") as db:
            db.execute("UPDATE jobs SET state=? WHERE id=?",
                       ("completed", self.job_id))
        with self.assertRaisesRegex(Hold, "terminal_job_cannot_be_restarted"):
            worker.verify_manual_worker_start(
                checkout=ROOT, fleet_root=self.owner.base, job_id=self.job_id)

    def test_checkout_clean_source_gate_rejects_dirty_candidate(self):
        # A small independent Git repository proves both clean acceptance and
        # dirty refusal without relying on this checkout's transient state.
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for args in (
                ("git", "init", "-q"),
                ("git", "config", "user.name", "CI Fixture"),
                ("git", "config", "user.email", "ci@localhost"),
            ):
                subprocess.run(args, cwd=repo, check=True,
                               capture_output=True, timeout=7)
            (repo / "tracked.txt").write_text("original")
            subprocess.run(("git", "add", "tracked.txt"), cwd=repo,
                           check=True, capture_output=True, timeout=7)
            subprocess.run(("git", "-c", "commit.gpgsign=false",
                            "commit", "-qm", "fixture"), cwd=repo,
                           check=True, capture_output=True, timeout=7)
            sha = subprocess.check_output(("git", "rev-parse", "HEAD"),
                                          cwd=repo, text=True, timeout=7).strip()
            worker.verify_exact_clean_checkout(repo, sha)
            (repo / "tracked.txt").write_text("tampered")
            with self.assertRaisesRegex(Hold, "not_exact_clean_head"):
                worker.verify_exact_clean_checkout(repo, sha)
            (repo / "tracked.txt").write_text("original")
            (repo / "unexpected.py").write_text("source outside Git HEAD")
            with self.assertRaisesRegex(Hold, "not_exact_clean_head"):
                worker.verify_exact_clean_checkout(repo, sha)
            with self.assertRaisesRegex(Hold, "not_exact_clean_head"):
                worker.verify_exact_clean_checkout(repo, "a"*40)

    def test_hostile_git_path_cannot_forge_clean_source(self):
        # Before hardening, this fake git produced a valid SHA and empty status,
        # so an unverified directory was accepted as a clean signed checkout.
        with tempfile.TemporaryDirectory(prefix="manual-git-path-") as td:
            root = Path(td)
            repo = root / "repo"
            fake_bin = root / "bin"
            repo.mkdir()
            fake_bin.mkdir()
            marker = root / "hostile-executable-ran"
            shim = fake_bin / "git"
            shim.write_text(
                "#!/bin/sh\nprintf ran > " + str(marker)
                + "\nif [ \"$3\" = \"rev-parse\" ]; then printf '%040d\\n' 0; fi\n"
            )
            shim.chmod(0o700)
            with mock.patch.dict(os.environ, {
                "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
                "HOME": str(root), "GIT_CONFIG_GLOBAL": str(root / "hostile"),
            }):
                with self.assertRaisesRegex(
                        Hold, "manual_worker_source_checkout_not_exact_clean_head"):
                    worker.verify_exact_clean_checkout(repo, "0" * 40)
            self.assertFalse(marker.exists(),
                             "untrusted git executable ran before source proof")

    def test_repository_filter_cannot_execute_before_blob_verification(self):
        # Git status can execute filter.clean from untrusted .git/config.
        # The worker must validate HEAD/index/worktree using only safe plumbing.
        with tempfile.TemporaryDirectory(prefix="manual-filter-gate-") as td:
            repo = Path(td)
            marker = repo / "filter-was-run"
            def git(*args):
                return subprocess.run(
                    ["/usr/bin/git", *args], cwd=repo, check=True,
                    capture_output=True, text=True, timeout=7)
            git("init", "-q")
            git("config", "user.name", "CI Fixture")
            git("config", "user.email", "ci@localhost")
            tracked = repo / "tracked.txt"
            tracked.write_text("original")
            (repo / ".gitattributes").write_text("tracked.txt filter=unsafe\n")
            git("add", ".")
            git("-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
            sha = git("rev-parse", "HEAD").stdout.strip()
            worker.verify_exact_clean_checkout(repo, sha)
            hook = repo / "hostile-filter.sh"
            hook.write_text(
                "#!/bin/sh\nprintf called > " + str(marker) + "\ncat\n"
            )
            hook.chmod(0o700)
            git("config", "filter.unsafe.clean", str(hook))
            tracked.write_text("tampered")
            with self.assertRaisesRegex(Hold, "not_exact_clean_head"):
                worker.verify_exact_clean_checkout(repo, sha)
            self.assertFalse(marker.exists(), "Git executed a local clean filter")

    def test_production_worker_entry_has_no_injected_get_or_plan(self):
        import inspect
        params = inspect.signature(worker.verify_manual_worker_start).parameters
        for param in ("fresh_source_sha", "provider_get", "signature_verifier",
                      "now", "policy_override", "allow_unsigned"):
            self.assertNotIn(param, params)


if __name__ == "__main__":
    unittest.main()
