"""Real SSH-signed local intent tests: no webhook forgery, provider POST or runner."""
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get("CLAWSWEEPER_TEST_CLEAN_SOURCE", str(ROOT)))
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_manual_run as manual
import direct_local_workflow as router
from estate_policy import Hold


class OwnerSignedManualRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.sha = router.git_head(SOURCE)
        self.now = int(time.time())
        self.request = self.base / "request.json"
        self.signature = self.base / "request.json.sig"
        self.key = self.base / "test-key"
        self.signers = self.base / "allowed_signers"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-f", str(self.key)], check=True,
            capture_output=True, timeout=8,
        )
        self.signers.write_text(
            manual.PRINCIPAL + " " + (self.base / "test-key.pub").read_text()
        )
        self.signers.chmod(0o600)
        self.policy = {
            "version": 4,
            "image": "sha256:" + "b" * 64,
            "node_versions": {"24": "/ci-tools/node24/bin/node"},
            "execution_hosts": {router.REPO: os.uname().nodename},
            "repositories": {router.REPO: {
                "branch": "main",
                "enrolled_head": self.sha,
                "contract": router.sha256(SOURCE / ".github/workflows/ci.yml"),
                "suites": {"linux-node24": {
                    "node": "24", "image": "sha256:" + "a" * 64,
                    "steps": [
                        {"command": """actionlint -shellcheck= -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml""",
                         "timeout": 600},
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
        self.doc = {
            "schema": manual.SCHEMA, "repo": manual.REPO,
            "source_sha": self.sha, "source_ref": "develop",
            "host": os.uname().nodename, "suite": "linux-node24",
            "job_intents": list(manual.JOBS),
            "purpose": "ordinary-source-validation",
            "nonce": "1234567890abcdef1234567890abcdef",
            "issued_at": self.now,
            "expires_at": self.now + 600,
        }
        self.resign()

    def resign(self):
        self.request.write_bytes(json.dumps(self.doc, sort_keys=True).encode())
        self.request.chmod(0o600)
        self.signature.unlink(missing_ok=True)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key),
             "-n", manual.NAMESPACE, str(self.request)],
            capture_output=True, check=True, timeout=8,
        )
        self.signature.chmod(0o600)

    def claim(self, *, fresh=None, **overrides):
        args = dict(
            checkout=SOURCE, fleet_root=self.base,
            request_file=self.request, signature_file=self.signature,
            allowed_signers_file=self.signers,
            fresh_source_sha=self.sha if fresh is None else fresh,
            now=self.now,
        )
        args.update(overrides)
        return manual._claim_verified(**args)

    def rows(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            return list(db.execute(
                "SELECT id,sha,ref,state FROM jobs ORDER BY id"
            ))

    def observations(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            return list(db.execute("SELECT key,value FROM observations"))

    def test_production_entry_point_has_no_override_parameters(self):
        import inspect
        parameters = inspect.signature(manual.claim_owner_signed_manual_run).parameters
        self.assertNotIn("fresh_source_sha", parameters)
        self.assertNotIn("signature_verifier", parameters)
        self.assertNotIn("now", parameters)

    def test_hostile_path_cannot_forge_owner_signature_before_queue(self):
        with tempfile.TemporaryDirectory(prefix="manual-hostile-path-") as tmp:
            directory = Path(tmp)
            marker = directory / "shim-ran"
            shim = directory / "ssh-keygen"
            shim.write_text("#!/bin/sh\nprintf spoofed > " + str(marker) + "\nexit 0\n")
            shim.chmod(0o700)
            bogus = (b"-----BEGIN SSH SIGNATURE-----\nZm9v\n"
                     b"-----END SSH SIGNATURE-----\n")
            with mock.patch.dict(os.environ, {
                "PATH": str(directory) + os.pathsep + os.environ["PATH"],
                "LD_PRELOAD": str(directory / "not-a-library.so"),
            }):
                with self.assertRaisesRegex(Hold, "untrusted_owner_signature"):
                    manual.verify_owner_signature_bytes(
                        b"not signed", bogus, self.signers)
            self.assertFalse(marker.exists(), "hostile PATH program ran")

    def test_github_readback_pins_binary_host_and_sealed_environment(self):
        payload = {"ref": "refs/heads/develop",
                   "object": {"type": "commit", "sha": self.sha}}
        fake = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(payload).encode(), stderr=b"")
        with tempfile.TemporaryDirectory(prefix="manual-gh-shim-") as tmp:
            with mock.patch.dict(os.environ, {
                "PATH": str(tmp) + os.pathsep + os.environ["PATH"],
                "GH_HOST": "attacker.example",
                "GH_CONFIG_DIR": str(tmp),
                "LD_PRELOAD": str(Path(tmp) / "evil.so"),
            }), mock.patch.object(manual.subprocess, "run", return_value=fake) as run:
                self.assertEqual(manual.read_fresh_develop_sha(), self.sha)
                argv = run.call_args.args[0]
                env = run.call_args.kwargs["env"]
                self.assertEqual(argv[0], "/usr/bin/gh")
                self.assertEqual(argv[1:4], ["api", "--hostname", "github.com"])
                self.assertEqual(env["GH_HOST"], "github.com")
                self.assertEqual(env["PATH"], "/usr/bin:/bin")
                self.assertNotEqual(env["GH_CONFIG_DIR"], str(tmp))
                self.assertNotIn("LD_PRELOAD", env)

    def test_offline_controller_builder_pins_child_environment(self):
        # The original renderer passed ambient HOME and LD_PRELOAD to a Python
        # child before any owner signature had been authenticated.
        source = (ROOT / "scripts/ci/build_direct_local_manual_controller.py"
                  ).read_text()
        entry = source.split("def _signed_manual_claim_entry(", 1)[1]
        entry = entry.split("\ndef ", 1)[0]
        self.assertIn('home = pathlib.Path(__import__("pwd").getpwuid(', entry)
        self.assertIn('env=environment', entry)
        self.assertIn('str(home / ".config/git/allowed_signers")', entry)
        self.assertNotIn('str(pathlib.Path.home()', entry)
        self.assertNotIn('"LD_PRELOAD"', entry)

    def test_owner_signer_and_github_config_ignore_injected_home(self):
        import pwd
        authoritative = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with tempfile.TemporaryDirectory(prefix="manual-hostile-home-") as td:
            fake_home = Path(td)
            (fake_home / ".config/git").mkdir(parents=True)
            with mock.patch.dict(os.environ, {"HOME": str(fake_home)}):
                self.assertEqual(manual.owner_allowed_signers(),
                                 authoritative / ".config/git/allowed_signers")
                env = manual._trusted_github_env()
                self.assertEqual(env["HOME"], str(authoritative))
                self.assertEqual(env["GH_CONFIG_DIR"],
                                 str(authoritative / ".config/gh"))
                self.assertNotIn(str(fake_home), str(env))

    def test_real_ssh_signature_one_durable_queue_row_and_replay(self):
        first = self.claim()
        second = self.claim()
        self.assertEqual(first["admission"], "queued")
        self.assertEqual(second["admission"], "already_admitted")
        self.assertEqual(first["existing_fleet_job_id"],
                         second["existing_fleet_job_id"])
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0][2:], ("local-manual", "queued"))
        self.assertEqual(len(self.observations()), 1)
        self.assertTrue(self.observations()[0][0].startswith("direct-local-manual:"))
        evidence = json.loads(self.observations()[0][1])
        self.assertEqual(evidence["proof_kind"], manual.PROOF)
        self.assertEqual(set(evidence["job_intents"]), set(manual.JOBS))
        self.assertNotIn(self.doc["nonce"], str(evidence))
        self.assertFalse(first["runner_started"])
        self.assertFalse(first["github_actions_dispatched"])
        self.assertFalse(first["github_status_published"])

    def test_signature_tamper_is_rejected_before_queue(self):
        self.doc["nonce"] = "b" * 32
        self.request.write_bytes(json.dumps(self.doc).encode())
        with self.assertRaisesRegex(Hold, "untrusted_owner_signature"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_same_nonce_different_signed_bytes_is_not_replayed(self):
        self.claim()
        self.doc["expires_at"] += 60
        self.resign()
        with self.assertRaisesRegex(Hold, "manual_nonce_collision"):
            self.claim()
        self.assertEqual(len(self.rows()), 1)

    def test_different_nonce_cannot_claim_existing_suite(self):
        self.claim()
        self.doc["nonce"] = "b" * 32
        self.resign()
        with self.assertRaisesRegex(Hold, "manual_existing_job_not_same"):
            self.claim()
        self.assertEqual(len(self.rows()), 1)

    def test_new_local_request_never_relabels_old_webhook_or_poller_job(self):
        with sqlite3.connect(self.base / "fleet.sqlite3") as db:
            db.execute(
                "INSERT INTO jobs(id,repo,sha,suite,policy,ref,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                ("local-fleet-111111111111", manual.REPO, self.sha,
                 manual.claims.SUITE,
                 manual.claims.reviewed_policy_hash(self.policy),
                 "main", "before", "before"),
            )
        with self.assertRaisesRegex(Hold, "manual_existing_job_not_same"):
            self.claim()
        self.assertEqual(self.rows()[0][2], "main")

    def test_existing_fleet_owner_lock_blocks_without_queue_change(self):
        with open(self.base / "control.lock", "rb+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(Hold, "manual_existing_fleet_owner_busy"):
                self.claim()
        self.assertEqual(self.rows(), [])

    def test_fresh_provider_source_drift_is_fail_closed(self):
        with self.assertRaisesRegex(Hold, "manual_source_moved"):
            self.claim(fresh="a" * 40)
        self.assertEqual(self.rows(), [])

    def test_no_privileged_or_extra_job_classes(self):
        self.doc["job_intents"].append(
            ".github/workflows/codeql.yml#analyze")
        self.resign()
        with self.assertRaisesRegex(Hold, "unapproved_manual_scope"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_expired_request_is_not_admitted(self):
        self.doc["issued_at"] = self.now - 1200
        self.doc["expires_at"] = self.now - 300
        self.resign()
        with self.assertRaisesRegex(Hold, "unapproved_manual_scope"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_different_owner_signing_namespace_rejected(self):
        self.signature.unlink()
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key),
             "-n", "wrong-namespace", str(self.request)],
            capture_output=True, check=True, timeout=8,
        )
        self.signature.chmod(0o600)
        with self.assertRaisesRegex(Hold, "untrusted_owner_signature"):
            self.claim()

    def test_untrusted_request_permissions_are_held(self):
        self.request.chmod(0o644)
        with self.assertRaisesRegex(Hold, "unsafe_manual_file"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def test_duplicate_json_keys_rejected_even_when_correctly_signed(self):
        raw = self.request.read_text().replace(
            '{"expires_at":', '{"expires_at":0,"expires_at":', 1)
        self.request.write_text(raw)
        self.resign_modified()
        with self.assertRaisesRegex(Hold, "duplicate_webhook_json_key"):
            self.claim()
        self.assertEqual(self.rows(), [])

    def resign_modified(self):
        self.request.chmod(0o600)
        self.signature.unlink()
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key),
             "-n", manual.NAMESPACE, str(self.request)],
            capture_output=True, check=True, timeout=8,
        )
        self.signature.chmod(0o600)

    def test_policy_source_drift_is_held(self):
        self.policy["repositories"][manual.REPO]["enrolled_head"] = "a" * 40
        (self.base / "fleet-policy.json").write_text(json.dumps(self.policy))
        with self.assertRaisesRegex(Hold, "manual_policy_source"):
            self.claim()
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
