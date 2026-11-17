"""Regression proofs for the R7-bound direct-local manual controller overlay.

No live queue, controller, webhook, runner, PR or GitHub Actions changes.
"""
import ast
import hashlib
import json
import os
import tempfile
import importlib.util
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "scripts/ci/build_direct_local_manual_controller.py"
FLEET = Path("/home/johnh/.local/share/local-ci/fleet_ci.py")
REPO = "AyobamiH/clawsweeper"
SHA = "944fd5ad04ba5c01d73b8c3059313469aad3357f"
REQUEST = "a" * 64
SPEC = importlib.util.spec_from_file_location("manual_controller_build_test", ENTRY)
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class FakeDB:
    def __init__(self):
        self.statements = []
        self.commits = 0

    def execute(self, statement, params):
        self.statements.append((statement, params))

    def commit(self):
        self.commits += 1


class BuilderTrustBoundaryTests(unittest.TestCase):
    def test_signed_source_reads_seal_path_home_and_git_configuration(self):
        # An untrusted PATH previously ran an attacker-supplied git binary
        # while the offline release builder claimed to verify signed source.
        with tempfile.TemporaryDirectory(prefix="manual-builder-hostile-") as tmp:
            root = Path(tmp)
            marker = root / "shim-executed"
            shim = root / "git"
            shim.write_text("#!/bin/sh\nprintf 'executed' > " + str(marker) + "\nexit 0\n")
            shim.chmod(0o755)
            with mock.patch.dict(os.environ, {
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
                "HOME": str(root),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "gpg.ssh.program",
                "GIT_CONFIG_VALUE_0": str(shim),
                "GIT_EXEC_PATH": str(root),
                "LD_PRELOAD": str(root / "untrusted.so"),
            }):
                frozen = build.signed_git_files(ROOT)
                signature = build._sealed_git(
                    ROOT, "verify-commit", build.MANUAL_SOURCE_COMMIT)
            self.assertFalse(marker.exists(), "pre-verification git shim ran")
            self.assertEqual(set(frozen), set(build.LIBRARIES))
            self.assertTrue(all(frozen.values()))
            self.assertEqual(signature.returncode, 0, signature.stderr[:200])


    def test_release_stage_cannot_use_injected_home_as_fleet(self):
        # A forged HOME must not redirect the release-root identity check.
        with tempfile.TemporaryDirectory(prefix="manual-builder-home-") as td:
            home = Path(td)
            bogus_base = home / ".local/share/local-ci/fleet_ci.py"
            bogus_stage = (home / ".local/share/local-ci/evidence/"
                           "clawsweeper-direct-local-20261113/new-stage")
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                with self.assertRaisesRegex(RuntimeError,
                                            "release_stage_must_be_new_private"):
                    build.stage(base=bogus_base, repo=ROOT, destination=bogus_stage)
            self.assertFalse(bogus_stage.exists())


class ReleaseCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = FLEET.read_bytes()
        cls.libs = build.signed_git_files(ROOT)
        cls.hashes = {key: build.digest(raw) for key, raw in cls.libs.items()}
        cls.out = build.build_controller(cls.base, cls.hashes)
        cls.tree = ast.parse(cls.out)

    def _functions(self, *names):
        funcs = [node for node in self.tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual(set(names), {x.name for x in funcs})
        return ast.Module(body=funcs, type_ignores=[])

    def _context(self, *funcs, provenance=None):
        writes = []
        core = types.SimpleNamespace(
            api=lambda *args, **kwargs: self.fail("upstream API invoked"),
            atomic=lambda *args: writes.append(args))
        glob = {
            "core": core,
            "EVIDENCE": Path("/in-memory-test-evidence"),
            "_MANUAL_REPO": REPO,
            "_verified_manual_claim": lambda job: (
                provenance if provenance is not None else
                {"request_sha256": REQUEST, "source_sha": SHA, "ref": "local-manual"}),
            "_verified_manual_start": lambda job: {
                "request_sha256": REQUEST, "source_sha": SHA, "ref": "local-manual"},
            "_verified_manual_success_receipt": lambda job, receipt: True,
        }
        exec(compile(self._functions(*funcs), "<in-memory-controller>", "exec"), glob)
        return glob, writes

    def test_exact_r7_byte_pin_and_source_only_staging(self):
        self.assertEqual(build.digest(self.base), build.R7_SHA256)
        self.assertNotEqual(self.base, self.out)
        self.assertIn(b"def _verified_manual_start(", self.out)
        self.assertIn(b"def _manual_proof_subprocess(", self.out)
        self.assertIn(b"existing_fleet_job_id", self.libs["direct_local_manual_run.py"])
        self.assertEqual(len(self.libs), len(build.LIBRARIES))
        self.assertIn(b"def publish(", self.out)

    def test_base_drift_fails_before_candidate_creation(self):
        with self.assertRaisesRegex(RuntimeError, "unrecognised_original_r7"):
            build.build_controller(self.base + b"\n", self.hashes)
        bad = dict(self.hashes)
        bad.pop("direct_local_manual_worker.py")
        with self.assertRaisesRegex(RuntimeError, "unrecognised_original_r7"):
            build.build_controller(self.base, bad)

    def test_guarded_manual_reference_never_calls_github_actions(self):
        env, _ = self._context("current_reference")
        job = {"repo": REPO, "ref": "local-manual", "sha": SHA, "id": "local-fleet-" + "a" * 12}
        self.assertTrue(env["current_reference"](job))

    def test_pending_manual_does_not_touch_github_or_outbox(self):
        env, writes = self._context("publish_pending", "publish")
        db = FakeDB()
        job = self._job()
        self.assertIsNone(env["publish_pending"](db, job, "Running locally"))
        self.assertFalse(db.statements)
        self.assertFalse(writes)

    def _job(self):
        return {"repo": REPO, "ref": "local-manual", "sha": SHA,
                "id": "local-fleet-" + "a" * 12, "suite": "linux-node24",
                "policy": "policy-sha"}

    def _receipt(self, outcome="success"):
        return {**self._job(), "outcome": outcome,
                "cleanup": {"container_absent": True}}

    def test_success_is_local_only_and_durable(self):
        env, writes = self._context("publish")
        job = self._job()
        db = FakeDB()
        receipt = self._receipt()
        self.assertIsNone(env["publish"](db, job, "success", "All steps passed", receipt))
        self.assertEqual(receipt["origin"], "owner-signed-local-manual")
        self.assertEqual(receipt["provider_status"], "suppressed-local-manual")
        self.assertEqual(receipt["manual_request_sha256"], REQUEST)
        self.assertIsNone(receipt["github_status"])
        self.assertEqual(len(writes), 1)
        self.assertEqual(db.commits, 1)
        self.assertEqual(db.statements[0][1], (job["id"], "local-manual"))

    def test_failed_test_is_not_relabelled_success(self):
        env, writes = self._context("publish")
        db = FakeDB()
        with self.assertRaisesRegex(RuntimeError, "exact_cleaned_execution"):
            env["publish"](db, self._job(), "success", "bogus", self._receipt("failure"))
        self.assertFalse(writes)
        self.assertFalse(db.statements)

    def test_missing_cleanup_blocks_completion(self):
        env, writes = self._context("publish")
        db = FakeDB()
        receipt = self._receipt()
        del receipt["cleanup"]
        with self.assertRaisesRegex(RuntimeError, "exact_cleaned_execution"):
            env["publish"](db, self._job(), "success", "bogus", receipt)
        self.assertFalse(writes)
        self.assertFalse(db.statements)

    def test_success_receipt_requires_genuine_steps_and_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory)
            job = self._job()
            content = b"Exact local CI command output\\n"
            (log_dir / (job["id"] + ".log")).write_bytes(content)
            profile = json.loads((Path.home() / ".local/share/local-ci/fleet-policy.json").read_text())
            commands = profile["repositories"][REPO]["suites"]["linux-node24"]["steps"]
            steps = [{
                "name": "Exact commit checkout",
                "command": "git init -q; git remote add origin https://github.com/"
                           + REPO + ".git; git checkout --quiet --detach FETCH_HEAD; "
                           + "test $(git rev-parse HEAD) = $GITHUB_SHA",
                "exit_code": 0, "started_at": "start", "finished_at": "end",
            }] + [{
                "name": step["name"], "command": step["command"],
                "exit_code": 0, "started_at": "start", "finished_at": "end",
            } for step in commands]
            receipt = self._receipt()
            receipt.update({
                "mode": "local-scheduler-not-github-actions",
                "controller_sha256": "controller-hash",
                "attempt": 1,
                "started_at": "start", "finished_at": "end",
                "steps": steps,
                "log_bytes": len(content),
                "log_sha256": hashlib.sha256(content).hexdigest(),
                "container_state": {"OOMKilled": False},
            })
            env = {
                "CONTROLLER_SHA": "controller-hash",
                "LOGS": log_dir,
                "os": os,
                "hashlib": hashlib,
                "load_policy": lambda: profile,
                "policy_hash": lambda _p, _r, _s: job["policy"],
            }
            exec(compile(self._functions("_verified_manual_success_receipt"),
                         "<checked-generated-manual-controller>", "exec"), env)
            check = env["_verified_manual_success_receipt"]
            self.assertTrue(check(job, receipt))
            self.assertIn("_verified_manual_success_receipt(job, receipt)",
                          ast.unparse(self._functions("publish")))
            receipt["steps"] = steps[:-1]
            with self.assertRaisesRegex(RuntimeError, "missing_command_receipts"):
                check(job, receipt)
            receipt["steps"] = steps
            steps[3]["exit_code"] = 1
            with self.assertRaisesRegex(RuntimeError, "failed_or_relabelled"):
                check(job, receipt)
            steps[3]["exit_code"] = 0
            steps[4]["command"] = "echo bypass"
            with self.assertRaisesRegex(RuntimeError, "failed_or_relabelled"):
                check(job, receipt)
            steps[4]["command"] = commands[3]["command"]
            receipt["log_sha256"] = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "log_integrity"):
                check(job, receipt)
            receipt["log_sha256"] = hashlib.sha256(content).hexdigest()
            env["policy_hash"] = lambda _p, _r, _s: "unexpected"
            with self.assertRaisesRegex(RuntimeError, "policy_moved"):
                check(job, receipt)

    def test_nonmanual_github_status_route_not_removed(self):
        names = {n.name: n for n in self.tree.body if isinstance(n, ast.FunctionDef)}
        self.assertIn("api", ast.unparse(names["publish"]))
        self.assertIn("api", ast.unparse(names["current_reference"]))
        self.assertIn("publish(db, job", ast.unparse(names["publish_pending"]))
        self.assertIn("def flush_reports", self.out.decode())
        self.assertIn("def recover", self.out.decode())
        self.assertIn("def run_job", self.out.decode())

    def test_controller_has_one_distinct_local_manual_claim_entry(self):
        text = self.out.decode()
        self.assertIn("'manual-claim'", text)
        self.assertIn("--signed-local-request", text)
        self.assertIn("def _signed_manual_claim_entry(", text)
        self.assertIn("owner_signed_manual_claim_result_not_trusted", text)
        self.assertEqual(text.count("receipt = _signed_manual_claim_entry("), 1)
        # No additional worker service, queue, or GitHub workflow dispatch.
        self.assertNotIn("workflow_dispatch", text)

    def test_manual_claim_cli_rejects_unexpected_result_and_holds(self):
        import json
        import re
        node = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == "_signed_manual_claim_entry")
        code = compile(ast.Module(body=[node], type_ignores=[]),
                       "<in-memory-manual-claim>", "exec")
        result = {
            "schema": "clawsweeper.existing-fleet-local-manual-claim.v1",
            "source_ref": "local-manual",
            "source_sha": SHA,
            "suite": "linux-node24",
            "admission": "queued",
            "job_intents": [
                ".github/workflows/ci.yml#check",
                ".github/workflows/ci.yml#sparse-repair-builds"
            ],
            "existing_fleet_job_id": "local-fleet-" + "a" * 12,
        }
        calls = []
        def runner(argv, **kw):
            calls.append(argv)
            return types.SimpleNamespace(returncode=0,
                                         stdout=json.dumps(result).encode())
        env = {
            "subprocess": types.SimpleNamespace(run=runner, TimeoutExpired=TimeoutError),
            "_verified_local_manual_worker": lambda: True,
            "_MANUAL_LIB": Path("/frozen"),
            "_MANUAL_CHECKOUT": Path("/exact-checkout"),
            "ROOT": Path("/existing-fleet"),
            "pathlib": types.SimpleNamespace(Path=Path),
            "sys": types.SimpleNamespace(executable=sys.executable),
            "json": json, "re": re,
            "NAME": re.compile("local-fleet-[a-f0-9]{12}" + chr(92) + "Z"),
            "os": types.SimpleNamespace(),
        }
        exec(code, env)
        self.assertEqual(env["_signed_manual_claim_entry"]("/signed", "/signature"),
                         result)
        self.assertIn("-I", calls[0])
        self.assertIn("-B", calls[0])
        result["job_intents"] = ["unreviewed-privileged-job"]
        with self.assertRaisesRegex(RuntimeError, "not_trusted"):
            env["_signed_manual_claim_entry"]("/signed", "/signature")

    def test_live_r7_fleet_controller_stays_byte_identical(self):
        self.assertEqual(hashlib.sha256(FLEET.read_bytes()).hexdigest(), build.R7_SHA256)


if __name__ == "__main__":
    unittest.main()
