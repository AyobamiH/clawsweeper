"""No-install render proof for the third replay suite in the existing controller."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sys
import subprocess
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/"scripts/ci"))
import direct_local_replay_controller as c


class ReplayControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Path("/home/johnh/.local/share/local-ci/fleet_ci.py")
        cls.library = Path("/home/johnh/.local/share/local-ci/clawsweeper-manual-code-v3")
        if not cls.runtime.is_file() or not cls.library.is_dir():
            raise unittest.SkipTest("Owner's existing installed fleet not present")
        cls.installed = cls.runtime.read_bytes()
        cls.original = hashlib.sha256(cls.installed).hexdigest()
        cls.frozen = {p.name: p.read_bytes()
                      for p in cls.library.iterdir() if p.is_file()}
        cls.source_sha = subprocess.check_output(
            ["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()

    def render(self, installed=None, digest=None, frozen=None, source_sha=None):
        return c.render(self.installed if installed is None else installed,
                        self.original if digest is None else digest,
                        self.frozen if frozen is None else frozen,
                        source_root=ROOT, source_sha=source_sha or self.source_sha)

    def function(self, tree, name):
        matches = [v for v in tree.body
                   if isinstance(v, ast.FunctionDef) and v.name==name]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_exact_single_existing_fleet_render_no_effect(self):
        report = self.render()
        self.assertEqual(report["installed_sha256"], self.original)
        self.assertEqual(report["state"], "prepared_not_installed")
        for key in ("installed", "executed", "new_controller",
                    "new_service", "github_dispatch"):
            self.assertFalse(report[key])
        self.assertEqual(len(report["frozen_hashes"]), 12)
        self.assertEqual(len(report["extra_frozen_files"]), 4)
        self.assertEqual(report["candidate_sha256"],
                         hashlib.sha256(report["controller"]).hexdigest())
        tree = ast.parse(report["controller"])
        for name in ("validate_job", "publish", "publish_pending",
                     "current_reference", "run_job", "main",
                     "_signed_replay_claim_entry", "_verified_replay_claim"):
            self.function(tree, name)
        candidate = report["controller"].decode()
        for expected in (
            "clawsweeper.existing-fleet-single-replay-claim.v1",
            "replay_existing_fleet_claim",
            "'local-manual-replay'",
            "replay_wrong_source_ref_or_job",
            "replay_unverified_terminal_cleanup",
            "replay_owner_proof_not_verified",
            "receipt['provider_status']='suppressed-local-replay'",
            "min(cfg.get('total_timeout',10800),900)",
            "replay_requires_web_signed_files",
            "replay_admission_result_not_exact",
            "direct_local_replay_admission.py",
            "direct_local_offline_replay_suite.py",
            "_verified_manual_success_receipt(job,receipt)",
            "job['suite'] in ('linux-node24-claw-check',",
        ):
            self.assertTrue(expected in candidate, expected)

    def test_successor_replaces_historical_gate_with_exact_source_contract(self):
        candidate = self.render()["controller"].decode()
        self.assertIn("Source-bound ClawSweeper split-suite validation v2", candidate)
        self.assertNotIn("Source-bound ClawSweeper split-suite validation v1", candidate)
        self.assertIn("Unreviewed ClawSweeper historical aggregate", candidate)

    def test_same_source_and_policy_renders_deterministically(self):
        a, b = self.render(), self.render()
        self.assertEqual(a["candidate_sha256"], b["candidate_sha256"])
        self.assertEqual(c._old_map(self.installed.decode()), a["historical_frozen_hashes"])
        self.assertEqual(a["source_sha"], self.source_sha)
        for name, raw in a["frozen_sources"].items():
            expected = subprocess.check_output(
                ["/usr/bin/git", "-C", str(ROOT), "cat-file", "blob",
                 self.source_sha + ":scripts/ci/" + name])
            self.assertEqual(raw, expected)
            self.assertEqual(a["frozen_hashes"][name], hashlib.sha256(expected).hexdigest())

    def test_updated_adapter_is_not_silently_replaced_by_installed_bytes(self):
        report = self.render()
        self.assertNotEqual(report["frozen_hashes"]["direct_local_workflow.py"],
                            report["historical_frozen_hashes"]["direct_local_workflow.py"])
        self.assertIn(b"def split_suite_spec(", report["frozen_sources"]["direct_local_workflow.py"])
        self.assertIn("repo_integrity.require_unheld(_replay_hold_db, _MANUAL_REPO)",
                      report["controller"].decode())

    def test_wrong_controller_hash_and_historical_module_drift_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "unverified_installed"):
            self.render(digest="0"*64)
        files = dict(self.frozen)
        files["direct_local_fleet_claim.py"] += b"\n# changed source\n"
        with self.assertRaisesRegex(ValueError, "historical_v3"):
            self.render(frozen=files)

    def test_missing_extra_and_already_modified_controller_refused(self):
        files = dict(self.frozen)
        files.pop("direct_local_signed_split_manual.py")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.render(frozen=files)
        files = dict(self.frozen)
        files["unexpected.py"] = b"oops"
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.render(frozen=files)
        with self.assertRaisesRegex(ValueError, "successor_source_sha"):
            self.render(source_sha="HEAD")
        with self.assertRaisesRegex(ValueError, "successor_git_verification"):
            self.render(source_sha="0"*40)
        self.assertNotEqual(self.render()["candidate_sha256"], self.original)

    def test_source_ref_blocks_fake_main_or_pr_provider_route(self):
        tree = ast.parse(self.render()["controller"])
        fn = self.function(tree, "validate_job")
        code = compile(ast.Module(body=[fn], type_ignores=[]),
                       "<candidate-validate-job>", "exec")
        ns = {"_MANUAL_REPO": c.REPO}
        exec(code,ns)
        job = {"repo": c.REPO, "suite":c.SUITE, "ref":"main"}
        with self.assertRaisesRegex(RuntimeError,"wrong_source_ref"):
            ns["validate_job"](job, {})
        job["ref"] = "pr/123"
        with self.assertRaisesRegex(RuntimeError,"wrong_source_ref"):
            ns["validate_job"](job, {})
        job["ref"] = c.REF
        job["suite"] = "linux-node24-claw-check"
        with self.assertRaisesRegex(RuntimeError,"wrong_source_ref"):
            ns["validate_job"](job, {})

    def test_replay_error_is_terminal_without_implicit_second_run(self):
        # A source-only review must not allow auto-retrying a one-use intent.
        tree = ast.parse(self.render()["controller"])
        fn = self.function(tree, "run_job")
        assignment = [n for n in ast.walk(fn)
                      if isinstance(n, ast.Assign)
                      and any(isinstance(target, ast.Name)
                              and target.id == "retry" for target in n.targets)]
        self.assertEqual(len(assignment), 1)
        code = compile(ast.Expression(body=assignment[0].value),
                       "<candidate-replay-retry>", "eval")
        values = {"outcome": "error", "attempt": 1, "receipt": {},
                  "_MANUAL_REPO": c.REPO}
        replay = dict(repo=c.REPO, ref=c.REF)
        original = dict(repo=c.REPO, ref="local-manual")
        self.assertFalse(eval(code, values, {"job": replay}))
        self.assertTrue(eval(code, values, {"job": original}))
        self.assertFalse(eval(code, dict(values, outcome="success"),
                              {"job": original}))

    def test_replay_success_requires_actual_64_character_container_id(self):
        # The installed verifier checked only the two historical suites.
        tree = ast.parse(self.render()["controller"])
        fn = self.function(tree, "_verified_manual_success_receipt")
        ns = {"re": __import__("re")}
        exec(compile(ast.Module(body=[fn], type_ignores=[]),
                     "<candidate-replay-container-id>", "exec"), ns)
        for wrong in (None, "", "fabricated", "a" * 63):
            with self.subTest(container=wrong):
                with self.assertRaisesRegex(RuntimeError,
                                            "without_real_container_id"):
                    ns["_verified_manual_success_receipt"](
                        {"suite": c.SUITE}, {"engine_container_id": wrong})

    def test_publish_success_is_local_only_and_requires_cleanup(self):
        tree = ast.parse(self.render()["controller"])
        fn = self.function(tree, "publish")
        code = compile(ast.Module(body=[fn], type_ignores=[]),
                       "<candidate-publish>", "exec")
        calls = []
        fake_core = types.SimpleNamespace(
            atomic=lambda *args: calls.append(("atomic",args)),
            api=lambda *args: self.fail("provider must never be touched"))
        ns = {"_MANUAL_REPO": c.REPO, "core": fake_core,
              "_verified_replay_claim":
                  lambda job: {"request_sha256": "f"*64},
              "_verified_manual_success_receipt":
                  lambda job,receipt: calls.append(("verified_success",)),
              "EVIDENCE": Path("/tmp")}
        exec(code,ns)
        job = {"id":"local-fleet-abcdef123456", "repo":c.REPO,
               "sha":"a"*40, "suite":c.SUITE, "ref":c.REF,
               "policy":"b"*64}
        receipt = dict(job, outcome="success",
                       cleanup={"container_absent": True})
        class DB:
            def execute(self,*args):
                calls.append(("execute",args))
            def commit(self):
                calls.append(("commit",))
        self.assertIsNone(ns["publish"](DB(),job,"pending","queued"))
        self.assertFalse(calls)
        bad = dict(receipt, cleanup={"container_absent":False})
        with self.assertRaisesRegex(RuntimeError,"cleanup"):
            ns["publish"](DB(),job,"success","done",bad)
        self.assertFalse(calls)
        self.assertIsNone(ns["publish"](DB(),job,"success","done",receipt))
        self.assertEqual(receipt["provider_status"], "suppressed-local-replay")
        self.assertIsNone(receipt["github_status"])
        self.assertEqual(receipt["manual_request_sha256"], "f"*64)
        self.assertEqual([item[0] for item in calls],
                         ["verified_success","atomic","execute","commit"])


if __name__ == "__main__":
    unittest.main()
