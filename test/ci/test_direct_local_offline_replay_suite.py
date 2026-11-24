"""The third-job suite renderer is read-only and defaults to HOLD."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_offline_replay_suite as adapter
import direct_local_workflow as mapping
from estate_policy import Hold


def policy():
    return {
        "execution_hosts": {mapping.REPO: "web"},
        "repositories": {mapping.REPO: {
            "branch": "main",
            "contract": mapping.sha256(ROOT / ".github/workflows/ci.yml"),
            "enrolled_head": "9" * 40,
            "suites": {
                suite: mapping.split_suite_spec(definition)
                for definition, (suite, _) in mapping.SPLIT.items()
            },
        }},
    }


class OfflineReplaySuiteTests(unittest.TestCase):
    def setUp(self):
        # The committed-source proof is exercised separately after integration.
        # During source development the two new files are intentionally untracked.
        patcher = patch.object(adapter, "source_clean")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_one_candidate_is_exact_nonexecutable(self):
        current = policy()
        before = copy.deepcopy(current)
        report = adapter.prepare(ROOT, current)
        self.assertEqual(current, before)
        self.assertEqual(report["workflow_job"], adapter.replay.JOB)
        self.assertEqual(report["suite_name"], adapter.SUITE)
        self.assertEqual(report["suite"]["image"], adapter.PINNED_IMAGE)
        self.assertEqual([s["command"] for s in report["suite"]["steps"]],
                         [command for _, command, _ in adapter.STEPS])
        self.assertLessEqual(sum(s["timeout"] for s in report["suite"]["steps"]) + 120, 900)
        self.assertEqual(report["suite"]["memory_mib"], 1536)
        self.assertTrue(report["requires_fresh_provider_main_readback"])
        self.assertTrue(report["requires_new_owner_signed_intent"])
        self.assertTrue(report["requires_separately_verified_signed_installation"])
        self.assertFalse(report["installed_policy_changed"])
        self.assertFalse(report["job_admitted"])
        self.assertFalse(report["job_executed"])
        self.assertFalse(report["provider_effect"])
        self.assertRegex(report["suite_sha256"], "^[0-9a-f]{64}$")

    def test_changed_established_guard_or_source_fails_closed(self):
        modifications = [
            lambda p: p["execution_hosts"].update({mapping.REPO: "other"}),
            lambda p: p["repositories"][mapping.REPO].update({"branch": "develop"}),
            lambda p: p["repositories"][mapping.REPO].update({"contract": "0" * 64}),
            lambda p: p["repositories"][mapping.REPO].update({"enrolled_head": "unknown"}),
            lambda p: p["repositories"][mapping.REPO]["suites"].update({adapter.SUITE: {}}),
            lambda p: p["repositories"][mapping.REPO]["suites"][
                "linux-node24-claw-check"].update({"image": "sha256:" + "0" * 64}),
            lambda p: p["repositories"][mapping.REPO]["suites"][
                "linux-node24-claw-sparse"].update({"memory_mib": 1024}),
            lambda p: p["repositories"][mapping.REPO]["suites"][
                "linux-node24-claw-check"].update({"execution_environment_revision": "unknown"}),
            lambda p: p["repositories"][mapping.REPO]["suites"][
                "linux-node24-claw-check"]["steps"][0].update({"timeout": 1}),
        ]
        for mutate in modifications:
            with self.subTest(mutate=repr(mutate)):
                value = policy()
                mutate(value)
                with self.assertRaises(Hold):
                    adapter.prepare(ROOT, value)

    def test_dirty_worktree_refuses_without_policy_effects(self):
        with patch.object(adapter, "source_clean", side_effect=Hold("dirty")):
            with self.assertRaises(Hold):
                adapter.prepare(ROOT, policy())

    def test_unreviewed_workflow_does_not_issue_suite(self):
        with patch.object(adapter.replay, "inspect", side_effect=Hold("workflow drift")):
            with self.assertRaises(Hold):
                adapter.prepare(ROOT, policy())

    def test_missing_or_malformed_policy_is_rejected(self):
        for value in (None, {}, {"repositories": []}):
            with self.subTest(policy=value):
                with self.assertRaises(Hold):
                    adapter.prepare(ROOT, value)


if __name__ == "__main__":
    unittest.main()
