"""Effect-free source-review candidate for the distinct offline replay job."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_offline_replay as replay
from estate_policy import Hold, load_manifest


class OfflineReplayTests(unittest.TestCase):
    def test_exact_source_candidate_is_not_execution_authority(self):
        report = replay.inspect(ROOT)
        self.assertEqual(report["job"], replay.JOB)
        self.assertTrue(report["source_and_dag_validated"])
        self.assertEqual(len(report["typed_steps"]), 4)
        self.assertEqual(report["workflow_total_timeout_seconds"], 900)
        self.assertTrue(all("timeout_seconds" not in step
                            for step in report["typed_steps"]))
        self.assertFalse(report["eligible_for_live_execution"])
        self.assertFalse(report["admitted"])
        self.assertFalse(report["executed"])
        self.assertFalse(report["github_provider_accepted"])
        self.assertFalse(report["external_effect_authority"])
        self.assertIsNone(report["terminal_receipt"])
        self.assertIn("distinct_owner_signed_manual_replay_intent",
                      report["next_required_gate"])

    def test_no_unreviewed_source_digest(self):
        with patch.object(replay, "EXPECTED_SHA256", "a" * 64):
            with self.assertRaises(Hold):
                replay.inspect(ROOT)

    def test_job_shape_and_event_authority_are_exact(self):
        changes = [
            lambda j: j.update({"execution_boundary": "guarded_sensitive_effects"}),
            lambda j: j.update({"events": ["push"]}),
            lambda j: j.update({"needs": ["check"]}),
            lambda j: j.update({"risks": ["secret_reference"]}),
            lambda j: j.update({"runs_on": ["ubuntu-latest"]}),
            lambda j: j.update({"status": "accepted"}),
            lambda j: j.update({"kind": "dynamic_or_other"}),
        ]
        for change in changes:
            with self.subTest(change=repr(change)):
                manifest = copy.deepcopy(load_manifest(
                    ROOT / "config/ci-workflow-estate.json"))
                row = next(j for j in manifest["jobs"]
                           if j["workflow"] + "#" + j["id"] == replay.JOB)
                change(row)
                with patch.object(replay, "load_manifest", return_value=manifest):
                    with self.assertRaises(Hold):
                        replay.inspect(ROOT)

    def test_removed_job_is_not_reclassified_as_ordinary(self):
        manifest = copy.deepcopy(load_manifest(
            ROOT / "config/ci-workflow-estate.json"))
        manifest["jobs"] = [j for j in manifest["jobs"]
                            if j["workflow"] + "#" + j["id"] != replay.JOB]
        with patch.object(replay, "load_manifest", return_value=manifest):
            with self.assertRaises(Hold):
                replay.inspect(ROOT)


if __name__ == "__main__":
    unittest.main()
