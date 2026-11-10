"""Migration parity: all 67 hosted job sources, default-off admission and Windows routing."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts" / "ci"))
from estate_policy import load_manifest, job_class

ROOT = Path(__file__).parents[2]
MANIFEST = load_manifest()
BASELINE = json.loads((ROOT / "engineering/hosted-runner-baseline.json").read_text())
MIGRATION = json.loads((ROOT / "engineering/migration-applied-summary.json").read_text())
PR106_OVERRIDES = json.loads((ROOT / "engineering/pr106-runner-overrides.json").read_text())
DYNAMIC_FAILCLOSED = json.loads((ROOT / "engineering/dynamic-hosted-failclosed.json").read_text())
assert DYNAMIC_FAILCLOSED["schema"] == "clawsweeper.dynamic-hosted-failclosed.v1"
assert PR106_OVERRIDES["parent_commit"] == "28addfb841f9605e634721d7d360d024ff91c636"
assert PR106_OVERRIDES["schema"] == "clawsweeper.pr106-runner-overrides.v1"


class MigrationParity(unittest.TestCase):
    def test_all_original_explicit_hosted_selectors_have_been_replaced(self):
        self.assertEqual(BASELINE["summary"]["github_hosted"], 67)
        self.assertEqual(MIGRATION["jobs_moved"], 67)
        self.assertTrue(MIGRATION["applied"])
        self.assertEqual(MANIFEST["summary"]["github_hosted"], 0)
        self.assertEqual(MANIFEST["summary"]["local_label"], 79)
        self.assertEqual(MANIFEST["summary"]["github_hosted"], 0)
        self.assertEqual(sum(x.get("prior_approved_p1_lane") is True for x in MIGRATION["jobs"]), 2)
        self.assertEqual(MANIFEST["summary"]["jobs"], 88)
        self.assertEqual(MANIFEST["summary"]["workflows"], 41)

    def test_label_class_platform_and_run_id_are_bound_for_every_conversion(self):
        after = {j["workflow"] + "#" + j["id"]: j for j in MANIFEST["jobs"]}
        for change in MIGRATION["jobs"]:
            key = change["workflow"] + "#" + change["id"]
            with self.subTest(job=key):
                job = after[key]
                self.assertEqual(job["kind"], "local_label")
                self.assertIn(change["label"], job["runs_on"])
                if change.get("prior_approved_p1_lane") is True:
                    self.assertEqual(job_class(job), "ordinary")
                    self.assertEqual(change["class"], "validation")
                else:
                    self.assertEqual(change["class"], job_class(job))
                self.assertIn("self-hosted", job["runs_on"])
                if change["platform"] == "Windows":
                    self.assertIn("Windows", job["runs_on"])
                    self.assertNotIn("Linux", job["runs_on"])
                else:
                    self.assertIn("Linux", job["runs_on"])
                    self.assertNotIn("Windows", job["runs_on"])

    def test_no_event_permission_or_admission_hint_lost(self):
        before = {j["workflow"] + "#" + j["id"]: j for j in BASELINE["jobs"]}
        after = {j["workflow"] + "#" + j["id"]: j for j in MANIFEST["jobs"]}
        self.assertEqual(set(before), set(after))
        prior_changes = set()
        for key, orig in before.items():
            current = after[key]
            with self.subTest(key=key):
                self.assertEqual(orig["events"], current["events"])
                self.assertTrue(set(orig["risks"]).issubset(set(current["risks"])),
                                "Cannot remove pre-existing trust risks: " + key)
                new_flags = set(current["risks"]) - set(orig["risks"])
                self.assertTrue(new_flags.issubset({
                    "workflow_secret_reference", "reusable_secret_inheritance",
                    "sensitive_upstream_dependency"
                }), "Unreviewed new trust classification: " + key)
                self.assertEqual(orig["display_name"], current["display_name"])
                if orig["kind"] != "github_hosted":
                    if orig["runs_on"] != current["runs_on"]:
                        prior_changes.add(key)
                        if key in PR106_OVERRIDES["entries"]:
                            self.assertEqual(current["runs_on"],
                                             PR106_OVERRIDES["entries"][key]["pr106_runner"])
                        else:
                            self.assertIn(key, DYNAMIC_FAILCLOSED["entries"])
                            pinned = DYNAMIC_FAILCLOSED["entries"][key]
                            self.assertEqual(orig["runs_on"], pinned["original_runner"])
                            self.assertEqual(current["runs_on"], pinned["safe_runner"])
                            self.assertEqual(current["source_sha256"], pinned["current_source_sha256"])
                    else:
                        self.assertNotIn(key, PR106_OVERRIDES["entries"])
                        self.assertNotIn(key, DYNAMIC_FAILCLOSED["entries"])
        self.assertEqual(prior_changes, set(PR106_OVERRIDES["entries"]) |
                         set(DYNAMIC_FAILCLOSED["entries"]))
        self.assertEqual(len(set(DYNAMIC_FAILCLOSED["entries"])), 4)
        self.assertEqual(
            {s["path"] for s in BASELINE["sources"]},
            {s["path"] for s in MANIFEST["sources"]},
        )

    def test_unreviewed_dynamic_routes_are_not_falsely_claimed_local(self):
        self.assertEqual(MANIFEST["summary"]["dynamic_hosted_fallback"], 0)
        self.assertEqual(MANIFEST["summary"]["dynamic_or_other"], 9)
        undecided = [j["workflow"] + "#" + j["id"] for j in MANIFEST["jobs"]
                     if j["kind"] in ("dynamic_hosted_fallback", "dynamic_or_other")]
        self.assertEqual(len(undecided), 9)
        self.assertIn(".github/workflows/repair-cluster-worker.yml#execute", undecided)
        # Missing dynamically provisioned runners must not start paid GitHub
        # execution. Every original hosted fallback is now fail-closed.
        baseline = {j["workflow"] + "#" + j["id"]: j for j in BASELINE["jobs"]}
        original_fallbacks = {k for k, j in baseline.items()
                              if j["kind"] == "dynamic_hosted_fallback"}
        self.assertEqual(len(original_fallbacks), 4)
        current = {j["workflow"] + "#" + j["id"]: j for j in MANIFEST["jobs"]}
        for key in original_fallbacks:
            selector = current[key]["runs_on"]
            self.assertIn("clawsweeper-unprovisioned-runner-held", selector)
            self.assertNotIn("ubuntu-latest", selector)
            self.assertEqual(current[key]["kind"], "dynamic_or_other")
        intake = current[".github/workflows/repair-issue-implementation-intake.yml#intake"]
        self.assertNotIn("github.event.client_payload.intake_runner", intake["runs_on"])
