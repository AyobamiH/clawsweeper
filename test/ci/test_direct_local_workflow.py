"""No-GitHub-Actions source routing contract for the existing ClawSweeper fleet."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci"
sys.path.insert(0, str(SCRIPT))
import direct_local_workflow as direct
from estate_policy import Hold, load_manifest


class DirectLocalWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest(ROOT / "config/ci-workflow-estate.json")
        cls.head = direct.git_head(ROOT)
        cls.ci_digest = direct.sha256(ROOT / ".github/workflows/ci.yml")

    def safe_policy(self):
        return {
            "execution_hosts": {direct.REPO: "web"},
            "repositories": {direct.REPO: {
                "branch": "main",
                "contract": self.ci_digest,
                "enrolled_head": self.head,
                "suites": {"linux-node24": {
                    "node": "24", "image": "sha256:" + "a" * 64,
                    "steps": [
                        {"name": "Workflow semantics",
                         "command": """actionlint -shellcheck= -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml""",
                         "timeout": 900},
                        {"name": "Dependencies", "command": "pnpm install --frozen-lockfile", "timeout": 900},
                        {"name": "Full check", "command": "pnpm run check", "timeout": 1500},
                        {"name": "Sparse smoke", "command": "pnpm run test:workflow-sparse-checkout", "timeout": 600},
                    ],
                }},
            }},
        }

    def test_entire_88_job_inventory_is_covered_by_one_owner(self):
        result = direct.compile_plan(ROOT, self.safe_policy(), commit=self.head, hostname="web")
        self.assertEqual(result["summary"]["workflows"], 41)
        self.assertEqual(result["summary"]["jobs"], 88)
        self.assertEqual(result["summary"]["classes"], direct.EXPECTED_CLASS_COUNTS)
        self.assertEqual(result["summary"]["mapped_to_existing_fleet"], 2)
        self.assertEqual(result["summary"]["held_for_class_specific_adapter"], 86)
        self.assertEqual(result["job_executions_observed"], 0)
        self.assertFalse(result["statuses_published"])
        self.assertFalse(result["provider_actions_dispatched"])
        self.assertEqual(len({j["key"] for j in result["jobs"]}), 88)

    def test_existing_fleet_runs_both_ordinary_jobs_as_one_pinned_suite(self):
        result = direct.compile_plan(ROOT, self.safe_policy(), commit=self.head, hostname="web")
        ready = [j for j in result["jobs"] if j["route"] == "existing-local-fleet"]
        self.assertEqual({j["key"] for j in ready}, set(direct.ORDINARY))
        self.assertEqual({j["suite"] for j in ready}, {"linux-node24"})
        self.assertEqual({j["required_step"] for j in ready}, set(direct.ORDINARY.values()))
        self.assertTrue(all(j["execution_observed"] is False for j in ready))

    def test_source_sha_cannot_be_substituted_for_local_tree_head(self):
        with self.assertRaises(Hold):
            direct.compile_plan(ROOT, self.safe_policy(), commit="d" * 40, hostname="web")

    def test_extra_execution_command_cannot_be_smuggled_into_existing_fleet(self):
        p = self.safe_policy()
        p["repositories"][direct.REPO]["suites"]["linux-node24"]["steps"].append(
            {"name": "unreviewed", "command": "curl https://example.com", "timeout": 10}
        )
        result = direct.compile_plan(ROOT, p, commit=self.head, hostname="web")
        self.assertEqual(result["summary"]["mapped_to_existing_fleet"], 0)

    def test_stale_live_fleet_source_pin_holds_ordinary_jobs(self):
        p = self.safe_policy()
        p["repositories"][direct.REPO]["contract"] = "0" * 64
        result = direct.compile_plan(ROOT, p, commit=self.head, hostname="web")
        self.assertEqual(result["summary"]["mapped_to_existing_fleet"], 0)
        self.assertEqual(result["summary"]["held_for_existing_fleet_source_pin"], 2)
        self.assertEqual(len([j for j in result["jobs"] if j["route"] == "held"]), 88)

    def test_wrong_head_or_owner_host_blocks_execution(self):
        for mutation, hostname in (
            ({"enrolled_head": "b" * 40}, "web"),
            ({}, "untrusted-host"),
        ):
            p = self.safe_policy()
            p["repositories"][direct.REPO].update(mutation)
            d = direct.compile_plan(ROOT, p, commit=self.head, hostname=hostname)
            self.assertEqual(d["summary"]["mapped_to_existing_fleet"], 0)

    def test_source_only_manifest_never_grants_execution(self):
        d = direct.compile_plan(ROOT, commit=self.head)
        self.assertEqual(d["summary"]["mapped_to_existing_fleet"], 0)
        self.assertTrue(all(j["route"] == "held" for j in d["jobs"]))

    def test_missing_sparse_command_and_unpinned_image_hold(self):
        p = self.safe_policy()
        p["repositories"][direct.REPO]["suites"]["linux-node24"]["steps"].pop()
        d = direct.compile_plan(ROOT, p, commit=self.head, hostname="web")
        self.assertEqual(d["summary"]["mapped_to_existing_fleet"], 0)
        p = self.safe_policy()
        p["repositories"][direct.REPO]["suites"]["linux-node24"]["image"] = "latest"
        d = direct.compile_plan(ROOT, p, commit=self.head, hostname="web")
        self.assertEqual(d["summary"]["mapped_to_existing_fleet"], 0)

    def test_secrets_review_codeql_e2e_windows_never_become_generic_validation(self):
        d = direct.compile_plan(ROOT, self.safe_policy(), commit=self.head, hostname="web")
        for job in d["jobs"]:
            if job["class"] != "ordinary":
                self.assertEqual(job["route"], "held", job["key"])
                self.assertIsNone(job["suite"])

    def test_readonly_source_mutation_and_added_workflows_hold(self):
        with tempfile.TemporaryDirectory(prefix="clawsweeper-direct-local-") as tmp:
            other = Path(tmp)
            shutil.copytree(ROOT / ".github/workflows", other / ".github/workflows")
            shutil.copytree(ROOT / "config", other / "config")
            original = other / ".github/workflows/ci.yml"
            original.write_bytes(original.read_bytes() + b"\n# unexpected new source\n")
            with self.assertRaises(Hold):
                direct.source_check(self.manifest, other)
            original.write_bytes((ROOT / ".github/workflows/ci.yml").read_bytes())
            (other / ".github/workflows/new-dangerous.yml").write_text("on: push\n")
            with self.assertRaises(Hold):
                direct.source_check(self.manifest, other)

    def test_unknown_needs_and_cycles_are_never_executable(self):
        sample = copy.deepcopy(self.manifest)
        sample["jobs"] = [
            {"workflow": ".github/workflows/fake.yml", "id": "a", "needs": ["missing"]},
        ]
        with self.assertRaises(Hold):
            direct.dag_check(sample)
        sample["jobs"] = [
            {"workflow": ".github/workflows/fake.yml", "id": "a", "needs": ["b"]},
            {"workflow": ".github/workflows/fake.yml", "id": "b", "needs": ["a"]},
        ]
        with self.assertRaises(Hold):
            direct.dag_check(sample)

    def test_unreviewed_job_count_raises_before_any_worker(self):
        x = copy.deepcopy(self.manifest)
        x["jobs"].append(copy.deepcopy(x["jobs"][0]))
        with self.assertRaises(Hold):
            direct.source_check(x, ROOT)

    def test_stable_class_counts_fail_on_unapproved_reclassification(self):
        x = copy.deepcopy(self.manifest)
        override = next(j for j in x["jobs"] if j["id"] == "check"
                        and j["workflow"] == ".github/workflows/ci.yml")
        override["risks"] = ["secret_reference"]
        with self.assertRaises(Hold):
            direct.job_class(override)


if __name__ == "__main__":
    unittest.main()
