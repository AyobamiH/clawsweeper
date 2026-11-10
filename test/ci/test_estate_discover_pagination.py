"""Bounded, identity-checked GitHub job pagination; no API effects."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts" / "ci"))
from estate_controller import verified_run_jobs, discover
from estate_policy import Hold, load_manifest, REPO

RUN_ID = 741
SHA = "a" * 40
WORKFLOW = ".github/workflows/codeql.yml"

def page_api(pages):
    calls = []
    def api(path):
        calls.append(path)
        n = int(path.rsplit("page=", 1)[-1])
        return pages.get(n, {"total_count": pages[1]["total_count"], "jobs": []})
    return api, calls

class JobPagination(unittest.TestCase):
    def setUp(self):
        self.first = [{"id": i, "run_id": RUN_ID, "status": "completed"} for i in range(1, 101)]
        self.last = {"id": 101, "run_id": RUN_ID, "status": "queued",
                     "name": "Analyze (actions)",
                     "labels": ["self-hosted", "Linux", "X64",
                                f"clawsweeper-ci-security-{RUN_ID}-actions"]}

    def test_all_101_jobs_are_seen(self):
        api, calls = page_api({1: {"total_count": 101, "jobs": self.first},
                               2: {"total_count": 101, "jobs": [self.last]}})
        items = verified_run_jobs(RUN_ID, api)
        self.assertEqual(len(items), 101)
        self.assertEqual(items[-1]["id"], 101)
        self.assertEqual(len(calls), 2)

    def test_discovery_does_not_lose_queued_job_on_page_two(self):
        jobs_api, _ = page_api({1: {"total_count": 101, "jobs": self.first},
                                2: {"total_count": 101, "jobs": [self.last]}})
        run = {"id": RUN_ID, "run_attempt": 1, "head_sha": SHA,
               "head_branch": "example", "repository": {"full_name": REPO},
               "path": WORKFLOW, "event": "pull_request"}
        def api(path):
            if "/actions/runs?" in path:
                return {"workflow_runs": [run] if "status=queued" in path else []}
            return jobs_api(path)
        result = discover(load_manifest(), api)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0].job_id, 101)

    def test_total_count_drift_is_a_hold(self):
        api, _ = page_api({1: {"total_count": 101, "jobs": self.first},
                           2: {"total_count": 102, "jobs": [self.last]}})
        with self.assertRaisesRegex(Hold, "incomplete_github_job_inventory"):
            verified_run_jobs(RUN_ID, api)

    def test_duplicate_job_identity_is_a_hold(self):
        duplicate = dict(self.last, id=100)
        api, _ = page_api({1: {"total_count": 101, "jobs": self.first},
                           2: {"total_count": 101, "jobs": [duplicate]}})
        with self.assertRaisesRegex(Hold, "inconsistent_github_job_inventory"):
            verified_run_jobs(RUN_ID, api)

    def test_partial_second_page_is_a_hold(self):
        api, _ = page_api({1: {"total_count": 102, "jobs": self.first},
                           2: {"total_count": 102, "jobs": [self.last]}})
        with self.assertRaisesRegex(Hold, "incomplete_github_job_inventory"):
            verified_run_jobs(RUN_ID, api)

    def test_more_than_twenty_pages_is_a_hold(self):
        api, _ = page_api({1: {"total_count": 2001, "jobs": self.first}})
        with self.assertRaisesRegex(Hold, "incomplete_github_job_inventory"):
            verified_run_jobs(RUN_ID, api)

    def test_single_page_and_empty_inventory(self):
        for jobs in ([], [self.last]):
            api, calls = page_api({1: {"total_count": len(jobs), "jobs": jobs}})
            self.assertEqual(verified_run_jobs(RUN_ID, api), jobs)
            self.assertEqual(len(calls), 1)

if __name__ == "__main__":
    unittest.main()
