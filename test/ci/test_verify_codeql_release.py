"""Adversarial no-network tests for CodeQL head/merge SARIF reconciliation."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import verify_codeql_release as verifier

HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
RUN_ID = 123
BRANCH = "signed-candidate"
START = "2026-11-07T10:00:00Z"
FINISH = "2026-11-07T10:10:00Z"
SCAN_TIME = "2026-11-07T10:05:00Z"


def fixture(event="workflow_dispatch"):
    run = {
        "id": RUN_ID, "head_sha": HEAD, "head_branch": BRANCH,
        "path": ".github/workflows/codeql.yml", "status": "completed",
        "conclusion": "success", "run_attempt": 1, "event": event,
        "pull_requests": [{"number": 8, "head": {"sha": HEAD}, "base": {"sha": BASE}}],
    }
    jobs = [
        {
            "id": n, "name": title, "status": "completed",
            "conclusion": "success", "runner_name": f"csw-ci-{RUN_ID}-{n}-1",
            "labels": ["self-hosted", f"clawsweeper-ci-security-{RUN_ID}-{lang}"],
            "started_at": START, "completed_at": FINISH,
        }
        for n, (lang, title) in enumerate(verifier.LANGUAGES.items(), 7)
    ]
    ref = f"refs/heads/{BRANCH}" if event != "pull_request" else "refs/pull/8/merge"
    sha = HEAD if event != "pull_request" else MERGE
    analyses = [
        {
            "id": n+100, "tool": {"name": "CodeQL"}, "analysis_key": ".github/workflows/codeql.yml:analyze",
            "category": f"/language:{lang}", "ref": ref, "commit_sha": sha,
            "created_at": SCAN_TIME, "error": "",
        }
        for n, lang in enumerate(verifier.LANGUAGES)
    ]
    return {
        f"{verifier.API}/actions/runs/{RUN_ID}": run,
        f"{verifier.API}/commits/{HEAD}": {
            "sha": HEAD, "commit": {"verification": {"verified": True}}},
        f"{verifier.API}/git/ref/heads/{BRANCH}": {"object": {"sha": HEAD}},
        f"{verifier.API}/pulls/8": {
            "head": {"sha": HEAD, "ref": BRANCH},
            "base": {"sha": BASE}, "merge_commit_sha": MERGE},
        f"{verifier.API}/git/ref/pull/8/merge": {
            "ref": "refs/pull/8/merge", "object": {"sha": MERGE}},
        f"{verifier.API}/commits/{MERGE}": {
            "sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}]},
        f"{verifier.API}/actions/runs/{RUN_ID}/jobs?per_page=100": {"jobs": jobs},
        f"{verifier.API}/code-scanning/analyses?per_page=100&page=1": analyses,
        f"{verifier.API}/code-scanning/alerts/3": {
            "state": "fixed", "rule": {"id": "js/clear-text-logging"}},
    }


class Tests(unittest.TestCase):
    def verified(self, data, **kw):
        def get(path):
            if path not in data:
                raise AssertionError("unexpected GitHub API: " + path)
            return copy.deepcopy(data[path])
        return verifier.verify_release(get, RUN_ID, HEAD, **kw)

    def test_signed_branch_head_and_both_languages_pass(self):
        data = fixture()
        report = self.verified(data, require_closed_alert=True)
        self.assertEqual(report["event"], "workflow_dispatch")
        self.assertEqual(report["analyses"]["actions"]["commit_sha"], HEAD)
        self.assertTrue(report["security_alert_3_fixed"])

    def test_signed_synthetic_pr_merge_must_have_exact_parents(self):
        data = fixture("pull_request")
        report = self.verified(data, pr_number=8)
        self.assertEqual(report["analyses"]["actions"]["commit_sha"], MERGE)
        self.assertEqual(report["analyses"]["javascript-typescript"]["ref"],
                         "refs/pull/8/merge")
        for wrong in ([HEAD, BASE], [BASE, "d" * 40], [BASE]):
            altered = copy.deepcopy(data)
            altered[f"{verifier.API}/commits/{MERGE}"]["parents"] = [
                {"sha": value} for value in wrong]
            with self.subTest(parents=wrong), self.assertRaisesRegex(
                    verifier.EvidenceRefused, "merge_parents_mismatch"):
                self.verified(altered, pr_number=8)

    def test_pr_also_allows_exact_head_scans_without_misassociation(self):
        data = fixture("pull_request")
        for scan in data[f"{verifier.API}/code-scanning/analyses?per_page=100&page=1"]:
            scan["commit_sha"] = HEAD
            scan["ref"] = f"refs/heads/{BRANCH}"
        self.assertEqual(self.verified(data, pr_number=8)["event"], "pull_request")

    def test_modified_runner_language_or_analysis_ref_refused(self):
        data = fixture()
        modifications = [
            ("run_head", f"{verifier.API}/actions/runs/{RUN_ID}", "head_sha", BASE),
            ("run_failed", f"{verifier.API}/actions/runs/{RUN_ID}", "conclusion", "failure"),
            ("run_workflow", f"{verifier.API}/actions/runs/{RUN_ID}", "path", "different.yml"),
            ("unsigned", f"{verifier.API}/commits/{HEAD}", None, None),
        ]
        for label, key, field, value in modifications:
            altered = copy.deepcopy(data)
            if label == "unsigned":
                altered[key]["commit"]["verification"]["verified"] = False
            else:
                altered[key][field] = value
            with self.subTest(label=label), self.assertRaises(verifier.EvidenceRefused):
                self.verified(altered)
        for kind in ("wrong_runner", "failed_job", "missing_label"):
            altered = copy.deepcopy(data)
            j = altered[f"{verifier.API}/actions/runs/{RUN_ID}/jobs?per_page=100"]["jobs"][0]
            if kind == "wrong_runner": j["runner_name"] = "owner-host"
            elif kind == "failed_job": j["conclusion"] = "failure"
            else: j["labels"] = []
            with self.subTest(kind=kind), self.assertRaises(verifier.EvidenceRefused):
                self.verified(altered)
        for kind in ("wrong_ref", "old_time", "error", "wrong_key", "missing_language"):
            altered = copy.deepcopy(data)
            scans = altered[f"{verifier.API}/code-scanning/analyses?per_page=100&page=1"]
            if kind == "wrong_ref": scans[0]["ref"] = "refs/heads/main"
            elif kind == "old_time": scans[0]["created_at"] = "2026-11-01T01:00:00Z"
            elif kind == "error": scans[0]["error"] = "upload failed"
            elif kind == "wrong_key": scans[0]["analysis_key"] = "unrelated"
            else: scans.pop()
            with self.subTest(kind=kind), self.assertRaises(verifier.EvidenceRefused):
                self.verified(altered)

    def test_open_alert_remains_visible_and_blocks_final_approval(self):
        data = fixture()
        data[f"{verifier.API}/code-scanning/alerts/3"]["state"] = "open"
        report = self.verified(data)
        self.assertFalse(report["security_alert_3_fixed"])
        with self.assertRaisesRegex(verifier.EvidenceRefused, "release_security_alert_not_fixed"):
            self.verified(data, require_closed_alert=True)

    def test_unpinned_pr_and_branch_drift_refuse(self):
        data = fixture("pull_request")
        with self.assertRaisesRegex(verifier.EvidenceRefused, "pull_request_not_pinned"):
            self.verified(data)
        data = fixture()
        data[f"{verifier.API}/git/ref/heads/{BRANCH}"]["object"]["sha"] = BASE
        with self.assertRaisesRegex(verifier.EvidenceRefused, "branch_head_moved"):
            self.verified(data)

    def test_owner_receipt_and_log_hash_validated(self):
        with tempfile.TemporaryDirectory() as root:
            data = fixture()
            for job in data[f"{verifier.API}/actions/runs/{RUN_ID}/jobs?per_page=100"]["jobs"]:
                path = Path(root) / f"run-{RUN_ID}-job-{job['id']}-attempt-1"
                path.mkdir()
                payload = b"Verified bounded runner log\n"
                (path / "runner.log").write_bytes(payload)
                receipt = {
                    "schema": "clawsweeper.selfhosted-jit.v1",
                    "run_id": RUN_ID, "job_id": job["id"], "attempt": 1,
                    "head_sha": HEAD, "runner_name": job["runner_name"],
                    "state": "passed", "issues": [], "runner_exit": 0,
                    "github_job": {"conclusion": "success", "runner_name": job["runner_name"]},
                    "log_bytes": len(payload), "log_sha256": hashlib.sha256(payload).hexdigest(),
                }
                (path / "receipt.json").write_text(json.dumps(receipt))
            report = self.verified(data, receipts=Path(root))
            self.assertIn("receipt_sha256", report["jobs"]["actions"])
            with open(Path(root)/f"run-{RUN_ID}-job-7-attempt-1"/"runner.log", "ab") as f:
                f.write(b"malicious trailing bytes")
            with self.assertRaisesRegex(verifier.EvidenceRefused, "runner_receipt_invalid"):
                self.verified(data, receipts=Path(root))


if __name__ == "__main__":
    unittest.main()
