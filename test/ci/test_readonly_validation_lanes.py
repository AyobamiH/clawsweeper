"""Admission and exact-source tests for the non-privileged local CI pilot."""
import base64
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import self_hosted_policy as p
import self_hosted_executor as e

BASE = "a" * 40
HEAD = "b" * 40
MERGE = "d" * 40
RUN_ID = 9876

def run(event="pull_request", branch="feature", actor="contributor", sha=HEAD):
    return {
        "id": RUN_ID, "run_attempt": 1, "path": ".github/workflows/ci.yml",
        "status": "in_progress", "repository": {"full_name": p.REPOSITORY, "id": 88},
        "head_branch": branch, "head_sha": sha, "event": event,
        "actor": {"login": actor},
        "pull_requests": [{"number": 101,
                           "base": {"ref": "main", "sha": BASE, "repo": {"id": 88}},
                           "head": {"sha": HEAD, "repo": {"id": 99}}}],
    }

def job(slot="check"):
    return {
        "id": 333, "run_id": RUN_ID,
        "name": "pnpm check" if slot == "check" else "sparse repair build smoke",
        "status": "queued",
        "labels": ["self-hosted", "Linux", "X64", f"clawsweeper-ci-validation-{RUN_ID}-{slot}"],
    }

def controls(**updates):
    x = {
        "enabled": True, "repo": p.REPOSITORY, "enabled_roles": ["validation"],
        "validation_accepted": True, "trusted_main_sha": BASE, "max_jobs_per_cycle": 1,
        "trusted_workflow_sha256": {".github/workflows/ci.yml": hashlib.sha256(b"original").hexdigest()},
    }
    x.update(updates)
    return x

class ReadonlyValidation(unittest.TestCase):
    def test_full_ci_and_sparse_jobs_admit_only_documented_events(self):
        for slot in ("check", "sparse"):
            with self.subTest(slot=slot):
                candidate = p.classify(run(), job(slot))
                self.assertEqual(candidate.role, "validation")
                self.assertTrue(p.category_enabled(candidate, controls()))
        for slot in ("check", "sparse"):
            for event in ("issue_comment", "pull_request_target", "repository_dispatch"):
                with self.subTest(slot=slot, event=event):
                    with self.assertRaisesRegex(p.AdmissionHold, "unapproved_event"):
                        p.classify(run(event), job(slot))
        with self.assertRaisesRegex(p.AdmissionHold, "unapproved_event"):
            p.classify(run("push", branch="main", actor="AyobamiH", sha=BASE), job("sparse"))

    def test_review_and_windows_jobs_stay_separate(self):
        # Standard-library test: Python CI must not depend on host PyYAML.
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        sections = {}
        for name in ("hosted-review-scan", "check", "sparse-repair-builds", "windows-codex-launch"):
            start = "  " + name + ":\n"
            self.assertIn(start, text)
            tail = text.split(start, 1)[1]
            import re
            next_job = re.search(r"(?m)^  [A-Za-z][A-Za-z0-9_-]+:$", tail)
            sections[name] = tail[:next_job.start()] if next_job else tail
        runid = chr(36) + "{{ github.run_id }}"
        self.assertIn(
            "clawsweeper-ci-review-" + runid + "-hosted-review-scan",
            sections["hosted-review-scan"],
        )
        self.assertIn(
            "clawsweeper-ci-windows-" + runid + "-windows-codex-launch",
            sections["windows-codex-launch"],
        )
        self.assertIn("self-hosted,", sections["windows-codex-launch"])
        self.assertIn("Windows,", sections["windows-codex-launch"])
        self.assertNotIn("Linux,", sections["windows-codex-launch"])
        self.assertNotIn("ubuntu-", sections["hosted-review-scan"])
        for name in ("check", "sparse-repair-builds"):
            body = sections[name]
            self.assertIn("runs-on: [self-hosted, Linux, X64,", body)
            self.assertIn("persist-credentials: false", body)
            self.assertNotIn("secrets.", body)
        self.assertIn("permissions:\n  contents: read", text)

    def test_default_denial_and_owner_bounded_preview(self):
        c = p.classify(run(), job())
        for kwargs, reason in [
            ({"enabled": False}, "controller_disabled"),
            ({"enabled_roles": []}, "role_not_accepted"),
            ({"validation_accepted": False}, "validation_not_accepted"),
            ({"trusted_main_sha": None}, "validation_main_not_pinned"),
            ({"validation_candidate_sha256": "f" * 64}, "validation_candidate_not_run_pinned"),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(p.AdmissionHold, reason):
                p.category_enabled(c, controls(**kwargs))
        self.assertTrue(p.category_enabled(c, controls(
            validation_candidate_sha256="f" * 64, allowed_run_ids=[RUN_ID])))
        with self.assertRaisesRegex(p.AdmissionHold, "unbounded_worker_configuration"):
            p.category_enabled(c, controls(max_jobs_per_cycle=2))
        with self.assertRaisesRegex(p.AdmissionHold, "validation_default_branch_owner_unverified"):
            p.classify(run("workflow_dispatch", branch="main", actor="untrusted"), job())
        self.assertEqual(p.classify(run("push", branch="main", actor="GitHub-App", sha=BASE), job()).role, "validation")
        self.assertTrue(p.category_enabled(p.classify(
            run("push", branch="main", actor="AyobamiH", sha=BASE), job()), controls()))

    def test_stacked_prs_and_forks_keep_original_ci_trigger(self):
        good = run()
        self.assertEqual(p.classify(good, job()).pr_number, 101)
        stacked = run()
        stacked["pull_requests"][0]["base"]["ref"] = "feature/stacked"
        self.assertEqual(p.classify(stacked, job()).trusted_base_sha, BASE)
        invalid = [
            dict(good, pull_requests=[]),
            dict(good, pull_requests=[{**good["pull_requests"][0],
                                      "base": {**good["pull_requests"][0]["base"],
                                               "repo": {"id": 99}}}]),
            dict(good, pull_requests=[{**good["pull_requests"][0],
                                      "head": {"sha": BASE, "repo": {"id": 99}}}]),
            dict(good, pull_requests=[{**good["pull_requests"][0], "number": None}]),
        ]
        for info in invalid:
            with self.assertRaisesRegex(p.AdmissionHold, "validation_pr_base_unverified"):
                p.classify(info, job())

    def test_source_bytes_immutable_and_temporary_preview_run_bound(self):
        candidate = p.classify(run(), job())
        main_source = b"original"
        preview_source = b"approved migration preview"
        preview_digest = hashlib.sha256(preview_source).hexdigest()

        def fakegh(path):
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": BASE}}
            if path.endswith("?ref=" + BASE):
                return {"content": base64.b64encode(main_source).decode()}
            if path.endswith("/git/ref/pull/101/merge"):
                return {"object": {"sha": MERGE}}
            if path.endswith("/git/commits/" + MERGE):
                return {"parents": [{"sha": BASE}, {"sha": HEAD}]}
            if path.endswith("?ref=" + HEAD) or path.endswith("?ref=" + MERGE):
                return {"content": base64.b64encode(preview_source).decode()}
            raise AssertionError(path)

        with patch.object(e, "gh", side_effect=fakegh):
            with self.assertRaisesRegex(p.AdmissionHold, "validation_workflow_drift"):
                e.source_authorised(candidate, controls())
            self.assertTrue(e.source_authorised(candidate, controls(
                validation_candidate_sha256=preview_digest, allowed_run_ids=[RUN_ID])))
            with self.assertRaisesRegex(p.AdmissionHold, "validation_candidate_workflow_drift"):
                e.source_authorised(candidate, controls(
                    validation_candidate_sha256="c" * 64, allowed_run_ids=[RUN_ID]))
            with self.assertRaisesRegex(p.AdmissionHold, "validation_main_changed"):
                e.source_authorised(candidate, controls(trusted_main_sha="c"*40))
            with self.assertRaisesRegex(p.AdmissionHold, "validation_baseline_changed"):
                e.source_authorised(candidate, controls(
                    trusted_workflow_sha256={".github/workflows/ci.yml": "f"*64}))

    def test_pull_request_merge_parent_drift_and_merged_yaml_change_refuse(self):
        candidate = p.classify(run(), job())
        original = b"original"
        preview = b"approved preview"
        digest = hashlib.sha256(preview).hexdigest()
        def gh(path):
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": BASE}}
            if path.endswith("/git/ref/pull/101/merge"):
                return {"object": {"sha": MERGE}}
            if path.endswith("/git/commits/" + MERGE):
                return {"parents": [{"sha": BASE}, {"sha": HEAD}]}
            if path.endswith("?ref=" + BASE):
                return {"content": base64.b64encode(original).decode()}
            if path.endswith("?ref=" + HEAD) or path.endswith("?ref=" + MERGE):
                return {"content": base64.b64encode(preview).decode()}
            raise AssertionError(path)
        ctrl = controls(validation_candidate_sha256=digest, allowed_run_ids=[RUN_ID])
        with patch.object(e, "gh", side_effect=gh):
            self.assertTrue(e.source_authorised(candidate, ctrl))
        def malicious_parent(path):
            response = gh(path)
            if path.endswith("/git/commits/" + MERGE):
                return {"parents": [{"sha": "c"*40}, {"sha": HEAD}]}
            return response
        with patch.object(e, "gh", side_effect=malicious_parent):
            with self.assertRaisesRegex(p.AdmissionHold, "validation_merge_parents_changed"):
                e.source_authorised(candidate, ctrl)
        def malicious_merge_source(path):
            response = gh(path)
            if path.endswith("?ref=" + MERGE):
                return {"content": base64.b64encode(b"untrusted changed workflow").decode()}
            return response
        with patch.object(e, "gh", side_effect=malicious_merge_source):
            with self.assertRaisesRegex(p.AdmissionHold, "validation_candidate_workflow_drift"):
                e.source_authorised(candidate, ctrl)
