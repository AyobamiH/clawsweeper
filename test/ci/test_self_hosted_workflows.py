"""No live GitHub, Docker, credentials or paid provider effects in these tests."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_policy as policy
import self_hosted_executor as executor

SHA = "a" * 40


def run(path=".github/workflows/codeql.yml", event="pull_request", branch="feature", actor="external"):
    return {"repository": {"full_name": "AyobamiH/clawsweeper"},
            "id": 123456789, "run_attempt": 1, "path": path, "head_sha": SHA,
            "head_branch": branch, "event": event, "actor": {"login": actor},
            "status": "in_progress",
            "pull_requests": [{"number": 123, "base": {"ref": "main", "sha": SHA},
                               "head": {"ref": branch, "sha": SHA}}]}


def job(role="security", slot="actions", name="Analyze (actions)", run_id=123456789):
    return {"id": 888, "run_id": run_id, "name": name, "status": "queued",
            "labels": ["self-hosted", "Linux", "X64", f"clawsweeper-ci-{role}-{run_id}-{slot}"]}


class PolicyTests(unittest.TestCase):
    def test_actions_and_javascript_codeql_preserved(self):
        for slot, name in (("actions", "Analyze (actions)"),
                           ("javascript-typescript", "Analyze (javascript-typescript)")):
            c = policy.classify(run(), job("security", slot, name))
            self.assertEqual(c.role, "security")
            self.assertEqual(c.sha, SHA)
            self.assertEqual(c.run_id, 123456789)
            self.assertTrue(policy.category_enabled(c, {"enabled": True,
                "repo": policy.REPOSITORY, "enabled_roles": ["security"],
                "allowed_branches": ["feature"], "max_jobs_per_cycle": 1}))

    def test_privileged_pr_target_uses_pinned_base_not_incoming_pr_branch(self):
        c = policy.classify(run(".github/workflows/clawsweeper-dispatch.yml",
                                "pull_request_target", branch="outside-contributor", actor="external"),
                            job("ops", "dispatch", "dispatch"))
        with self.assertRaisesRegex(policy.AdmissionHold, "trusted_base_not_pinned"):
            policy.category_enabled(c, {"enabled": True, "repo": policy.REPOSITORY,
                "enabled_roles": ["ops"], "operations_accepted": True, "allowed_branches": ["main"]})
        self.assertTrue(policy.category_enabled(c, {"enabled": True, "repo": policy.REPOSITORY,
            "enabled_roles": ["ops"], "operations_accepted": True, "trusted_main_sha": SHA,
            "allowed_branches": ["main"], "max_jobs_per_cycle": 1}))

    def test_ops_never_executes_untrusted_pull_request(self):
        with self.assertRaisesRegex(policy.AdmissionHold, "untrusted_privileged_pull_request"):
            policy.classify(run(".github/workflows/repair-containment-smoke.yml",
                                "pull_request", actor="external"),
                            job("ops", "provision", "Provision containment smoke compute"))

    def test_stacked_pr_target_never_gets_a_main_privileged_runner(self):
        scenario = run(".github/workflows/clawsweeper-dispatch.yml",
                       "pull_request_target", branch="feature")
        scenario["pull_requests"][0]["base"] = {"ref": "fix/issue68-local-orchestration-20261105", "sha": SHA}
        with self.assertRaisesRegex(policy.AdmissionHold, "target_base_not_main"):
            policy.classify(scenario, job("ops", "dispatch", "dispatch"))

    def test_codeql_image_requires_owner_pin_and_verifies_tag(self):
        c = policy.classify(run(), job())
        with self.assertRaisesRegex(policy.AdmissionHold, 'codeql_image_not_pinned'):
            executor.approved_job_image(c, {})
        image = 'sha256:' + 'f'*64
        with patch.object(executor, 'run_cli', return_value=image) as call:
            self.assertEqual(executor.approved_job_image(c, {'security_image_sha256': image}), image)
            self.assertIn('image', call.call_args.args[0])
        with patch.object(executor, 'run_cli', return_value='sha256:'+'e'*64):
            with self.assertRaisesRegex(policy.AdmissionHold, 'codeql_image_drift'):
                executor.approved_job_image(c, {'security_image_sha256': image})

    def test_containerised_e2e_kept_on_hold_without_inner_daemon(self):
        c = policy.classify(run(".github/workflows/automerge-e2e.yml", actor="AyobamiH"),
                            job("isolation", "e2e", "production automerge flow"))
        with self.assertRaisesRegex(policy.AdmissionHold, "nested_docker_isolation_not_proven"):
            policy.category_enabled(c, {"enabled": True, "repo": policy.REPOSITORY,
                "enabled_roles": ["isolation"], "allowed_branches": ["feature"]})

    def test_reject_untrusted_label_and_job(self):
        template = run()
        for change in ({"labels": ["self-hosted", "Linux", "X64", "clawsweeper-operations"]},
                       {"labels": ["self-hosted", "Linux", "X64", "clawsweeper-ci-security-333-actions"]},
                       {"name": "run arbitrary payload"}, {"status": "completed"}):
            with self.subTest(change=change), self.assertRaises(policy.AdmissionHold):
                policy.classify(template, {**job(), **change})
        with self.assertRaisesRegex(policy.AdmissionHold, "foreign_repository"):
            policy.classify({**template, "repository": {"full_name": "foreign/repo"}}, job())

    def test_default_deny_and_single_job_contract(self):
        c = policy.classify(run(), job())
        for value in ({}, {"enabled": False}, {"enabled": True},
                      {"enabled": True, "repo": policy.REPOSITORY, "enabled_roles": ["security"],
                       "allowed_branches": ["feature"], "max_jobs_per_cycle": 2}):
            with self.subTest(value=value), self.assertRaises(policy.AdmissionHold):
                policy.category_enabled(c, value)

    def test_source_authority_pins_main_and_workflow_bytes(self):
        c = policy.classify(run(".github/workflows/clawsweeper-dispatch.yml",
                                "pull_request_target", actor="external"),
                            job("ops", "dispatch", "dispatch"))
        import base64
        blob = b"name: pinned workflow\n"
        import hashlib
        digest = hashlib.sha256(blob).hexdigest()
        calls = []
        def fake_gh(path, *args):
            calls.append(path)
            if "git/ref/heads/main" in path:
                return {"object": {"sha": SHA}}
            return {"content": base64.b64encode(blob).decode()}
        with patch.object(executor, "gh", side_effect=fake_gh):
            self.assertTrue(executor.source_authorised(c, {
                "trusted_main_sha": SHA,
                "trusted_workflow_sha256": {c.workflow: digest},
            }))
            with self.assertRaisesRegex(policy.AdmissionHold, "trusted_workflow_drift"):
                executor.source_authorised(c, {"trusted_main_sha": SHA,
                    "trusted_workflow_sha256": {c.workflow: "0"*64}})
        self.assertTrue(any(x.startswith("repos/AyobamiH/clawsweeper/contents/") for x in calls))

    def test_discovery_readonly_bounded_and_no_duplicate(self):
        valid = run()
        valid["status"] = "queued"
        fake_calls=[]
        def gh(path, method="GET", body=None):
            fake_calls.append((path, method))
            if "runs?status=queued" in path:
                return {"workflow_runs": [valid]}
            if "runs?status=in_progress" in path:
                return {"workflow_runs": [valid]}
            if "jobs?" in path:
                return {"jobs": [job(), {**job(), "id": 889, "labels": ["ubuntu-latest"]}]}
            raise AssertionError(path)
        with patch.object(executor, "gh", side_effect=gh):
            discovered = executor.discover()
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].job_id, 888)
        self.assertEqual(sum("/jobs?" in x for x, _ in fake_calls), 1)
        self.assertTrue(all(method == "GET" for _, method in fake_calls))

    def test_receipt_is_owner_only_and_durable(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/"evidence"/"receipt.json"
            executor.atomic(path, {"state": "registration_uncertain"})
            self.assertEqual(json.loads(path.read_text())["state"], "registration_uncertain")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            executor.atomic(path, {"state": "terminal"})
            self.assertEqual(json.loads(path.read_text())["state"], "terminal")

    def test_bounded_live_acceptance_cannot_take_other_runs(self):
        c = policy.classify(run(), job())
        controls = {"enabled": True, "repo": policy.REPOSITORY,
                    "enabled_roles": ["security"], "allowed_branches": ["feature"],
                    "allowed_run_ids": [123456790], "max_jobs_per_cycle": 1}
        with self.assertRaisesRegex(policy.AdmissionHold, "run_id_not_authorised"):
            policy.category_enabled(c, controls)
        controls["allowed_run_ids"] = [123456789]
        self.assertTrue(policy.category_enabled(c, controls))

    def test_completed_ephemeral_runner_may_already_be_deregistered(self):
        with patch.object(executor, "gh", return_value={"total_count": 0, "runners": []}):
            self.assertTrue(executor.runner_absent_verified(232, "csw-ci-owned"))
        with patch.object(executor, "gh", return_value={"total_count": 1,
             "runners": [{"id": 232, "name": "csw-ci-owned"}]}):
            with self.assertRaisesRegex(RuntimeError, "runner_deregistration_unverified"):
                executor.runner_absent_verified(232, "csw-ci-owned")
        with patch.object(executor, "gh", return_value={"total_count": 3, "runners": []}):
            with self.assertRaisesRegex(RuntimeError, "runner_inventory_unbounded"):
                executor.runner_absent_verified(232, "csw-ci-owned")

    def test_disposable_worker_cleanup_waits_for_verified_removal(self):
        with patch.object(executor, "inspect_owned", side_effect=[{ "owned": True }, {"owned": True}, None]) as inspect, \
             patch.object(executor, "run_cli", return_value="") as stop, \
             patch.object(executor.time, "sleep"):
            executor.stop_owned("csw-ci-owned-worker", "csw-ci-owned")
            self.assertEqual(stop.call_count, 1)
            self.assertEqual(inspect.call_count, 3)
        with patch.object(executor, "inspect_owned", side_effect=[None]) as inspect, \
             patch.object(executor, "run_cli") as stop:
            executor.stop_owned("csw-ci-owned-worker", "csw-ci-owned")
            stop.assert_not_called()
            inspect.assert_called_once()

    def test_existing_attempt_never_registers_another_runner(self):
        c = policy.classify(run(), job())
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)/"receipts"
            target.mkdir(mode=0o700)
            (target/"run-123456789-job-888-attempt-1").mkdir()
            with patch.object(executor, "RECEIPTS", target), patch.object(executor, "gh") as remote:
                with self.assertRaisesRegex(policy.AdmissionHold, "existing_or_uncertain_runner_intent"):
                    executor.runner_job(c, {})
                remote.assert_not_called()


if __name__ == "__main__":
    unittest.main()
