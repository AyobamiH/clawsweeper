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
    return {"repository": {"full_name": "AyobamiH/clawsweeper", "id": 42},
            "id": 123456789, "run_attempt": 1, "path": path, "head_sha": SHA,
            "head_branch": branch, "event": event, "actor": {"login": actor},
            "status": "in_progress",
            "pull_requests": [{"number": 123, "base": {"ref": "main", "sha": SHA, "repo": {"id": 42}},
                               "head": {"ref": branch, "sha": SHA, "repo": {"id": 42}}}]}


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

    def test_all_existing_operations_events_survive_default_branch_routing(self):
        event_cases = {
            "dispatch": (".github/workflows/clawsweeper-dispatch.yml", "dispatch",
                         ("issues", "issue_comment", "pull_request_target")),
            "notify": (".github/workflows/github-activity.yml", "notify",
                       ("repository_dispatch", "issues", "issue_comment", "pull_request_target",
                        "pull_request_review", "pull_request_review_comment", "workflow_run")),
        }
        for slot, (path, name, events) in event_cases.items():
            for event in events:
                with self.subTest(slot=slot, event=event):
                    info = run(path, event, branch="main" if event != "pull_request_target" else "external-branch", actor="external")
                    candidate = policy.classify(info, job("ops", slot, name))
                    self.assertEqual(candidate.role, "ops")
                    self.assertEqual(candidate.event, event)
                    self.assertTrue(policy.category_enabled(candidate, {
                        "enabled": True, "repo": policy.REPOSITORY,
                        "enabled_roles": ["ops"], "operations_accepted": True,
                        "trusted_main_sha": SHA,
                        "max_jobs_per_cycle": 1,
                    }))
        for slot, (path, name, _) in event_cases.items():
            info = run(path, "workflow_dispatch", branch="main", actor="AyobamiH")
            with self.subTest(slot=slot), self.assertRaisesRegex(policy.AdmissionHold, "unapproved_event"):
                policy.classify(info, job("ops", slot, name))

    def test_event_operations_reject_unpinned_or_stale_main_source(self):
        c = policy.classify(run(".github/workflows/github-activity.yml", "issues", branch="main", actor="external"),
                            job("ops", "notify", "notify"))
        import base64, hashlib
        content = b"name: immutable tested workflow\n"
        digest = hashlib.sha256(content).hexdigest()
        expected = {"trusted_main_sha": SHA, "trusted_workflow_sha256": {c.workflow: digest}}
        def gh(path, *args):
            if "git/ref/heads/main" in path:
                return {"object": {"sha": SHA}}
            return {"content": base64.b64encode(content).decode()}
        with patch.object(executor, "gh", side_effect=gh):
            self.assertTrue(executor.source_authorised(c, expected))
            with self.assertRaisesRegex(policy.AdmissionHold, "default_branch_source_drift"):
                executor.source_authorised(c.__class__(**{**vars(c), "sha": "b" * 40}), expected)
            with self.assertRaisesRegex(policy.AdmissionHold, "trusted_workflow_head_changed"):
                executor.source_authorised(c, {**expected, "trusted_main_sha": "b" * 40})

    def test_real_review_event_branch_requires_same_workflow_bytes_at_pr_sha(self):
        # Real GitHub Actions runs 41961710139 and 38621294582 have feature
        # head branches and no pull_requests list, unlike issues events.
        import base64, hashlib
        trusted = b"name: exact pinned notify workflow\\n"
        attacker = b"name: changed untrusted workflow\\n"
        digest = hashlib.sha256(trusted).hexdigest()
        controls = {"enabled": True, "repo": policy.REPOSITORY,
                    "enabled_roles": ["ops"], "operations_accepted": True,
                    "trusted_main_sha": SHA, "max_jobs_per_cycle": 1,
                    "trusted_workflow_sha256":
                        {".github/workflows/github-activity.yml": digest}}
        for event in ("pull_request_review", "pull_request_review_comment"):
            with self.subTest(event=event):
                info = run(".github/workflows/github-activity.yml", event,
                           branch="feature-pr", actor="external")
                info["head_sha"] = "b" * 40
                info["pull_requests"] = []
                candidate = policy.classify(info, job("ops", "notify", "notify"))
                self.assertTrue(policy.category_enabled(candidate, controls))
                def gh(path, *args):
                    if "/git/ref/heads/main" in path:
                        return {"object": {"sha": SHA}}
                    if path.endswith("?ref=" + SHA):
                        return {"content": base64.b64encode(trusted).decode()}
                    if path.endswith("?ref=" + "b" * 40):
                        return {"content": base64.b64encode(trusted).decode()}
                    raise AssertionError(path)
                with patch.object(executor, "gh", side_effect=gh):
                    self.assertTrue(executor.source_authorised(candidate, controls))
                def tampered(path, *args):
                    reply = gh(path, *args)
                    if path.endswith("?ref=" + "b" * 40):
                        reply = {"content": base64.b64encode(attacker).decode()}
                    return reply
                with patch.object(executor, "gh", side_effect=tampered):
                    with self.assertRaisesRegex(policy.AdmissionHold,
                                               "review_workflow_source_drift"):
                        executor.source_authorised(candidate, controls)
                with patch.object(executor, "gh", side_effect=lambda path, *args:
                                  (_ for _ in ()).throw(RuntimeError("not found"))
                                  if path.endswith("?ref=" + "b" * 40)
                                  else gh(path, *args)):
                    with self.assertRaisesRegex(policy.AdmissionHold,
                                               "review_workflow_source_unverifiable"):
                        executor.source_authorised(candidate, controls)
        # An ordinary issue callback with a PR revision stays forbidden.
        issue = run(".github/workflows/github-activity.yml", "issues",
                    branch="feature-pr", actor="external")
        with self.assertRaisesRegex(policy.AdmissionHold, "untrusted_default_branch_source"):
            policy.classify(issue, job("ops", "notify", "notify"))

    def test_ops_never_executes_untrusted_pull_request(self):
        with self.assertRaisesRegex(policy.AdmissionHold, "untrusted_privileged_pull_request"):
            policy.classify(run(".github/workflows/repair-containment-smoke.yml",
                                "pull_request", actor="external"),
                            job("ops", "provision", "Provision containment smoke compute"))

    def test_privileged_pull_request_head_repository_is_not_implicit_authority(self):
        workflow = ".github/workflows/repair-containment-smoke.yml"
        base = run(workflow, "pull_request", branch="owner-pr", actor="AyobamiH")
        candidate = policy.classify(base, job("ops", "provision", "Provision containment smoke compute"))
        self.assertEqual(candidate.branch, "owner-pr")
        # Even a trusted owner PR cannot receive privileged runner secrets
        # until there is separately approved, pinned execution authority.
        with self.assertRaisesRegex(policy.AdmissionHold, "privileged_pr_run_not_pinned"):
            policy.category_enabled(candidate, {"enabled": True, "repo": policy.REPOSITORY,
                "enabled_roles": ["ops"], "operations_accepted": True,
                "trusted_main_sha": SHA, "max_jobs_per_cycle": 1})
        for case in ("fork", "missing_head_repo", "missing_repository_id", "foreign_base"):
            scenario = json.loads(json.dumps(base))
            if case == "fork":
                scenario["pull_requests"][0]["head"]["repo"]["id"] = 99
            elif case == "missing_head_repo":
                del scenario["pull_requests"][0]["head"]["repo"]
            elif case == "missing_repository_id":
                del scenario["repository"]["id"]
            else:
                scenario["pull_requests"][0]["base"]["repo"]["id"] = 99
            with self.subTest(case=case), self.assertRaisesRegex(
                    policy.AdmissionHold, "privileged_pull_request_source"):
                policy.classify(scenario, job("ops", "provision", "Provision containment smoke compute"))

    def test_privileged_owner_pr_pins_base_and_exact_workflow_at_head(self):
        import base64, hashlib
        good=b"name: pinned trusted workflow\n"
        evil=b"name: changed PR instructions\n"
        digest=hashlib.sha256(good).hexdigest()
        r=run(".github/workflows/repair-containment-smoke.yml", "pull_request",
              branch="owner-feature", actor="AyobamiH")
        r["repository"]["id"]=17
        r["head_sha"]="b"*40
        r["pull_requests"][0]["head"]={"ref":"owner-feature","sha":"b"*40,"repo":{"id":17}}
        r["pull_requests"][0]["base"]={"ref":"main","sha":SHA,"repo":{"id":17}}
        ctrl={"enabled":True,"repo":policy.REPOSITORY,"enabled_roles":["ops"],
              "operations_accepted":True,"trusted_main_sha":SHA,"max_jobs_per_cycle":1,
              "allowed_run_ids":[123456789],
              "trusted_workflow_sha256":{".github/workflows/repair-containment-smoke.yml":digest}}
        def gh(path, changed=False):
            if path.endswith("/git/ref/heads/main"):return {"object":{"sha":SHA}}
            if path.endswith("?ref="+SHA):return {"content":base64.b64encode(good).decode()}
            if path.endswith("?ref="+"b"*40):return {"content":base64.b64encode(evil if changed else good).decode()}
            raise AssertionError(path)
        for slot,name in (("provision","Provision containment smoke compute"),
                          ("cleanup","Destroy containment smoke compute")):
            with self.subTest(slot=slot):
                c=policy.classify(r,job("ops",slot,name))
                self.assertEqual(c.trusted_base_sha,SHA)
                self.assertTrue(policy.category_enabled(c,ctrl))
                with patch.object(executor,"gh",side_effect=gh):
                    self.assertTrue(executor.source_authorised(c,ctrl))
                with patch.object(executor,"gh",side_effect=lambda p:gh(p,True)):
                    with self.assertRaisesRegex(policy.AdmissionHold,"privileged_pr_workflow_source_drift"):
                        executor.source_authorised(c,ctrl)
                with patch.object(executor,"gh",side_effect=lambda p:
                                  (_ for _ in ()).throw(RuntimeError("missing"))
                                  if p.endswith("?ref="+"b"*40) else gh(p)):
                    with self.assertRaisesRegex(policy.AdmissionHold,"privileged_pr_workflow_source_unverifiable"):
                        executor.source_authorised(c,ctrl)
                with patch.object(executor,"gh",side_effect=lambda p:
                                  {"object":{"sha":"c"*40}}
                                  if p.endswith("/git/ref/heads/main") else gh(p)):
                    with self.assertRaisesRegex(policy.AdmissionHold,"target_base_sha_changed"):
                        executor.source_authorised(c,ctrl)
                with self.assertRaisesRegex(policy.AdmissionHold,"trusted_base_not_pinned"):
                    policy.category_enabled(c,{**ctrl,"trusted_main_sha":""})
        for changed in ({"ref":"stacked"},{"sha":""},{"repo":{"id":22}}):
            bad={**r,"pull_requests":[{**r["pull_requests"][0],
                 "base":{**r["pull_requests"][0]["base"],**changed}}]}
            with self.assertRaisesRegex(policy.AdmissionHold,"untrusted_privileged_pull_request_source"):
                policy.classify(bad,job("ops","provision","Provision containment smoke compute"))

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
            if "runs?status=pending" in path:
                return {"workflow_runs": []}
            if "jobs?" in path:
                return {"jobs": [job(), {**job(), "id": 889, "labels": ["ubuntu-latest"]}]}
            raise AssertionError(path)
        with patch.object(executor, "gh", side_effect=gh):
            discovered = executor.discover()
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].job_id, 888)
        self.assertEqual(sum("/jobs?" in x for x, _ in fake_calls), 1)
        self.assertTrue(all(method == "GET" for _, method in fake_calls))

    def test_pending_workflow_run_admits_only_queued_exact_jit_job(self):
        # Live GitHub may report a waiting self-hosted run as pending while its
        # JIT-labelled job is queued; omitting pending strands genuine work.
        waiting = run()
        waiting["status"] = "pending"
        requests = []
        def gh(path, method="GET", body=None):
            requests.append((path, method))
            if "runs?status=pending" in path:
                return {"workflow_runs": [waiting]}
            if "runs?status=queued" in path or "runs?status=in_progress" in path:
                return {"workflow_runs": []}
            if "jobs?" in path:
                return {"jobs": [job(), {**job(), "id": 889, "status": "completed"}]}
            raise AssertionError(path)
        with patch.object(executor, "gh", side_effect=gh):
            result = executor.discover()
        self.assertEqual([(c.run_id, c.job_id, c.sha) for c in result],
                         [(123456789, 888, SHA)])
        self.assertEqual(sum("/jobs?" in path for path, _ in requests), 1)
        self.assertTrue(all(method == "GET" for _, method in requests))
        self.assertTrue(any("runs?status=pending" in path for path, _ in requests))

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

    def test_foreign_container_label_fails_immediately_without_stopping_it(self):
        with patch.object(executor, "inspect_owned", side_effect=RuntimeError("container_ownership_mismatch")) as inspect, \
             patch.object(executor, "run_cli") as stop, \
             patch.object(executor.time, "sleep") as wait:
            with self.assertRaisesRegex(RuntimeError, "container_ownership_mismatch"):
                executor.stop_owned("csw-ci-owned-worker", "different-owner")
            inspect.assert_called_once()
            stop.assert_not_called()
            wait.assert_not_called()

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
