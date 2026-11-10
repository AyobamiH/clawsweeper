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

    def test_privileged_manual_dispatch_is_owner_only_for_every_registered_slot(self):
        slots = [(slot, path, name) for (role, slot), (path, name) in policy.WORKFLOWS.items()
                 if role == "ops" and "workflow_dispatch" in policy.EVENTS[(role, slot)]]
        self.assertGreaterEqual(len(slots), 5)
        for slot, path, name in slots:
            with self.subTest(slot=slot, actor="AyobamiH"):
                result = policy.classify(
                    run(path, event="workflow_dispatch", branch="main", actor="AyobamiH"),
                    job("ops", slot, name))
                self.assertEqual(result.slot, slot)
            for actor in ("external", "github-actions[bot]", "", "ayobamih"):
                with self.subTest(slot=slot, actor=actor):
                    denial = ("untrusted_operations_source" if slot in ("provision", "cleanup")
                              else "untrusted_operations_dispatch_actor")
                    with self.assertRaisesRegex(policy.AdmissionHold, denial):
                        policy.classify(
                            run(path, event="workflow_dispatch", branch="main", actor=actor),
                            job("ops", slot, name))
            with self.subTest(slot=slot, actor="missing"):
                missing = run(path, event="workflow_dispatch", branch="main")
                missing["actor"] = {}
                denial = ("untrusted_operations_source" if slot in ("provision", "cleanup")
                          else "untrusted_operations_dispatch_actor")
                with self.assertRaisesRegex(policy.AdmissionHold, denial):
                    policy.classify(missing, job("ops", slot, name))

        c = policy.classify(run(".github/workflows/clawsweeper-dispatch.yml",
                                "pull_request_target", branch="outside-contributor", actor="external"),
                            job("ops", "dispatch", "dispatch"))
        with self.assertRaisesRegex(policy.AdmissionHold, "trusted_base_not_pinned"):
            policy.category_enabled(c, {"enabled": True, "repo": policy.REPOSITORY,
                "enabled_roles": ["ops"], "operations_accepted": True, "allowed_branches": ["main"]})
        self.assertTrue(policy.category_enabled(c, {"enabled": True, "repo": policy.REPOSITORY,
            "enabled_roles": ["ops"], "operations_accepted": True, "trusted_main_sha": SHA,
            "allowed_branches": ["main"], "max_jobs_per_cycle": 1}))

    def test_privileged_pr_target_requires_trusted_base_not_incoming_branch(self):
        # Recovered from the 6 Nov operational-admission worktree. An
        # external PR's head branch is NOT authority for the privileged job.
        c = policy.classify(
            run(".github/workflows/clawsweeper-dispatch.yml",
                "pull_request_target", branch="outside-contributor", actor="external"),
            job("ops", "dispatch", "dispatch"),
        )
        self.assertEqual(c.branch, "outside-contributor")
        self.assertEqual(c.trusted_base_sha, SHA)
        controls = {
            "enabled": True, "repo": policy.REPOSITORY,
            "enabled_roles": ["ops"], "operations_accepted": True,
            "allowed_branches": ["main"], "max_jobs_per_cycle": 1,
        }
        with self.assertRaisesRegex(policy.AdmissionHold, "trusted_base_not_pinned"):
            policy.category_enabled(c, controls)
        self.assertTrue(policy.category_enabled(
            c, {**controls, "trusted_main_sha": SHA}))
        with self.assertRaisesRegex(policy.AdmissionHold, "operations_not_proven"):
            policy.category_enabled(
                c, {**controls, "trusted_main_sha": SHA, "operations_accepted": False})

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
                    controls = {
                        "enabled": True, "repo": policy.REPOSITORY,
                        "enabled_roles": ["ops"], "operations_accepted": True,
                        "trusted_main_sha": SHA,
                        "max_jobs_per_cycle": 1,
                    }
                    if event in ("pull_request_review", "pull_request_review_comment"):
                        with self.assertRaisesRegex(
                            policy.AdmissionHold, "executed_pr_merge_workflow_unverifiable"
                        ):
                            policy.category_enabled(candidate, controls)
                    else:
                        self.assertTrue(policy.category_enabled(candidate, controls))
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
            if "/actions/variables/CLAWSWEEPER_TRUSTED_MAIN_SHA" in path:
                return {"value": SHA}
            return {"content": base64.b64encode(content).decode()}
        with patch.object(executor, "gh", side_effect=gh):
            self.assertTrue(executor.source_authorised(c, expected))
            with self.assertRaisesRegex(policy.AdmissionHold, "default_branch_source_drift"):
                executor.source_authorised(c.__class__(**{**vars(c), "sha": "b" * 40}), expected)
            with self.assertRaisesRegex(policy.AdmissionHold, "trusted_workflow_head_changed"):
                executor.source_authorised(c, {**expected, "trusted_main_sha": "b" * 40})

    def test_real_review_event_merge_source_must_be_attested_before_privilege(self):
        # GitHub run 41961710139 and its check suite expose a PR head SHA,
        # not the historical synthetic merge workflow that actually ran.
        # Even an owner-approved current main and matching PR-head bytes do
        # not justify credentialed runner registration.
        controls = {"enabled": True, "repo": policy.REPOSITORY,
                    "enabled_roles": ["ops"], "operations_accepted": True,
                    "trusted_main_sha": SHA, "max_jobs_per_cycle": 1}
        for event in ("pull_request_review", "pull_request_review_comment"):
            with self.subTest(event=event):
                info = run(".github/workflows/github-activity.yml", event,
                           branch="feature-pr", actor="external")
                info["head_sha"] = "b" * 40
                info["pull_requests"] = []
                candidate = policy.classify(info, job("ops", "notify", "notify"))
                with self.assertRaisesRegex(
                        policy.AdmissionHold, "executed_pr_merge_workflow_unverifiable"):
                    policy.category_enabled(candidate, controls)
                with patch.object(executor, "gh") as remote:
                    with self.assertRaisesRegex(
                            policy.AdmissionHold, "executed_pr_merge_workflow_unverifiable"):
                        executor.source_authorised(candidate, controls)
                    remote.assert_not_called()
        issue = run(".github/workflows/github-activity.yml", "issues",
                    branch="feature-pr", actor="external")
        with self.assertRaisesRegex(policy.AdmissionHold, "untrusted_default_branch_source"):
            policy.classify(issue, job("ops", "notify", "notify"))

    def test_notification_owner_pin_is_independent_of_controller_and_branch(self):
        import base64, hashlib
        source=b"trusted workflow bytes\n"
        digest=hashlib.sha256(source).hexdigest()
        c=policy.classify(run(".github/workflows/github-activity.yml", "pull_request_target",
                              branch="feature-pr", actor="external"),
                          job("ops", "notify", "notify"))
        controls={"trusted_main_sha":SHA,
                  "trusted_workflow_sha256": {c.workflow:digest}}
        def gh(path, approved=SHA):
            if path.endswith('/git/ref/heads/main'):
                return {"object":{"sha":SHA}}
            if '/actions/variables/CLAWSWEEPER_TRUSTED_MAIN_SHA' in path:
                return {"value":approved}
            if path.endswith('?ref='+SHA):
                return {"content":base64.b64encode(source).decode()}
            raise AssertionError(path)
        with patch.object(executor, "gh", side_effect=gh):
            self.assertTrue(executor.source_authorised(c, controls))
        with patch.object(executor, "gh", side_effect=lambda p:gh(p,'b'*40)):
            with self.assertRaisesRegex(policy.AdmissionHold, 'notification_checkout_pin_mismatch'):
                executor.source_authorised(c,controls)
        with patch.object(executor,"gh",side_effect=lambda p:
                          (_ for _ in ()).throw(RuntimeError('unavailable'))
                          if '/actions/variables/' in p else gh(p)):
            with self.assertRaisesRegex(policy.AdmissionHold, 'notification_checkout_pin_unverifiable'):
                executor.source_authorised(c,controls)

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
        with self.assertRaisesRegex(
                policy.AdmissionHold, "executed_pr_merge_workflow_unverifiable"):
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

    def test_privileged_owner_pr_cannot_bypass_historical_merge_attestation(self):
        # A valid owner, same-repository head, pinned run, exact base and
        # matching workflow files still cannot prove historical executed SHA.
        r = run(".github/workflows/repair-containment-smoke.yml", "pull_request",
                branch="owner-feature", actor="AyobamiH")
        r["repository"]["id"] = 17
        r["head_sha"] = "b" * 40
        r["pull_requests"][0]["head"] = {
            "ref": "owner-feature", "sha": "b" * 40, "repo": {"id": 17},
        }
        r["pull_requests"][0]["base"] = {
            "ref": "main", "sha": SHA, "repo": {"id": 17},
        }
        ctrl = {"enabled": True, "repo": policy.REPOSITORY,
                "enabled_roles": ["ops"], "operations_accepted": True,
                "trusted_main_sha": SHA, "max_jobs_per_cycle": 1,
                "allowed_run_ids": [123456789],
                "trusted_workflow_sha256": {
                    ".github/workflows/repair-containment-smoke.yml": "c" * 64,
                }}
        for slot, name in (("provision", "Provision containment smoke compute"),
                           ("cleanup", "Destroy containment smoke compute")):
            with self.subTest(slot=slot):
                candidate = policy.classify(r, job("ops", slot, name))
                self.assertEqual(candidate.trusted_base_sha, SHA)
                with self.assertRaisesRegex(
                        policy.AdmissionHold, "executed_pr_merge_workflow_unverifiable"):
                    policy.category_enabled(candidate, ctrl)
                with patch.object(executor, "gh") as remote:
                    with self.assertRaisesRegex(
                            policy.AdmissionHold, "executed_pr_merge_workflow_unverifiable"):
                        executor.source_authorised(candidate, ctrl)
                    remote.assert_not_called()
        for change in ({"ref": "stacked"}, {"sha": ""}, {"repo": {"id": 22}}):
            altered = {**r, "pull_requests": [{
                **r["pull_requests"][0],
                "base": {**r["pull_requests"][0]["base"], **change}
            }]}
            with self.assertRaisesRegex(
                    policy.AdmissionHold, "untrusted_privileged_pull_request_source"):
                policy.classify(altered, job("ops", "provision",
                                             "Provision containment smoke compute"))

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

    def test_rootless_e2e_requires_exact_owner_run_and_nested_image(self):
        info = run(".github/workflows/automerge-e2e.yml", actor="AyobamiH")
        info["pull_requests"][0]["base"]["sha"] = "b" * 40
        candidate = policy.classify(
            info, job("isolation", "e2e", "production automerge flow"))
        self.assertEqual((candidate.pr_number, candidate.trusted_base_sha),
                         (123, "b" * 40))
        valid = {
            "enabled": True, "repo": policy.REPOSITORY,
            "enabled_roles": ["isolation"], "operations_accepted": False,
            "allowed_run_ids": [candidate.run_id], "allowed_branches": [candidate.branch],
            "max_jobs_per_cycle": 1, "isolation_accepted": True,
            "isolation_head_sha": candidate.sha,
            "isolation_base_sha": candidate.trusted_base_sha,
            "isolation_pr_number": candidate.pr_number,
            "isolation_image_sha256": "sha256:" + "f" * 64,
            "isolation_workflow_sha256": "d" * 64,
            "isolation_harness_sha256": {
                name: "f" * 64 for name in policy.ISOLATION_HARNESS_FILES},
        }
        self.assertTrue(policy.category_enabled(candidate, valid))
        invalid = (
            ({"isolation_accepted": False}, "nested_docker_isolation_not_proven"),
            ({"enabled_roles": ["security", "isolation"]}, "isolation_mixed_authority"),
            ({"operations_accepted": True}, "isolation_mixed_authority"),
            ({"allowed_run_ids": [candidate.run_id, 123]}, "isolation_run_not_exclusive"),
            ({"isolation_head_sha": "c" * 40}, "isolation_head_not_pinned"),
            ({"isolation_base_sha": "c" * 40}, "isolation_pr_ancestry_not_pinned"),
            ({"isolation_pr_number": 124}, "isolation_pr_ancestry_not_pinned"),
            ({"isolation_image_sha256": "latest"}, "isolation_image_not_pinned"),
            ({"isolation_workflow_sha256": None}, "isolation_workflow_not_pinned"),
            ({"isolation_harness_sha256": None}, "isolation_harness_not_pinned"),
            ({"isolation_harness_sha256": {}}, "isolation_harness_not_pinned"),
            ({"allowed_branches": ["main"]}, "branch_not_authorised"),
        )
        for override, refusal in invalid:
            with self.subTest(override=override), self.assertRaisesRegex(
                policy.AdmissionHold, refusal
            ):
                policy.category_enabled(candidate, {**valid, **override})

    def test_rootless_e2e_rejects_foreign_pr_and_untrusted_actor(self):
        fixture = run(".github/workflows/automerge-e2e.yml", actor="external")
        j = job("isolation", "e2e", "production automerge flow")
        with self.assertRaisesRegex(policy.AdmissionHold, "untrusted_isolation_actor"):
            policy.classify(fixture, j)
        fixture["actor"]["login"] = "AyobamiH"
        for change in ("head_repo", "base_repo", "head_sha", "head_ref", "base_missing"):
            bad = json.loads(json.dumps(fixture))
            if change == "head_repo":
                bad["pull_requests"][0]["head"]["repo"]["id"] = 99
            elif change == "base_repo":
                bad["pull_requests"][0]["base"]["repo"]["id"] = 99
            elif change == "head_sha":
                bad["pull_requests"][0]["head"]["sha"] = "b" * 40
            elif change == "head_ref":
                bad["pull_requests"][0]["head"]["ref"] = "other"
            elif change == "base_missing":
                bad["pull_requests"] = []
            with self.subTest(change=change), self.assertRaisesRegex(
                policy.AdmissionHold, "isolation_pr_source_unverifiable"
            ):
                policy.classify(bad, j)
        main = run(".github/workflows/automerge-e2e.yml",
                   event="push", branch="main", actor="AyobamiH")
        current = policy.classify(main, j)
        with self.assertRaisesRegex(policy.AdmissionHold, "isolation_non_pr_unaccepted"):
            policy.category_enabled(current, {
                "enabled": True, "repo": policy.REPOSITORY,
                "enabled_roles": ["isolation"], "allowed_run_ids": [current.run_id],
                "allowed_branches": ["main"], "isolation_accepted": True,
                "isolation_head_sha": SHA, "isolation_image_sha256": "sha256:"+"f"*64,
                "isolation_workflow_sha256": "d"*64,
                "isolation_harness_sha256": {
                    name: "f"*64 for name in policy.ISOLATION_HARNESS_FILES},
                "max_jobs_per_cycle": 1,
            })

    def test_rootless_e2e_pins_actual_pr_merge_and_workflow_bytes(self):
        import base64
        import hashlib
        payload = b"name: reviewed automerge e2e\n"
        digest = hashlib.sha256(payload).hexdigest()
        info = run(".github/workflows/automerge-e2e.yml", actor="AyobamiH")
        info["pull_requests"][0]["base"]["sha"] = "b" * 40
        c = policy.classify(info, job("isolation", "e2e", "production automerge flow"))
        harness_paths = policy.ISOLATION_HARNESS_FILES
        harness = {name: ("reviewed:" + name + "\n").encode()
                   for name in harness_paths}
        state = {"head": SHA, "verified": True,
                 "base_ref_sha": "b" * 40, "head_ref_sha": SHA,
                 "parents": ["b" * 40, SHA], "workflow": payload,
                 "harness": harness.copy(), "merge_harness": {}}
        def response(url):
            if url.endswith("/pulls/123"):
                return {"state": "open",
                        "head": {"sha": state["head"], "ref": "feature",
                                 "repo": {"full_name": policy.REPOSITORY}},
                        "base": {"sha": "b" * 40, "ref": "main",
                                 "repo": {"full_name": policy.REPOSITORY}}}
            if url.endswith("/git/ref/heads/main"):
                return {"object": {"sha": state["base_ref_sha"]}}
            if url.endswith("/git/ref/heads/feature"):
                return {"object": {"sha": state["head_ref_sha"]}}
            if url.endswith("/commits/" + SHA):
                return {"sha": SHA, "commit": {"verification": {"verified": state["verified"]}}}
            if url.endswith("/git/ref/pull/123/merge"):
                return {"object": {"sha": "c" * 40}}
            if url.endswith("/git/commits/" + "c" * 40):
                return {"parents": [{"sha": p} for p in state["parents"]]}
            if "/contents/.github/workflows/automerge-e2e.yml?ref=" in url:
                return {"content": base64.b64encode(state["workflow"]).decode()}
            for name in harness_paths:
                if "/contents/" + name + "?ref=" in url:
                    blob = (state["merge_harness"].get(name, state["harness"][name])
                            if url.endswith("?ref=" + "c" * 40)
                            else state["harness"][name])
                    return {"content": base64.b64encode(blob).decode() + "\n",
                            "type": "file", "encoding": "base64"}
            raise AssertionError("unapproved GitHub lookup: " + url)
        source_controls = {
            "isolation_workflow_sha256": digest,
            "isolation_base_ref": "main",
            "isolation_harness_sha256": {
                name: hashlib.sha256(blob).hexdigest()
                for name, blob in harness.items()},
        }
        with patch.object(executor, "gh", side_effect=response):
            self.assertTrue(executor.source_authorised(c, source_controls))
            with self.assertRaisesRegex(policy.AdmissionHold,
                                        "isolation_base_ref_not_pinned"):
                executor.source_authorised(c, {
                    "isolation_workflow_sha256": digest,
                    "isolation_harness_sha256": source_controls["isolation_harness_sha256"],
                })
            for key, value, refusal in (
                ("head", "d" * 40, "isolation_pr_head_or_base_moved"),
                ("base_ref_sha", "d" * 40, "isolation_base_branch_drift"),
                ("head_ref_sha", "d" * 40, "isolation_head_branch_drift"),
                ("verified", False, "isolation_commit_signature_unverified"),
                ("parents", [SHA, "b" * 40], "isolation_merge_parents_changed"),
                ("workflow", b"modified workflow\n", "isolation_workflow_source_drift"),
            ):
                with self.subTest(key=key):
                    previous = state[key]
                    state[key] = value
                    try:
                        with self.assertRaisesRegex(policy.AdmissionHold, refusal):
                            executor.source_authorised(c, source_controls)
                    finally:
                        state[key] = previous
            with self.assertRaisesRegex(policy.AdmissionHold,
                                        "isolation_harness_not_pinned"):
                executor.source_authorised(
                    c, {key: value for key, value in source_controls.items()
                        if key != "isolation_harness_sha256"})
            for name in harness_paths:
                with self.subTest(file=name):
                    previous = state["harness"][name]
                    state["harness"][name] = b"attacker-controlled substitute\n"
                    try:
                        with self.assertRaisesRegex(
                                policy.AdmissionHold, "isolation_harness_source_drift"):
                            executor.source_authorised(c, source_controls)
                    finally:
                        state["harness"][name] = previous
            with self.assertRaisesRegex(policy.AdmissionHold,
                                        "isolation_workflow_not_pinned"):
                executor.source_authorised(c, {})
            for name in harness_paths:
                with self.subTest(merge_only=name):
                    state["merge_harness"][name] = b"tampered on synthetic merge\n"
                    try:
                        with self.assertRaisesRegex(
                                policy.AdmissionHold, "isolation_harness_source_drift"):
                            executor.source_authorised(c, source_controls)
                    finally:
                        del state["merge_harness"][name]
        with patch.object(executor, "gh", side_effect=RuntimeError("network")):
            with self.assertRaisesRegex(policy.AdmissionHold,
                                        "isolation_source_readback_unavailable"):
                executor.source_authorised(c, source_controls)

    def test_rootless_e2e_uses_only_pinned_image_and_full_duration(self):
        c = policy.classify(
            run(".github/workflows/automerge-e2e.yml", actor="AyobamiH"),
            job("isolation", "e2e", "production automerge flow"))
        with self.assertRaisesRegex(policy.AdmissionHold, "isolation_image_not_pinned"):
            executor.approved_job_image(c, {})
        image = "sha256:" + "e" * 64
        with patch.object(executor, "run_cli", return_value=image) as call:
            self.assertEqual(executor.approved_job_image(
                c, {"isolation_image_sha256": image}), image)
            self.assertIn(executor.ISOLATION_IMAGE_NAME, call.call_args.args[0])
        with patch.object(executor, "run_cli", return_value="sha256:"+"f"*64):
            with self.assertRaisesRegex(policy.AdmissionHold, "isolation_image_drift"):
                executor.approved_job_image(c, {"isolation_image_sha256": image})
        self.assertEqual(executor.runner_limits(c), (115*60, "4g"))
        self.assertEqual(executor.runner_limits(
            policy.classify(run(), job())), (42*60, "4g"))
        ops = policy.classify(
            run(".github/workflows/clawsweeper-dispatch.yml",
                event="issues", branch="main", actor="external"),
            job("ops", "dispatch", "dispatch"))
        self.assertEqual(executor.runner_limits(ops), (42*60, "2g"))

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
                                "issues", branch="main", actor="external"),
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
