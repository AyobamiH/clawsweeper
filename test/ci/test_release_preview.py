"""No network, credentials, Docker or provider effects: exact release-preview admission tests."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
sys.path.insert(0, str(Path(__file__).parent))
import self_hosted_executor as executor
import self_hosted_policy as policy
from test_self_hosted_workflows import run, job, SHA

WORKFLOW = ".github/workflows/repair-containment-smoke.yml"
BRANCH = "release-preview/proven"
HEAD = "b" * 40
TREE = "c" * 40
TRUSTED_WORKFLOW = b"name: bounded release preview\n"
DIGEST = hashlib.sha256(TRUSTED_WORKFLOW).hexdigest()


def candidate(slot="provision", event="workflow_dispatch", actor="AyobamiH", branch=BRANCH):
    info = run(WORKFLOW, event, branch=branch, actor=actor)
    info["head_sha"] = HEAD
    name = {
        "provision": "Provision containment smoke compute",
        "cleanup": "Destroy containment smoke compute",
    }[slot]
    return policy.classify(info, job("ops", slot, name))


def controls(**updates):
    result = {
        "enabled": True,
        "repo": policy.REPOSITORY,
        "enabled_roles": ["ops"],
        "operations_accepted": False,
        "trusted_main_sha": SHA,
        "allowed_run_ids": [123456789],
        "max_jobs_per_cycle": 1,
        "release_preview": {
            "accepted": True,
            "branch": BRANCH,
            "head_sha": HEAD,
            "tree_sha": TREE,
            "workflow_sha256": DIGEST,
        },
    }
    return {**result, **updates}


def fake_gh(path):
    if path.endswith("/git/ref/heads/main"):
        return {"object": {"sha": SHA}}
    if path.endswith("/git/ref/heads/" + BRANCH):
        return {"object": {"sha": HEAD}}
    if path.endswith("/commits/" + HEAD):
        return {"sha": HEAD, "commit": {
            "verification": {"verified": True},
            "tree": {"sha": TREE},
        }}
    if path.endswith("/contents/" + WORKFLOW + "?ref=" + HEAD):
        return {"content": base64.b64encode(TRUSTED_WORKFLOW).decode()}
    raise AssertionError("unexpected GitHub lookup: " + path)


class ReleasePreview(unittest.TestCase):
    def test_only_owner_dispatch_provision_and_cleanup_admit_exact_preview(self):
        for slot in ("provision", "cleanup"):
            with self.subTest(slot=slot):
                c = candidate(slot=slot)
                self.assertTrue(policy.category_enabled(c, controls()))
                with patch.object(executor, "gh", side_effect=fake_gh) as mock:
                    self.assertTrue(executor.source_authorised(c, controls()))
                paths = [args.args[0] for args in mock.call_args_list]
                self.assertEqual(len(paths), 4)
                self.assertIn("repos/AyobamiH/clawsweeper/commits/" + HEAD, paths)
                self.assertIn("repos/AyobamiH/clawsweeper/git/ref/heads/" + BRANCH, paths)

    def test_preview_never_grants_event_dispatch_or_untrusted_actor(self):
        with self.assertRaisesRegex(policy.AdmissionHold, "untrusted_operations_source"):
            candidate(actor="external")
        with self.assertRaisesRegex(policy.AdmissionHold, "untrusted_operations_source"):
            candidate(event="push")
        c = candidate()
        for scenario in ({"enabled": False}, {"enabled_roles": ["security"]},
                         {"allowed_run_ids": []}, {"allowed_run_ids": [123456789, 9]},
                         {"operations_accepted": True}, {"max_jobs_per_cycle": 2}):
            with self.subTest(scenario=scenario), self.assertRaises(policy.AdmissionHold):
                policy.category_enabled(c, {**controls(), **scenario})
        other = policy.classify(
            run(".github/workflows/clawsweeper-dispatch.yml",
                "issues", branch="main", actor="external"),
            job("ops", "dispatch", "dispatch"))
        with self.assertRaisesRegex(policy.AdmissionHold, "operations_not_proven"):
            policy.category_enabled(other, controls())

    def test_preview_scope_must_be_complete_and_exact(self):
        c = candidate()
        good = controls()
        for scope in (
            {"accepted": False}, {"branch": "other"},
            {"head_sha": "d" * 40}, {"tree_sha": "bad"},
            {"workflow_sha256": "bad"}, {"branch": "../../main"},
        ):
            with self.subTest(scope=scope), self.assertRaises(policy.AdmissionHold):
                policy.category_enabled(c, {**good, "release_preview": {
                    **good["release_preview"], **scope}})
        with self.assertRaisesRegex(policy.AdmissionHold, "release_preview_not_accepted"):
            policy.category_enabled(c, {**good, "release_preview": None})
        for missing in ("accepted", "branch", "head_sha", "tree_sha", "workflow_sha256"):
            with self.subTest(missing=missing):
                incomplete = dict(good["release_preview"])
                del incomplete[missing]
                with self.assertRaises(policy.AdmissionHold):
                    policy.category_enabled(c, {**good, "release_preview": incomplete})

    def test_live_source_requires_exact_signed_tree_workflow_and_main(self):
        c = candidate()
        accepted = controls()
        with patch.object(executor, "gh", side_effect=fake_gh):
            self.assertTrue(executor.source_authorised(c, accepted))
            with self.assertRaisesRegex(policy.AdmissionHold, "release_preview_main_changed"):
                executor.source_authorised(c, controls(trusted_main_sha="d" * 40))
        updates = [
            ("/git/ref/heads/" + BRANCH, {"object": {"sha": "d" * 40}},
             "release_preview_branch_moved"),
            ("/commits/" + HEAD,
             {"sha": HEAD, "commit": {"verification": {"verified": False}, "tree": {"sha": TREE}}},
             "release_preview_commit_unverified"),
            ("/commits/" + HEAD,
             {"sha": HEAD, "commit": {"verification": {"verified": True},
                                    "tree": {"sha": "d" * 40}}},
             "release_preview_commit_unverified"),
            ("/contents/" + WORKFLOW + "?ref=" + HEAD,
             {"content": base64.b64encode(b"name: injected\n").decode()},
             "release_preview_workflow_mismatch"),
        ]
        for match, value, reason in updates:
            with self.subTest(reason=reason):
                def tampered(path):
                    return value if path.endswith(match) else fake_gh(path)
                with patch.object(executor, "gh", side_effect=tampered):
                    with self.assertRaisesRegex(policy.AdmissionHold, reason):
                        executor.source_authorised(c, accepted)
        with patch.object(executor, "gh", side_effect=RuntimeError("network")):
            with self.assertRaises(RuntimeError):
                executor.source_authorised(c, accepted)


if __name__ == "__main__":
    unittest.main()
