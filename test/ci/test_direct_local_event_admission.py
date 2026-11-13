"""No-provider, fail-closed event-to-intent tests for the existing local fleet."""
import copy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_workflow as router
import direct_local_event_admission as events
from estate_policy import Hold


class SignedLocalEventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.head = router.git_head(ROOT)
        cls.policy = {
            "execution_hosts": {router.REPO: "web"},
            "repositories": {router.REPO: {
                "branch": "main", "enrolled_head": cls.head,
                "contract": router.sha256(ROOT / ".github/workflows/ci.yml"),
                "suites": {"linux-node24": {
                    "node": "24", "image": "sha256:" + "a" * 64,
                    "steps": [
                        {"command": "actionlint -shellcheck= -ignore 'unexpected key \"queue\" for \"concurrency\" section' .github/workflows/*.yml", "timeout": 600},
                        {"command": "pnpm install --frozen-lockfile", "timeout": 600},
                        {"command": "pnpm run check", "timeout": 1800},
                        {"command": "pnpm run test:workflow-sparse-checkout", "timeout": 600},
                    ],
                }},
            }},
        }
        cls.plan = router.compile_plan(ROOT, cls.policy, commit=cls.head, hostname="web")

    def setUp(self):
        self.secret = b"a" * 32
        self.push = {"repository": {"full_name": router.REPO},
                     "ref": "refs/heads/main", "after": self.head,
                     "deleted": False, "forced": False}

    def pr(self):
        return {"repository": {"full_name": router.REPO}, "action": "synchronize",
                "pull_request": {
                    "number": 101, "state": "open", "draft": False,
                    "user": {"login": "AyobamiH"},
                    "head": {"sha": self.head, "repo": {"full_name": router.REPO}},
                    "base": {"ref": "main", "repo": {"full_name": router.REPO}},
                }}

    def route(self, *, event="push", payload=None, body=None, signature=None,
              secret=None, ref_sha=None, plan=None, delivery=None):
        body = (json.dumps(self.push if payload is None else payload).encode()
                if body is None else body)
        secret = self.secret if secret is None else secret
        signature = (signature if signature is not None
                     else "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest())
        return events.verified_ordinary_intents(
            self.plan if plan is None else plan, body=body, event_name=event,
            signature=signature,
            delivery_id=delivery or "01234567-89ab-cdef-0123-456789abcdef",
            secret=secret, fresh_ref_sha=ref_sha or self.head)

    def test_exact_main_push_routes_check_only_without_execution(self):
        result = self.route()
        self.assertEqual([x["job"] for x in result["intents"]],
                         [".github/workflows/ci.yml#check"])
        self.assertFalse(result["queue_admitted"])
        self.assertFalse(result["job_executed"])
        self.assertFalse(result["github_status_published"])

    def test_owner_pr_routes_check_and_sparse(self):
        result = self.route(event="pull_request", payload=self.pr())
        self.assertEqual(result["source_ref"], "pr/101")
        self.assertEqual({x["job"] for x in result["intents"]}, set(router.ORDINARY))

    def test_repeated_delivery_has_stable_identity_but_no_effect(self):
        a, b = self.route(), self.route()
        self.assertEqual(a["intent_identity_sha256"], b["intent_identity_sha256"])
        self.assertTrue(a["existing_fleet_delivery_claim_required"])

    def test_invalid_signature_and_malformed_delivery_are_held(self):
        for kwargs in ({"signature": "sha256=" + "0" * 64},
                       {"delivery": "bad"}, {"delivery": "-" * 36},
                       {"delivery": "a" * 36}, {"secret": b"short"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Hold):
                self.route(**kwargs)

    def test_duplicate_json_keys_are_held_even_when_signed(self):
        body = ('{"repository":{"full_name":"%s"},"ref":"refs/heads/main",'
                '"ref":"refs/heads/evil","after":"%s","deleted":false,'
                '"forced":false}' % (router.REPO, self.head)).encode()
        with self.assertRaises(Hold):
            self.route(body=body)

    def test_forced_foreign_or_stale_main_is_held(self):
        for k, v in (("forced", True), ("ref", "refs/heads/develop"),
                     ("after", "b" * 40)):
            payload = copy.deepcopy(self.push)
            payload[k] = v
            with self.subTest(key=k), self.assertRaises(Hold):
                self.route(payload=payload)
        with self.assertRaises(Hold):
            self.route(ref_sha="b" * 40)

    def test_pr_fork_draft_other_actor_base_or_head_is_held(self):
        for path, value in (
            (("pull_request", "draft"), True),
            (("pull_request", "user", "login"), "intruder"),
            (("pull_request", "head", "repo", "full_name"), "intruder/repo"),
            (("pull_request", "base", "ref"), "develop"),
            (("pull_request", "head", "sha"), "b" * 40),
            (("action",), "closed"),
        ):
            payload = self.pr()
            target = payload
            for k in path[:-1]:
                target = target[k]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(Hold):
                self.route(event="pull_request", payload=payload)

    def test_step_swapping_and_duplicate_job_identity_are_held(self):
        plan = copy.deepcopy(self.plan)
        check = next(x for x in plan["jobs"]
                     if x["key"] == ".github/workflows/ci.yml#check")
        check["required_step"] = "pnpm run test:workflow-sparse-checkout"
        with self.assertRaises(Hold):
            self.route(plan=plan)
        plan = copy.deepcopy(self.plan)
        check = next(x for x in plan["jobs"]
                     if x["key"] == ".github/workflows/ci.yml#check")
        plan["jobs"][0] = copy.deepcopy(check)
        with self.assertRaises(Hold):
            self.route(plan=plan)

    def test_workflow_dispatch_foreign_repo_or_oversize_is_held(self):
        with self.assertRaises(Hold):
            self.route(event="workflow_dispatch")
        p = copy.deepcopy(self.push)
        p["repository"]["full_name"] = "attacker/repo"
        with self.assertRaises(Hold):
            self.route(payload=p)
        with self.assertRaises(Hold):
            self.route(body=b"x" * 65537)

    def test_unpinned_ordinary_job_or_untrusted_plan_is_held(self):
        plan = copy.deepcopy(self.plan)
        next(x for x in plan["jobs"]
             if x["key"] == ".github/workflows/ci.yml#check")["route"] = "held"
        with self.assertRaises(Hold):
            self.route(plan=plan)
        plan = copy.deepcopy(self.plan)
        plan["source_verified"] = False
        with self.assertRaises(Hold):
            self.route(plan=plan)


if __name__ == "__main__":
    unittest.main()
