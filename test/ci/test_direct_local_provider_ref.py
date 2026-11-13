"""No-provider readback tests; simulated GET is NOT live provider acceptance."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_provider_ref as refs
import test_direct_local_fleet_claim as existing_fixture
from estate_policy import Hold


class FreshProviderReadbackTests(unittest.TestCase):
    def setUp(self):
        # Reuse the exact existing fleet WAL fixture, never create a second
        # queue implementation or touch the owner-installed fleet.
        self.fixture = existing_fixture.ExistingFleetAdmissionTests("test_exact_main_push_durable_queue_then_idempotent_redelivery")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.calls = []
        self.secret = self.fixture.secret
        self.head = self.fixture.head
        self.payload = copy.deepcopy(self.fixture.payload)

    def fetch(self, path):
        self.calls.append(path)
        if path == refs.MAIN_GET:
            return {"ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": self.head}}
        if path == "repos/AyobamiH/clawsweeper/pulls/101":
            return copy.deepcopy(self.pr_payload()["pull_request"])
        self.fail("unexpected_provider_get")

    def signed(self, payload=None):
        raw = json.dumps(payload or self.payload).encode()
        return raw, "sha256=" + hmac.new(self.secret, raw, hashlib.sha256).hexdigest()

    def claim(self, payload=None, *, event="push", fetch=None, delivery=None):
        body, signature = self.signed(payload)
        return refs.claim_with_fresh_provider_readback(
            checkout=ROOT, fleet_root=self.fixture.base, body=body,
            event_name=event, signature=signature, secret=self.secret,
            delivery_id=delivery or "01234567-89ab-cdef-0123-456789abcdef",
            provider_get=fetch or self.fetch,
        )

    def pr_payload(self):
        return {
            "repository": {"full_name": refs.REPO},
            "action": "synchronize",
            "pull_request": {
                "number": 101, "state": "open", "draft": False,
                "user": {"login": "AyobamiH"},
                "head": {"sha": self.head, "repo": {"full_name": refs.REPO}},
                "base": {"ref": "main", "repo": {"full_name": refs.REPO}},
            },
        }

    def test_exact_main_get_to_existing_wal_once(self):
        first = self.claim()
        repeat = self.claim()
        self.assertEqual(self.calls, [refs.MAIN_GET, refs.MAIN_GET])
        self.assertTrue(first["fresh_provider_source_verified"])
        self.assertFalse(first["provider_ci_execution"])
        self.assertEqual(first["admission"], "queued")
        self.assertEqual(repeat["admission"], "already_admitted")
        self.assertEqual(self.fixture.rows()[0][-1], "queued")
        self.assertEqual(len(self.fixture.rows()), 1)

    def test_stale_main_must_hold_before_queue(self):
        with self.assertRaisesRegex(Hold, "fresh_main_ref_moved"):
            self.claim(fetch=lambda _path: {"ref": "refs/heads/main",
                                            "object": {"type": "commit", "sha": "0" * 40}})
        self.assertEqual(self.fixture.rows(), [])

    def test_tag_is_not_main_commit(self):
        with self.assertRaisesRegex(Hold, "fresh_main_ref_moved"):
            self.claim(fetch=lambda _path: {"ref": "refs/heads/main",
                                            "object": {"type": "tag", "sha": self.head}})
        self.assertEqual(self.fixture.rows(), [])

    def test_bad_signature_never_gets_provider_data(self):
        body, sig = self.signed()
        with self.assertRaisesRegex(Hold, "bad_webhook_hmac"):
            refs.verified_fresh_source_sha(
                body=body, event_name="push", signature="sha256="+"0"*64,
                delivery_id="01234567-89ab-cdef-0123-456789abcdef",
                secret=self.secret, provider_get=self.fetch)
        self.assertEqual(self.calls, [])

    def test_duplicate_keys_refused_before_api(self):
        body = ('{"repository":{"full_name":"AyobamiH/clawsweeper"},'
                '"after":"'+self.head+'","after":"'+self.head+'"}').encode()
        sig = "sha256=" + hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(Hold, "invalid_webhook_json_before_provider_get"):
            refs.verified_fresh_source_sha(
                body=body, event_name="push", signature=sig,
                delivery_id="01234567-89ab-cdef-0123-456789abcdef",
                secret=self.secret, provider_get=self.fetch)
        self.assertEqual(self.calls, [])

    def test_foreign_repository_no_provider_get(self):
        data = {**self.payload, "repository": {"full_name": "attacker/clone"}}
        with self.assertRaisesRegex(Hold, "foreign_repository"):
            self.claim(data)
        self.assertEqual(self.calls, [])

    def test_exact_owner_pr_get_to_existing_wal(self):
        result = self.claim(self.pr_payload(), event="pull_request")
        self.assertEqual(result["provider_get_kind"], "pr")
        self.assertEqual(self.calls, ["repos/AyobamiH/clawsweeper/pulls/101"])
        self.assertEqual(len(result["job_intents"]), 2)
        self.assertEqual(result["admission"], "queued")
        self.assertEqual(len(self.fixture.rows()), 1)

    def test_pr_draft_changed_since_signed_event_is_hold(self):
        def changed(_path):
            data = self.pr_payload()["pull_request"]
            data["draft"] = True
            return data
        with self.assertRaisesRegex(Hold, "fresh_pr_head_or_trust_metadata_moved"):
            self.claim(self.pr_payload(), event="pull_request", fetch=changed)
        self.assertEqual(self.fixture.rows(), [])

    def test_pr_new_head_since_signed_event_is_hold(self):
        def changed(_path):
            data = self.pr_payload()["pull_request"]
            data["head"]["sha"] = "a" * 40
            return data
        with self.assertRaisesRegex(Hold, "fresh_pr_head_or_trust_metadata_moved"):
            self.claim(self.pr_payload(), event="pull_request", fetch=changed)
        self.assertEqual(self.fixture.rows(), [])

    def test_pr_actor_changed_since_event_is_hold(self):
        def changed(_path):
            data = self.pr_payload()["pull_request"]
            data["user"]["login"] = "attacker"
            return data
        with self.assertRaisesRegex(Hold, "fresh_pr_head_or_trust_metadata_moved"):
            self.claim(self.pr_payload(), event="pull_request", fetch=changed)
        self.assertEqual(self.fixture.rows(), [])

    def test_unsupported_event_fails_without_get(self):
        with self.assertRaisesRegex(Hold, "no_provider_get_for_unreviewed_event"):
            self.claim(event="workflow_dispatch")
        self.assertEqual(self.calls, [])

    def test_unavailable_provider_get_fails_closed(self):
        def offline(_path):
            raise Hold("fresh_github_get_unavailable")
        with self.assertRaisesRegex(Hold, "fresh_github_get_unavailable"):
            self.claim(fetch=offline)
        self.assertEqual(self.fixture.rows(), [])

    def test_strict_get_paths_no_actions_endpoints(self):
        with self.assertRaisesRegex(Hold, "unapproved_fresh_github_get_path"):
            refs.read_github_get("repos/AyobamiH/clawsweeper/actions/workflows/codeql.yml/dispatches")
        with self.assertRaisesRegex(Hold, "unapproved_fresh_github_get_path"):
            refs.read_github_get("repos/AyobamiH/clawsweeper/pulls/101?page=2")


if __name__ == "__main__":
    unittest.main()
