"""A third source-only replay job cannot inherit either original signed intent."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_replay_release_contract as review
import direct_local_offline_replay_suite as suite
from estate_policy import Hold
from test_direct_local_offline_replay_suite import policy as original_policy


class ThirdReplayReleaseContractTests(unittest.TestCase):
    def setUp(self):
        now = int(time.time())
        self.now = now
        self.sha = review.estate.git_head(ROOT)
        self.intent = {
            "schema": review.INTENT_SCHEMA,
            "repo": review.estate.REPO,
            "source_sha": self.sha,
            "source_ref": "main",
            "host": "web",
            "suite": suite.SUITE,
            "job_intents": [review.JOB],
            "purpose": "effect-free-offline-replay-validation",
            "nonce": "f" * 32,
            "issued_at": now,
            "expires_at": now + 600,
        }
        self.old = original_policy()
        self.original = copy.deepcopy(self.old)
        patcher = mock.patch.object(suite, "source_clean")
        patcher.start()
        self.addCleanup(patcher.stop)

    def raw(self):
        return review.canonical(self.intent)

    def test_contract_only_adds_one_scoped_suite_no_mutation(self):
        rendered = review.proposed_policy(ROOT, self.old)
        self.assertEqual(self.old, self.original)
        self.assertEqual(rendered["source_sha"], self.sha)
        self.assertEqual(rendered["intended_job_count"], 1)
        self.assertEqual(rendered["old_job_replays"], 0)
        self.assertEqual(rendered["workflow_job"], review.JOB)
        self.assertEqual(rendered["signature_namespace"],
                         "clawsweeper-third-offline-replay-v1")
        self.assertEqual(rendered["policy"]["repositories"][
            review.estate.REPO]["enrolled_head"], self.sha)
        prof = rendered["policy"]["repositories"][review.estate.REPO]["suites"]
        self.assertEqual(len(prof), 3)
        self.assertEqual(prof[suite.SUITE]["memory_mib"], 1536)
        self.assertEqual(prof[suite.SUITE]["writable_mib"], 1536)
        self.assertEqual(prof[suite.SUITE]["cpus"], 1)
        self.assertEqual(prof[suite.SUITE]["pids"], 256)
        self.assertEqual(len(prof[suite.SUITE]["steps"]), 4)
        for name in ("installed", "admitted", "executed",
                     "github_dispatch", "provider_status", "new_fleet_controller"):
            self.assertIs(rendered[name], False)

    def test_exact_single_job_and_freshness_only(self):
        self.assertEqual(review.parse_intent(self.raw(), now=self.now), self.intent)
        changed = (
            ("schema", "clawsweeper.owner-signed-local-manual-request.v2-split"),
            ("source_ref", "develop"),
            ("host", "Ayobami-Dev"),
            ("suite", "linux-node24-claw-check"),
            ("job_intents", [".github/workflows/ci.yml#check"]),
            ("job_intents", [review.JOB, review.JOB]),
            ("purpose", "ordinary-source-validation"),
            ("source_sha", "unknown"),
            ("nonce", "x" * 32),
            ("issued_at", self.now + 60),
            ("expires_at", self.now - 1),
            ("expires_at", self.now + 901),
        )
        for field, value in changed:
            with self.subTest(field=field, value=value):
                original = self.intent[field]
                self.intent[field] = value
                with self.assertRaises(Hold):
                    review.parse_intent(self.raw(), now=self.now)
                self.intent[field] = original
        self.intent["nonce"] = "a" * 32
        with self.assertRaises(Hold):
            review.parse_intent(
                self.raw().replace(b'"nonce":', b'"nonce":"b","nonce":'),
                now=self.now)

    def test_intent_authentication_has_distinct_signature_namespace(self):
        raw = self.raw()
        fake_sig = b"-----BEGIN SSH SIGNATURE-----\nTEST\n"
        with mock.patch.object(review.auth, "owner_allowed_signers",
                               return_value=ROOT/"AGENTS.md"), \
             mock.patch.object(review.auth, "owner_bytes", return_value=b"owner"), \
             mock.patch.object(review.auth, "_trusted_system_binary",
                               return_value="/usr/bin/ssh-keygen"), \
             mock.patch.object(review.subprocess, "run") as invocation:
            invocation.return_value.returncode = 0
            review.verify_owner_intent(raw, fake_sig)
            args = invocation.call_args.args[0]
            self.assertEqual(args[args.index("-n") + 1],
                             review.INTENT_NAMESPACE)
            self.assertEqual(invocation.call_args.kwargs["input"], raw)
            self.assertEqual(invocation.call_args.kwargs["env"]["PATH"],
                             "/usr/bin:/bin")
            invocation.return_value.returncode = 255
            with self.assertRaises(Hold):
                review.verify_owner_intent(raw, fake_sig)
        with self.assertRaises(Hold):
            review.verify_owner_intent(raw, b"old-two-job-signature")

    def test_preflight_fails_closed_when_provider_main_differs(self):
        with mock.patch.object(review, "verify_owner_intent"), \
             mock.patch.object(review, "read_fresh_main_sha") as main_get, \
             mock.patch.object(review.os, "getuid", return_value=1000), \
             mock.patch.object(review.os, "uname") as machine:
            machine.return_value.nodename = "web"
            main_get.return_value = "b" * 40
            with self.assertRaisesRegex(Hold, "not_fresh_main"):
                review.validate_for_admission(
                    ROOT, self.old, self.raw(), b"mock", now=self.now)
            main_get.return_value = self.sha
            admitted = review.validate_for_admission(
                ROOT, self.old, self.raw(), b"mock", now=self.now)
            self.assertEqual(admitted["job_count"], 1)
            self.assertEqual(admitted["ref"], "local-manual-replay")
            self.assertEqual(admitted["source_sha"], self.sha)
            self.assertIs(admitted["owner_signed"], True)
            self.assertIs(admitted["installed"], False)
            self.assertIs(admitted["admitted"], False)
            self.assertIs(admitted["executed"], False)
            self.assertIs(admitted["provider_effect"], False)
        self.assertEqual(self.old, self.original)

    def test_unverified_signed_source_or_existing_policy_refuses(self):
        with mock.patch.object(suite, "source_clean",
                               side_effect=Hold("dirty tree")):
            with self.assertRaises(Hold):
                review.proposed_policy(ROOT, self.old)
        mutated = copy.deepcopy(self.old)
        mutated["repositories"][review.estate.REPO]["suites"][
            suite.SUITE] = {"node": "24"}
        with self.assertRaises(Hold):
            review.proposed_policy(ROOT, mutated)

    def test_no_queue_or_provider_effect_entry_point(self):
        for attr in ("claim", "enqueue", "dispatch", "install", "publish"):
            self.assertFalse(hasattr(review, attr))
        self.assertNotEqual(review.REF, "local-manual")
        self.assertEqual(self.old, self.original)


if __name__ == "__main__":
    unittest.main()
