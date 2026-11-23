"""Crash, concurrency, ownership and evidence regression tests. No live JIT."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts" / "ci"))
from estate_policy import Admission, Hold, REPO, CLASSES
from estate_slots import SlotLedger, key_of

SHA = "a" * 40
LOG = "f" * 64
BASE = dict(enabled=True, repo=REPO, max_parallel=2,
            class_parallel_caps={key: (2 if key == "ordinary" else 1) for key in CLASSES})


def candidate(index, role="ordinary"):
    return Admission(f".github/workflows/ci.yml#check-{index}", role, 123, 1000 + index, 1,
                     SHA, ".github/workflows/ci.yml", "pull_request", f"run-{index}",
                     "test job", "feature")


def proof(c, **overrides):
    p = dict(run_id=c.run_id, job_id=c.job_id, attempt=c.attempt,
             log_sha256=LOG, runner_absent_verified=True,
             containers_absent_verified=True, github_terminal_verified=True,
             external_effects_verified=True, review_verdict_complete=True,
             source_bundle_verified=True, sarif_upload_verified=True,
             all_scenarios_verified=True, rootless_runtime_verified=True,
             native_windows_execution_verified=True)
    p.update(overrides)
    return p


class SlotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "slots"
        self.ledger = SlotLedger(self.root)
        self.controls = json.loads(json.dumps(BASE))

    def tearDown(self):
        self.tmp.cleanup()

    def reserve(self, c, **kwargs):
        return self.ledger.reserve(c, self.controls, memory_available_mib=20000,
                                   disk_free_gib=100, **kwargs)

    def test_two_disjoint_jobs_can_run_simultaneously_without_a_third_slot(self):
        a = self.reserve(candidate(1))
        b = self.reserve(candidate(2))
        self.assertEqual({a["slot"], b["slot"]}, {0, 1})
        self.assertEqual(len(self.ledger.inspect()["attempts"]), 2)
        with self.assertRaisesRegex(Hold, "fleet_capacity_exhausted"):
            self.reserve(candidate(3))
        self.assertEqual(self.ledger.update(candidate(1), state="running")["state"], "running")
        self.assertEqual(self.ledger.update(candidate(2), state="running")["state"], "running")
        a_done = self.ledger.update(candidate(1), state="finished", proof=proof(candidate(1)))
        self.assertEqual(a_done["state"], "finished")
        self.assertEqual(self.reserve(candidate(3))["slot"], 0)

    def test_attempt_is_never_replayed_after_success_or_failure(self):
        c = candidate(1)
        self.reserve(c)
        self.ledger.update(c, state="finished", proof=proof(c))
        with self.assertRaisesRegex(Hold, "duplicate_or_uncertain_job_intent"):
            self.reserve(c)
        self.reserve(replace(c, attempt=2))
        with self.assertRaisesRegex(Hold, "duplicate_or_uncertain_job_intent"):
            self.reserve(replace(c, attempt=2))

    def test_crashed_worker_keeps_capacity_held_across_new_instance(self):
        c = candidate(1)
        self.reserve(c)
        new = SlotLedger(self.root)
        with self.assertRaisesRegex(Hold, "duplicate_or_uncertain_job_intent"):
            new.reserve(c, self.controls, memory_available_mib=20000, disk_free_gib=100)
        self.assertEqual(new.inspect()["attempts"][key_of(c)]["state"], "reserved")
        new.reserve(candidate(2), self.controls, memory_available_mib=20000, disk_free_gib=100)
        with self.assertRaisesRegex(Hold, "fleet_capacity_exhausted"):
            new.reserve(candidate(3), self.controls, memory_available_mib=20000, disk_free_gib=100)

    def test_missing_cleanup_or_terminal_verification_keeps_slot_held(self):
        c = candidate(1)
        self.reserve(c)
        r = self.ledger.update(c, state="finished", proof=proof(c, runner_absent_verified=False))
        self.assertEqual(r["state"], "held")
        with self.assertRaisesRegex(Hold, "reservation_already_final_or_held"):
            self.ledger.update(c, state="finished", proof=proof(c))
        with self.assertRaisesRegex(Hold, "duplicate_or_uncertain_job_intent"):
            self.reserve(c)

    def test_class_specific_evidence_is_mandatory(self):
        for i, role, failed_key in [
            (1, "privileged", "external_effects_verified"),
            (2, "review", "review_verdict_complete"),
            (3, "codeql", "sarif_upload_verified"),
            (4, "e2e", "rootless_runtime_verified"),
            (5, "windows", "native_windows_execution_verified"),
        ]:
            with self.subTest(role=role):
                with tempfile.TemporaryDirectory() as root:
                    ledger = SlotLedger(Path(root) / "slots")
                    c = candidate(i, role)
                    ledger.reserve(c, self.controls, memory_available_mib=20000, disk_free_gib=100)
                    result = ledger.update(c, state="finished", proof=proof(c, **{failed_key: False}))
                    if role == "codeql":
                        self.assertEqual(result["state"], "awaiting_evidence")
                        self.assertEqual(result["reason"], "sarif_readback_pending")
                    else:
                        self.assertEqual(result["state"], "held")
                        self.assertEqual(result["reason"], "class_evidence_incomplete")

    def test_identity_and_digests_are_required_to_release_any_slot(self):
        c = candidate(1)
        self.reserve(c)
        for corrupted, reason in [
            ({"job_id": 1}, "final_receipt_identity_mismatch"),
            ({"log_sha256": "0" * 50}, "runner_log_digest_missing"),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(Hold, reason):
                self.ledger.update(c, state="finished", proof=proof(c, **corrupted))
        self.assertEqual(self.ledger.inspect()["attempts"][key_of(c)]["state"], "reserved")

    def test_class_caps_and_resource_guards_do_not_overcommit(self):
        codeql = candidate(1, "codeql")
        self.reserve(codeql)
        with self.assertRaisesRegex(Hold, "class_capacity_exhausted"):
            self.reserve(candidate(2, "codeql"))
        with self.assertRaisesRegex(Hold, "shared_fleet_has_priority"):
            self.reserve(candidate(3), fleet_busy=True)
        with self.assertRaisesRegex(Hold, "aggregate_memory_reserve"):
            self.ledger.reserve(candidate(3), self.controls,
                                memory_available_mib=8000, disk_free_gib=100)
        with self.assertRaisesRegex(Hold, "insufficient_disk_reserve"):
            self.ledger.reserve(candidate(3), self.controls,
                                memory_available_mib=20000, disk_free_gib=10)

    def test_invalid_parallel_configuration_must_fail_closed(self):
        c = candidate(1)
        for change in (
            {"max_parallel": 0},
            {"max_parallel": 100},
            {"max_parallel": True},
            {"class_parallel_caps": {}},
            {"class_parallel_caps": {k: 3 for k in CLASSES}},
            {"enabled": False},
        ):
            ctrl = {**self.controls, **change}
            with self.subTest(change=change), self.assertRaises(Hold):
                self.ledger.reserve(c, ctrl, memory_available_mib=20000, disk_free_gib=100)

    def test_parallel_threads_cannot_reserve_same_attempt_twice(self):
        c = candidate(1)
        def run():
            try:
                return "accepted", self.reserve(c)
            except Hold as exc:
                return "held", str(exc)
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _: run(), range(8)))
        self.assertEqual(sum(x[0] == "accepted" for x in outcomes), 1)
        self.assertEqual(sum(x[0] == "held" for x in outcomes), 7)
        self.assertEqual(len(self.ledger.inspect()["attempts"]), 1)

    def test_independent_reconciliation_releases_only_proven_cleanup_and_keeps_attempt_history(self):
        c = candidate(1, "privileged")
        self.reserve(c)
        held = self.ledger.update(c, state="finished", proof=proof(c, external_effects_verified=False))
        self.assertEqual(held["state"], "held")
        with self.assertRaisesRegex(Hold, "independent_reconciliation_incomplete"):
            self.ledger.reconcile_held(c, proof=proof(c, external_effects_verified=False))
        reconciled = self.ledger.reconcile_held(c, proof=proof(c))
        self.assertEqual(reconciled["state"], "reconciled")
        self.assertEqual(reconciled["state_before_reconciliation"], "held")
        with self.assertRaisesRegex(Hold, "duplicate_or_uncertain_job_intent"):
            self.reserve(c)
        with self.assertRaisesRegex(Hold, "attempt_not_held"):
            self.ledger.reconcile_held(c, proof=proof(c))
        self.assertEqual(self.reserve(candidate(2))["slot"], 0)

    def test_owner_only_ledger_and_lock_with_no_symlink_following(self):
        c = candidate(1)
        self.reserve(c)
        for name in ("ledger.json", "ledger.lock"):
            p = self.root / name
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        link_root = Path(self.tmp.name) / "alias"
        link_root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(Hold, "unsafe_estate_state_permissions"):
            SlotLedger(link_root)
