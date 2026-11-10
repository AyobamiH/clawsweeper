"""Offline controller acceptance including two simultaneous real worker callbacks.

No GitHub workflow dispatch, model inference, Docker, or runner registration.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import copy
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts" / "ci"))
import estate_controller as ctl
from estate_policy import classify, load_manifest, REPO, CLASSES, Admission
from estate_slots import SlotLedger

MANIFEST = load_manifest()
SHA = "a" * 40


def synthetic(job_id, ident):
    # The CI check/sparse jobs are delegated to the pre-existing validation
    # controller. Exercise concurrent estate JIT with the two distinct CodeQL
    # matrix languages instead of fabricating a second owner for those jobs.
    assert job_id in ("actions", "javascript-typescript")
    path = ".github/workflows/codeql.yml"
    item = next(j for j in MANIFEST["jobs"] if j["workflow"] == path and j["id"] == "analyze")
    run = {"id": 9000 + ident, "run_attempt": 1, "head_sha": SHA, "head_branch": "main",
           "repository": {"full_name": REPO}, "path": path, "event": "workflow_dispatch"}
    job = {"id": 10000 + ident, "run_id": 9000 + ident, "name": f"Analyze ({job_id})",
           "status": "queued",
           "labels": ["self-hosted", "Linux", "X64",
                      f"clawsweeper-ci-security-{9000 + ident}-{job_id}"]}
    c = classify(MANIFEST, run, job)
    return (c, run, job), item


def controls(items):
    permitted = {}
    for candidate, entry in items:
        record = permitted.setdefault(candidate.job_key, {
            "class": "codeql", "source_sha256": entry["source_sha256"],
            "run_ids": [], "head_shas": [],
            "approved_attempts": [], "image_sha256": "a" * 64,
        })
        record["approved_attempts"].append({
            "run_id": candidate.run_id,
            "job_id": candidate.job_id,
            "attempt": candidate.attempt,
            "head_sha": candidate.sha,
            "job_name": candidate.name,
        })
        record["run_ids"].append(candidate.run_id)
        if candidate.sha not in record["head_shas"]:
            record["head_shas"].append(candidate.sha)
    return dict(enabled=True, allow_live_mutations=True, repo=REPO,
                trusted_main_sha=SHA, enabled_classes=["codeql"],
                codeql_sarif_accepted=True, approved_jobs=permitted,
                max_parallel=2,
                class_parallel_caps={k: (2 if k == "codeql" else 1) for k in CLASSES})


def successful(c):
    return dict(run_id=c.run_id, job_id=c.job_id, attempt=c.attempt,
                log_sha256="a" * 64, runner_absent_verified=True,
                containers_absent_verified=True, github_terminal_verified=True,
                sarif_upload_verified=True)


class ControllerAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = SlotLedger(Path(self.tmp.name) / "slots")
        # Pure mocked-controller tests have no right to seize the real
        # production fleet lock; the actual locking contract is exercised
        # separately against a private test-owned lock inode.
        guard = patch.object(ctl, "shared_fleet_exclusive", side_effect=lambda: nullcontext())
        guard.start()
        self.addCleanup(guard.stop)
        legacy = patch.object(ctl, "legacy_executor_exclusive", side_effect=lambda: nullcontext())
        legacy.start()
        self.addCleanup(legacy.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_off_cannot_even_discover_or_dispatch(self):
        with patch.object(ctl, "discover", side_effect=AssertionError("should not discover")):
            self.assertEqual(ctl.cycle(manifest=MANIFEST, controls={}, ledger=self.ledger),
                             {"held": "estate_controller_disabled"})

    def test_two_different_readonly_jobs_execute_concurrently_and_release_slots(self):
        one, e1 = synthetic("actions", 1)
        two, e2 = synthetic("javascript-typescript", 2)
        trusted = controls([(one[0], e1), (two[0], e2)])
        barrier = threading.Barrier(2, timeout=5)
        starts = []
        def worker(candidate, _controls):
            starts.append(candidate.job_id)
            barrier.wait()
            return successful(candidate)
        def api(path):
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": SHA}}
            raise AssertionError(path)
        def digest(run, main, api=None):
            return (e1 if run["id"] == one[0].run_id else e2)["source_sha256"]
        with patch.object(ctl, "discover", return_value=[one, two]), \
             patch.object(ctl, "fetch_workflow_digest", side_effect=digest), \
             patch.object(ctl, "preflight_runtime_inventory", return_value={}), \
             patch.object(ctl, "host_capacity", return_value={
                 "memory_available_mib": 20000, "disk_free_gib": 100, "fleet_busy": False}):
            result = ctl.cycle(MANIFEST, trusted, self.ledger, api=api, worker=worker)
        self.assertEqual(set(starts), {one[0].job_id, two[0].job_id})
        self.assertEqual([x["state"] for x in result["jobs"]], ["finished", "finished"])
        self.assertEqual(len(self.ledger.inspect()["attempts"]), 2)
        self.assertEqual(ctl.inspect(MANIFEST, trusted, self.ledger)["active_or_held_attempts"], [])
        with self.assertRaisesRegex(Exception, "duplicate_or_uncertain_job_intent"):
            self.ledger.reserve(one[0], trusted, memory_available_mib=20000, disk_free_gib=100)

    def test_crashed_worker_never_causes_automatic_replay(self):
        one, e1 = synthetic("actions", 1)
        trusted = controls([(one[0], e1)])
        calls = []
        def worker(candidate, _controls):
            calls.append(candidate.job_id)
            raise RuntimeError("worker interrupted")
        def api(path):
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": SHA}}
            raise AssertionError(path)
        with patch.object(ctl, "discover", return_value=[one]), \
             patch.object(ctl, "fetch_workflow_digest", return_value=e1["source_sha256"]), \
             patch.object(ctl, "reconcile_codeql", return_value=[]), \
             patch.object(ctl, "preflight_runtime_inventory", return_value={}), \
             patch.object(ctl, "host_capacity", return_value={
                 "memory_available_mib": 20000, "disk_free_gib": 100, "fleet_busy": False}):
            first = ctl.cycle(MANIFEST, trusted, self.ledger, api=api, worker=worker)
            second = ctl.cycle(MANIFEST, trusted, self.ledger, api=api, worker=worker)
        self.assertEqual(calls, [one[0].job_id])
        self.assertEqual(first["jobs"][0]["state"], "held")
        self.assertEqual(second, {"held": "fleet_or_class_capacity_not_available"})
        self.assertEqual(len(self.ledger.inspect()["attempts"]), 1)

    def test_source_mismatch_is_not_softened_when_execution_is_requested(self):
        one, e1 = synthetic("actions", 1)
        trusted = controls([(one[0], e1)])
        with patch.object(ctl, "discover", return_value=[one]), \
             patch.object(ctl, "fetch_workflow_digest", return_value="b" * 64), \
             patch.object(ctl, "preflight_runtime_inventory", return_value={}), \
             patch.object(ctl, "host_capacity", return_value={
                 "memory_available_mib": 20000, "disk_free_gib": 100, "fleet_busy": False}):
            report = ctl.cycle(MANIFEST, trusted, self.ledger, api=lambda p: {"object": {"sha": SHA}},
                               worker=lambda *_: (_ for _ in ()).throw(AssertionError("should never run")))
        self.assertEqual(report["held"], "no_approved_queued_jobs")
        self.assertFalse(self.ledger.inspect()["attempts"])

    def test_codeql_group_proof_releases_awaiting_evidence_without_replay(self):
        c = Admission(".github/workflows/codeql.yml#analyze", "codeql", 404, 505, 1, SHA,
                      ".github/workflows/codeql.yml", "push", "clawsweeper-ci-security-404-actions",
                      "Analyze (actions)", "main")
        config = dict(enabled=True, repo=REPO, max_parallel=2,
                      class_parallel_caps={k: 2 for k in CLASSES})
        self.ledger.reserve(c, config, memory_available_mib=20000, disk_free_gib=100)
        self.ledger.update(c, state="running")
        res = self.ledger.update(c, state="finished", proof={
            **successful(c), "sarif_upload_verified": False})
        self.assertEqual(res["state"], "awaiting_evidence")
        import json
        receipt_root = Path(self.tmp.name) / "receipts"
        folder = receipt_root / "run-404-job-505-attempt-1"
        folder.mkdir(parents=True)
        (folder / "receipt.json").write_text(json.dumps({"runner_id": 222}))
        evidence = {"jobs": {
            "actions": {"id": 505, "runner": "csw-ci-404-505-1",
                        "log_sha256": "a" * 64},
        }}
        with patch.object(ctl.existing, "RECEIPTS", receipt_root), \
             patch("verify_codeql_release.verify_release", return_value=evidence), \
             patch.object(ctl.existing, "runner_absent_verified", return_value=True), \
             patch.object(ctl.existing, "inspect_owned", return_value=None):
            result = ctl.reconcile_codeql(
                self.ledger, api=lambda p: {"head_sha": SHA, "event": "push", "pull_requests": []})
        self.assertEqual(result[0]["state"], "reconciled")
        record = next(iter(self.ledger.inspect()["attempts"].values()))
        self.assertEqual(record["state_before_reconciliation"], "awaiting_evidence")
        self.assertEqual(record["state"], "reconciled")
