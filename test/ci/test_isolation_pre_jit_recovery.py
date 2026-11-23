"""Exact-owner E2E preparation recovery; no GitHub, JIT or Docker effects.

The SIGKILL test uses a real child process and disk-backed journal but fake
Docker state. It proves recovery without repeating an uncertain registration.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as ex
from self_hosted_policy import AdmissionHold, Candidate

IMAGE = "sha256:" + "a" * 64
HEAD = "b" * 40


def candidate():
    return Candidate(4101, 4202, 1, HEAD,
                     ".github/workflows/automerge-e2e.yml",
                     "pull_request", "isolation", "e2e",
                     "clawsweeper-ci-isolation-4101-e2e",
                     "production automerge flow", "owner-branch",
                     "c" * 40, 103)


def identity():
    return "csw-ci-4101-4202-1"


class NoProviderPreparationTests(unittest.TestCase):
    def test_journal_is_fsynced_before_volume_and_before_post(self):
        c = candidate()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            receipts.mkdir(mode=0o700)
            target = receipts / "run-4101-job-4202-attempt-1"
            observations = []

            def prepare(name, image):
                observed = json.loads((target / "preparation-intent.json").read_text())
                self.assertEqual(observed["state"], "preparing")
                self.assertFalse(observed["jit_post_may_have_started"])
                self.assertFalse((target / "receipt.json").exists())
                observations.append("prepared")
                return ex.volume_name(name), name + "-vault-holder"

            def fake_gh(path, method="GET", body=None):
                if method == "POST":
                    journal = json.loads((target / "preparation-intent.json").read_text())
                    receipt = json.loads((target / "receipt.json").read_text())
                    self.assertEqual(journal["state"], "registration_may_have_started")
                    self.assertTrue(journal["jit_post_may_have_started"])
                    self.assertEqual(receipt["state"], "registration_uncertain")
                    observations.append("post")
                    raise RuntimeError("network interrupted; never retry")
                self.assertIn("/actions/runners", path)
                return {"total_count": 0, "runners": []}

            with (patch.object(ex, "RECEIPTS", receipts),
                  patch.object(ex, "approved_job_image", return_value=IMAGE),
                  patch.object(ex, "isolation_log_limiter", return_value="/usr/bin/prlimit"),
                  patch.object(ex, "prepare_isolation_volume", side_effect=prepare),
                  patch.object(ex, "gh", side_effect=fake_gh),
                  patch.object(ex, "stop_owned"),
                  patch.object(ex, "cleanup_isolation_volume") as cleanup,
                  patch.object(ex, "lookup_owned_runner", return_value=None),
                  patch.object(ex, "runner_absent_verified", return_value=True)):
                result = ex.runner_job(c, {})
                self.assertEqual(result["state"], "held")
                self.assertEqual(observations, ["prepared", "post"])
                cleanup.assert_called_once()
                self.assertEqual(json.loads((target / "preparation-intent.json").read_text())["state"],
                                 "registration_may_have_started")
                with self.assertRaises(AdmissionHold):
                    ex.select_runner_intent(c)

    def test_pre_jit_receipt_write_failure_forces_owned_cleanup(self):
        c = candidate()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            receipts.mkdir(mode=0o700)
            target = receipts / "run-4101-job-4202-attempt-1"
            orig_atomic = ex.atomic
            stages = []

            def faulty_atomic(path, content):
                if path.name == "receipt.json":
                    stages.append("receipt_failure")
                    raise OSError("fault-injected atomic receipt failure")
                return orig_atomic(path, content)

            with (patch.object(ex, "RECEIPTS", receipts),
                  patch.object(ex, "approved_job_image", return_value=IMAGE),
                  patch.object(ex, "isolation_log_limiter", return_value="/usr/bin/prlimit"),
                  patch.object(ex, "prepare_isolation_volume", return_value=(
                      ex.volume_name(identity()), identity() + "-vault-holder")),
                  patch.object(ex, "atomic", side_effect=faulty_atomic),
                  patch.object(ex, "remove_isolation_holder") as remove_seed,
                  patch.object(ex, "cleanup_isolation_volume") as cleanup,
                  patch.object(ex, "gh", side_effect=AssertionError("never JIT/GET"))):
                with self.assertRaises(OSError):
                    ex.runner_job(c, {})
                remove_seed.assert_called_once_with(identity() + "-home-seed", identity())
                cleanup.assert_called_once_with(
                    ex.volume_name(identity()), identity() + "-vault-holder", identity())
                self.assertEqual(stages, ["receipt_failure"])
                record = json.loads((target / "preparation-intent.json").read_text())
                self.assertEqual(record["state"], "cleanup_verified")
                self.assertFalse(record["jit_post_may_have_started"])
                self.assertFalse((target / "receipt.json").exists())

    def test_prepare_failure_is_also_inside_cleanup_guard(self):
        c = candidate()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            receipts.mkdir(mode=0o700)
            with (patch.object(ex, "RECEIPTS", receipts),
                  patch.object(ex, "approved_job_image", return_value=IMAGE),
                  patch.object(ex, "isolation_log_limiter", return_value="/usr/bin/prlimit"),
                  patch.object(ex, "prepare_isolation_volume",
                               side_effect=RuntimeError("partially allocated")),
                  patch.object(ex, "remove_isolation_holder") as seed,
                  patch.object(ex, "cleanup_isolation_volume") as cleanup,
                  patch.object(ex, "gh", side_effect=AssertionError("never JIT/GET"))):
                with self.assertRaisesRegex(RuntimeError, "partially allocated"):
                    ex.runner_job(c, {})
                seed.assert_called_once()
                cleanup.assert_called_once()
                journal = receipts / "run-4101-job-4202-attempt-1" / "preparation-intent.json"
                self.assertEqual(json.loads(journal.read_text())["state"], "cleanup_verified")

    def test_actual_sigkill_recovery_reclaims_exact_resources_without_replay(self):
        c = candidate()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            receipts.mkdir(mode=0o700)
            code = r'''
import os,sys,signal
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import self_hosted_executor as ex
from self_hosted_policy import Candidate
c = Candidate(4101,4202,1,"b"*40,".github/workflows/automerge-e2e.yml",
              "pull_request","isolation","e2e","clawsweeper-ci-isolation-4101-e2e",
              "production automerge flow","owner-branch","c"*40,103)
def kill_after_prep(owner,image):
    os.kill(os.getpid(),signal.SIGKILL)
with (patch.object(ex,"RECEIPTS",Path(sys.argv[2])),
      patch.object(ex,"approved_job_image",return_value="sha256:"+"a"*64),
      patch.object(ex,"isolation_log_limiter",return_value="/usr/bin/prlimit"),
      patch.object(ex,"prepare_isolation_volume",side_effect=kill_after_prep),
      patch.object(ex,"gh",side_effect=AssertionError("provider forbidden"))):
    ex.runner_job(c,{})
'''
            child = subprocess.run(
                [sys.executable, "-B", "-c", code,
                 str(Path(ex.__file__).parent), str(receipts)],
                capture_output=True, timeout=20)
            self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
            target = receipts / "run-4101-job-4202-attempt-1"
            self.assertFalse((target / "receipt.json").exists())
            journal = json.loads((target / "preparation-intent.json").read_text())
            self.assertEqual(journal["state"], "preparing")

            # Fake Docker resources model partial allocation surviving SIGKILL.
            live_volumes = {journal["evidence_volume"], journal["home_volume"]}
            live_containers = {journal["holder"], journal["seed"]}
            cleaned = []

            def owned(name, owner):
                self.assertEqual(owner, identity())
                return {"Config": {"Labels": {ex.LABEL: owner}}} if name in live_containers else None

            def volume(name, owner, *, options=ex.VOLUME_OPTIONS):
                self.assertEqual(owner, identity())
                return {"Name": name} if name in live_volumes else None

            def remove_seed(name, owner):
                cleaned.append(("seed", name))
                live_containers.discard(name)

            def cleanup(volume_name, holder, owner):
                cleaned.append(("volumes", volume_name, holder))
                live_containers.discard(holder)
                live_volumes.clear()

            with (patch.object(ex, "RECEIPTS", receipts),
                  patch.object(ex, "inspect_owned", side_effect=owned),
                  patch.object(ex, "inspect_isolation_volume", side_effect=volume),
                  patch.object(ex, "remove_isolation_holder", side_effect=remove_seed),
                  patch.object(ex, "cleanup_isolation_volume", side_effect=cleanup),
                  patch.object(ex, "gh", side_effect=AssertionError("no GitHub effects"))):
                result = ex.reconcile_isolation_preparation(target, c, identity())
                self.assertEqual(result["state"], "cleanup_verified_no_registration_retry")
                self.assertFalse(result["registration_replayed"])
                self.assertFalse(live_volumes)
                self.assertFalse(live_containers)
                self.assertEqual(len(cleaned), 2)
                self.assertEqual(ex.reconcile_isolation_preparation(target, c, identity())["state"],
                                 "cleanup_verified_no_registration_retry")
                self.assertEqual(len(cleaned), 2)
                with self.assertRaises(AdmissionHold):
                    ex.select_runner_intent(c)

    def test_foreign_container_identity_fences_without_deleting(self):
        c = candidate()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            target = receipts / "run-4101-job-4202-attempt-1"
            target.mkdir(parents=True, mode=0o700)
            with patch.object(ex, "RECEIPTS", receipts):
                ex.atomic(target / "preparation-intent.json",
                          ex.isolation_preparation_record(c, identity(), IMAGE))
            with (patch.object(ex, "RECEIPTS", receipts),
                  patch.object(ex, "inspect_owned",
                               side_effect=RuntimeError("container_ownership_mismatch")),
                  patch.object(ex, "cleanup_isolation_volume") as cleanup,
                  patch.object(ex, "gh", side_effect=AssertionError("no provider effects"))):
                with self.assertRaisesRegex(RuntimeError, "container_ownership_mismatch"):
                    ex.reconcile_isolation_preparation(target, c, identity())
                cleanup.assert_not_called()

    def test_uncertain_registration_boundary_holds_when_job_is_not_terminal(self):
        c = candidate()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            target = receipts / "run-4101-job-4202-attempt-1"
            target.mkdir(parents=True, mode=0o700)
            with patch.object(ex, "RECEIPTS", receipts):
                ex.atomic(target / "preparation-intent.json",
                          dict(ex.isolation_preparation_record(c, identity(), IMAGE),
                               state="registration_may_have_started",
                               jit_post_may_have_started=True))
                ex.atomic(target / "receipt.json", {
                    "schema": "clawsweeper.selfhosted-jit.v1",
                    "run_id": 4101, "job_id": 4202, "attempt": 1,
                    "head_sha": HEAD, "workflow": c.workflow, "event": c.event,
                    "role": "isolation", "label": c.label,
                    "runner_name": identity(), "image_sha256": IMAGE,
                    "state": "registration_uncertain"})
            def gh(path, method="GET", body=None):
                self.assertEqual(method, "GET")
                if "/actions/runs/" in path:
                    return {"id": 4101, "run_attempt": 1, "head_sha": HEAD,
                            "path": c.workflow}
                return {"id": 4202, "run_id": 4101, "status": "queued",
                        "conclusion": None}
            with (patch.object(ex, "RECEIPTS", receipts),
                  patch.object(ex, "gh", side_effect=gh),
                  patch.object(ex, "cleanup_isolation_volume") as cleanup):
                with self.assertRaisesRegex(AdmissionHold,
                                            "isolation_post_boundary_job_not_terminal"):
                    ex.reconcile_isolation_preparation(target, c, identity())
                cleanup.assert_not_called()

    def test_terminal_receipt_reconciles_no_provider_and_preserves_post_provenance(self):
        for outcome, conclusion, runner_id, issues in (
                ("passed", "success", 79, []),
                ("held", "failure", 78, ["isolation_volume_cleanup_unverified"])):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as td:
                c = candidate()
                name = identity()
                receipts = Path(td) / "receipts"
                target = receipts / "run-4101-job-4202-attempt-1"
                target.mkdir(parents=True, mode=0o700)
                with patch.object(ex, "RECEIPTS", receipts):
                    ex.atomic(target / "preparation-intent.json", dict(
                        ex.isolation_preparation_record(c, name, IMAGE),
                        state="registration_may_have_started",
                        jit_post_may_have_started=True))
                    ex.atomic(target / "receipt.json", {
                        "schema": "clawsweeper.selfhosted-jit.v1",
                        "run_id": c.run_id, "job_id": c.job_id, "attempt": c.run_attempt,
                        "head_sha": c.sha, "workflow": c.workflow, "event": c.event,
                        "role": "isolation", "label": c.label, "runner_name": name,
                        "image_sha256": IMAGE, "state": outcome, "runner_id": runner_id,
                        "finished_at": "2026-11-12T12:00:00Z", "issues": issues})
                calls = []
                def gh_get(path, method="GET", body=None):
                    self.assertEqual(method, "GET")
                    calls.append(path)
                    if "/actions/runs/" in path:
                        return {"id": c.run_id, "run_attempt": c.run_attempt,
                                "head_sha": c.sha, "path": c.workflow}
                    return {"id": c.job_id, "run_id": c.run_id,
                            "status": "completed", "conclusion": conclusion,
                            "runner_name": name, "runner_id": runner_id}
                with (patch.object(ex, "RECEIPTS", receipts),
                      patch.object(ex, "gh", side_effect=gh_get),
                      patch.object(ex, "lookup_owned_runner", return_value=None),
                      patch.object(ex, "runner_absent_verified", return_value=True) as absent,
                      patch.object(ex, "inspect_owned", return_value=None),
                      patch.object(ex, "inspect_isolation_volume", return_value=None),
                      patch.object(ex, "remove_isolation_holder") as seed,
                      patch.object(ex, "cleanup_isolation_volume") as cleanup):
                    first = ex.reconcile_isolation_preparation(target, c, name)
                    second = ex.reconcile_isolation_preparation(target, c, name)
                    self.assertEqual(first["state"], "cleanup_verified_no_registration_retry")
                    self.assertEqual(second["state"], first["state"])
                    seed.assert_called_once_with(name + "-home-seed", name)
                    cleanup.assert_called_once()
                    self.assertEqual(absent.call_count, 2)
                    self.assertEqual(len(calls), 4)
                    journal = json.loads((target / "preparation-intent.json").read_text())
                    self.assertEqual(journal["state"], "cleanup_verified_terminal")
                    self.assertTrue(journal["jit_post_may_have_started"])
                    self.assertFalse(journal["registration_replayed"])
                    self.assertEqual(journal["registration_outcome"],
                                     "terminal_provider_reconciled")
                    with self.assertRaises(AdmissionHold):
                        ex.select_runner_intent(c)

    def test_terminal_passed_provider_runner_id_mismatch_refuses_cleanup(self):
        c = candidate()
        name = identity()
        with tempfile.TemporaryDirectory() as td:
            receipts = Path(td) / "receipts"
            target = receipts / "run-4101-job-4202-attempt-1"
            target.mkdir(parents=True, mode=0o700)
            with patch.object(ex, "RECEIPTS", receipts):
                ex.atomic(target / "preparation-intent.json", dict(
                    ex.isolation_preparation_record(c, name, IMAGE),
                    state="registration_may_have_started",
                    jit_post_may_have_started=True))
                ex.atomic(target / "receipt.json", {
                    "schema": "clawsweeper.selfhosted-jit.v1",
                    "run_id": c.run_id, "job_id": c.job_id, "attempt": c.run_attempt,
                    "head_sha": c.sha, "workflow": c.workflow, "event": c.event,
                    "role": "isolation", "label": c.label, "runner_name": name,
                    "image_sha256": IMAGE, "state": "passed", "runner_id": 79,
                    "finished_at": "2026-11-12T12:00:00Z", "issues": []})
            def gh_get(path, method="GET", body=None):
                self.assertEqual(method, "GET")
                if "/actions/runs/" in path:
                    return {"id": c.run_id, "run_attempt": c.run_attempt,
                            "head_sha": c.sha, "path": c.workflow}
                return {"id": c.job_id, "run_id": c.run_id, "status": "completed",
                        "conclusion": "success", "runner_name": name, "runner_id": 80}
            with (patch.object(ex, "RECEIPTS", receipts),
                  patch.object(ex, "gh", side_effect=gh_get),
                  patch.object(ex, "remove_isolation_holder") as seed,
                  patch.object(ex, "cleanup_isolation_volume") as cleanup):
                with self.assertRaisesRegex(
                        AdmissionHold, "isolation_terminal_passed_binding_mismatch"):
                    ex.reconcile_isolation_preparation(target, c, name)
                seed.assert_not_called()
                cleanup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
