"""Dedicated rootless E2E class acceptance; all provider and Docker calls mocked."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
from estate_policy import Admission, Hold, REPO, classify, load_manifest
import estate_e2e_driver as driver
import estate_controller as ctl


MANIFEST = load_manifest()
KEY = driver.E2E_KEY
HEAD = "a" * 40
BASE = "b" * 40
IMAGE = "sha256:" + "c" * 64


def candidate(**kwargs):
    item = dict(job_key=KEY, job_class="e2e", run_id=800, job_id=801,
                attempt=1, sha=HEAD, workflow=".github/workflows/automerge-e2e.yml",
                event="pull_request", label="clawsweeper-ci-isolation-800-e2e",
                name="production automerge flow", branch="test/safe")
    item.update(kwargs)
    return Admission(**item)


def controls(c=None):
    c = c or candidate()
    return {
        "repo": REPO, "enabled": True, "allow_live_mutations": True,
        "enabled_classes": ["e2e"], "enabled_roles": ["isolation"],
        "allowed_run_ids": [c.run_id], "operations_accepted": False,
        "model_inference_permitted": False,
        "isolation_accepted": True,
        "rootless_nested_container_proven": True,
        "e2e_dedicated_driver_accepted": True,
        "isolation_image_sha256": IMAGE,
        "isolation_head_sha": c.sha,
        "isolation_workflow_sha256": "d" * 64,
        "isolation_pr_number": 8, "isolation_base_sha": BASE,
        "isolation_base_ref": "main",
        "isolation_harness_sha256": {k: "f" * 64 for k in ctl.existing.ISOLATION_HARNESS_FILES},
        "approved_jobs": {KEY: {
            "class": "e2e", "source_sha256": "d" * 64,
            "image_sha256": IMAGE[7:], "run_ids": [c.run_id],
            "head_shas": [c.sha],
            "approved_attempts": [{
                "run_id": c.run_id, "job_id": c.job_id,
                "attempt": c.attempt, "head_sha": c.sha,
                "job_name": c.name,
            }],
            "no_host_docker_socket": True, "full_scenarios": True,
        }},
    }


def provider(c):
    repo = {"full_name": REPO, "id": 135}
    base = {"sha": BASE, "ref": "main", "repo": repo}
    head = {"sha": c.sha, "ref": c.branch, "repo": repo}
    run = {"id": c.run_id, "run_attempt": c.attempt, "head_sha": c.sha,
           "head_branch": c.branch, "event": c.event, "path": c.workflow,
           "repository": repo, "pull_requests": [{"number": 8}],
           "actor": {"login": "AyobamiH", "id": 12345}}
    job = {"id": c.job_id, "run_id": c.run_id, "status": "queued",
           "name": c.name, "labels": ["self-hosted", "Linux", "X64", c.label],
           "runner_id": 0, "runner_name": ""}
    pr = {"number": 8, "state": "open", "head": head, "base": base}
    terminal = {**job, "status": "completed", "conclusion": "success",
                "runner_name": "csw-ci-800-801-1", "runner_id": 3}
    resources = {
        f"repos/{REPO}/actions/runs/{c.run_id}": run,
        f"repos/{REPO}/actions/jobs/{c.job_id}": job,
        f"repos/{REPO}/pulls/8": pr,
    }
    calls = [0]
    def api(path):
        if path == f"repos/{REPO}/actions/jobs/{c.job_id}":
            calls[0] += 1
            if calls[0] > 1:
                return terminal
        return resources[path]
    return api


class E2ESourceContract(unittest.TestCase):
    def test_source_label_matches_existing_dedicated_isolation_contract(self):
        c = candidate()
        run = {"id": c.run_id, "run_attempt": c.attempt,
               "head_sha": c.sha, "head_branch": c.branch,
               "event": "pull_request", "path": c.workflow,
               "actor": {"login": "reviewer", "id": 100},
               "repository": {"full_name": REPO}}
        job = {"id": c.job_id, "run_id": c.run_id, "status": "queued",
               "name": c.name, "labels": ["self-hosted", "Linux", "X64", c.label]}
        self.assertEqual(classify(MANIFEST, run, job), c.__class__(**{
            **c.__dict__, "actor_login": "reviewer", "actor_id": 100}))
        for label in (c.label.replace("isolation", "security"),
                      "clawsweeper-ci-e2e-800-automerge-e2e",
                      c.label.replace("-800-", "-900-")):
            with self.subTest(label=label):
                with self.assertRaisesRegex(Hold, "run_bound_runner_label_missing"):
                    classify(MANIFEST, run, {**job, "labels": ["self-hosted", label]})
        self.assertEqual(sum(x["workflow"] == c.workflow and x["id"] == "automerge-e2e"
                             for x in MANIFEST["jobs"]), 1)

    def test_default_deny_binds_scope_before_any_provider_read(self):
        c = candidate()
        for change in (
            {"e2e_dedicated_driver_accepted": False},
            {"operations_accepted": True},
            {"model_inference_permitted": True},
            {"enabled_classes": ["e2e", "privileged"]},
            {"enabled_roles": ["isolation", "security"]},
            {"allowed_run_ids": [800, 801]},
            {"isolation_image_sha256": "sha256:" + "f"*64},
            {"isolation_workflow_sha256": "e"*64},
            {"isolation_harness_sha256": {}},
            {"rootless_nested_container_proven": False},
        ):
            with self.subTest(change=change):
                config = {**controls(c), **change}
                with patch.object(driver.legacy, "runner_job") as effect:
                    with self.assertRaises(Hold):
                        driver.execute(c, config, api=lambda _: self.fail("unauthorised GET"))
                    effect.assert_not_called()

    def test_other_e2e_and_other_classes_never_steal_isolation_driver(self):
        c = candidate()
        for change in (
            {"job_key": ".github/workflows/repair-containment-smoke.yml#containment-smoke"},
            {"job_class": "privileged"},
            {"event": "workflow_dispatch"},
            {"branch": "main"},
            {"label": "clawsweeper-ci-security-800-e2e"},
            {"attempt": 2},
        ):
            with self.subTest(change=change), patch.object(driver.legacy, "runner_job") as effect:
                with self.assertRaises(Hold):
                    driver.execute(candidate(**change), controls())
                effect.assert_not_called()

    def test_changed_job_or_run_not_registered(self):
        c = candidate()
        for drift in ("status", "sha", "pr"):
            api = provider(c)
            def altered(path):
                d = api(path)
                if drift == "status" and "/actions/jobs/" in path:
                    return {**d, "status": "in_progress"}
                if drift == "sha" and "/actions/runs/" in path:
                    return {**d, "head_sha": "e" * 40}
                if drift == "pr" and "/pulls/" in path:
                    return {**d, "head": {**d["head"], "sha": "e"*40}}
                return d
            with self.subTest(drift=drift), patch.object(driver.legacy, "runner_job") as effect:
                with self.assertRaises(Hold):
                    driver.execute(c, controls(c), api=altered)
                effect.assert_not_called()

    def test_true_legacy_classification_of_live_pr_isolation_then_fences_source(self):
        c = candidate()
        # No mocked classifier: confirms both real source policy layers agree
        # on the live PR-shaped objects before any POST.
        with (
            patch.object(driver.legacy, "category_enabled", return_value=True) as gate,
            patch.object(driver.legacy, "source_authorised",
                         side_effect=driver.legacy.AdmissionHold("synthetic_untrusted_source")) as source,
            patch.object(driver.legacy, "runner_job") as effect,
        ):
            with self.assertRaisesRegex(Hold, "e2e_legacy_admission_refused"):
                driver.execute(c, controls(c), api=provider(c))
            self.assertEqual(gate.call_count, 1)
            self.assertEqual(source.call_count, 1)
            lc = source.call_args.args[0]
            self.assertEqual((lc.role, lc.slot, lc.pr_number, lc.trusted_base_sha),
                             ("isolation", "e2e", 8, BASE))
            effect.assert_not_called()

    def test_success_requires_proven_28_files_provider_identity_and_cleanup(self):
        c = candidate()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            expected = root/"run-800-job-801-attempt-1"/"receipt.json"
            expected.parent.mkdir(mode=0o700)
            record = dict(
                state="passed", role="isolation", issues=[], runner_exit=0,
                run_id=800, job_id=801, attempt=1, head_sha=HEAD,
                image_sha256=IMAGE, label=c.label,
                runner_name="csw-ci-800-801-1", runner_id=3,
                log_sha256="a"*64,
                e2e_proof={"verdict": "INDEPENDENT_E2E_VAULT_PASS",
                           "cases": 28, "manifest_sha256": "b"*64,
                           "receipt_sha256": "c"*64},
            )
            log_path = expected.parent / "runner.log"
            log_path.write_bytes(b"bounded e2e worker output\n")
            log_path.chmod(0o600)
            record["log_bytes"] = log_path.stat().st_size
            record["log_sha256"] = hashlib.sha256(log_path.read_bytes()).hexdigest()
            expected.write_text(json.dumps(record))
            expected.chmod(0o600)
            lc = SimpleNamespace(
                role="isolation", slot="e2e", run_id=800, job_id=801,
                run_attempt=1, sha=c.sha, label=c.label,
                trusted_base_sha=BASE)
            with (
                patch.object(driver.legacy, "RECEIPTS", root),
                patch.object(driver.legacy, "classify", return_value=lc),
                patch.object(driver.legacy, "category_enabled", return_value=True) as legacy_policy,
                patch.object(driver.legacy, "source_authorised", return_value=True) as legacy_source,
                patch.object(driver.legacy, "approved_job_image", return_value=IMAGE),
                patch.object(driver.legacy, "runner_job", return_value={
                    "state": "passed", "receipt": str(expected)}) as effect,
                patch.object(driver.legacy, "runner_absent_verified", return_value=True) as gone,
                patch.object(driver.legacy, "inspect_owned", return_value=None),
            ):
                result = driver.execute(c, controls(c), api=provider(c))
                self.assertEqual(effect.call_count, 1)
                self.assertEqual(legacy_policy.call_count, 1)
                self.assertEqual(legacy_source.call_count, 1)
                self.assertEqual(gone.call_count, 1)
                self.assertTrue(result["github_terminal_verified"])
                self.assertTrue(result["all_scenarios_verified"])
                self.assertTrue(result["rootless_runtime_verified"])
                self.assertTrue(result["runner_absent_verified"])
                self.assertTrue(result["containers_absent_verified"])
                self.assertEqual(result["e2e_manifest_sha256"], "b"*64)
                self.assertEqual(result["log_sha256"], record["log_sha256"])
                # A green runner receipt cannot testify to its own log bytes.
                log_path.write_bytes(b"tampered" + b"!" * (record["log_bytes"] - 8))
                with self.assertRaisesRegex(driver.Hold, "e2e_runner_log_changed|e2e_runner_log_digest_mismatch"):
                    driver.execute(c, controls(c), api=provider(c))
                log_path.write_bytes(b"bounded e2e worker output\n")
                log_path.chmod(0o600)
                # Github's immutable assigned runner id is part of the proof.
                original_api = provider(c)
                def drift_runner(path):
                    value = original_api(path)
                    if path.endswith("/actions/jobs/801") and value.get("status") == "completed":
                        return {**value, "runner_id": 4}
                    return value
                self.assertFalse(driver.execute(c, controls(c), api=drift_runner)
                                 ["github_terminal_verified"])
                # The log cannot be replaced with a same-content symlink.
                log_path.unlink()
                alternate = root / "untrusted-log"
                alternate.write_bytes(b"bounded e2e worker output\n")
                log_path.symlink_to(alternate)
                with self.assertRaisesRegex(driver.Hold, "e2e_runner_log_unsafe"):
                    driver.execute(c, controls(c), api=provider(c))
                log_path.unlink()
                log_path.write_bytes(b"bounded e2e worker output\n")
                log_path.chmod(0o600)
                # Proof cannot mint a green result from a partial matrix.
                record["e2e_proof"]["cases"] = 27
                expected.write_text(json.dumps(record))
                expected.chmod(0o600)
                with self.assertRaisesRegex(Hold, "e2e_28_case_or_runner_receipt_invalid"):
                    driver.execute(c, controls(c), api=provider(c))
                # A symlink is not trusted even when it points at expected bytes.
                expected.unlink()
                target = root / "attacker-receipt"
                target.write_text(json.dumps(record))
                expected.symlink_to(target)
                with self.assertRaises(Hold):
                    driver.execute(c, controls(c), api=provider(c))

    def test_native_isolation_routing_is_fail_closed_when_unapproved(self):
        c=candidate()
        with patch.object(driver.legacy, "runner_job") as effect:
            with self.assertRaises(Hold):
                ctl.native_driver(c, {})
            effect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
