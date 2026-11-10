"""Offline adversarial coverage for all six ClawSweeper execution classes."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts" / "ci"))
from estate_policy import load_manifest, classify, admit, job_class, Hold, REPO, OVERRIDES

SHA = "a" * 40
MANIFEST = load_manifest()


def entry(path, job_id):
    return next(j for j in MANIFEST["jobs"] if j["workflow"] == path and j["id"] == job_id)


def runner(path, job_id, *, event="workflow_dispatch", branch="main", run_id=54321):
    item = entry(path, job_id)
    cls = job_class(item)
    run = {"id": run_id, "run_attempt": 1, "head_sha": SHA, "head_branch": branch,
           "repository": {"full_name": REPO}, "path": path, "event": event,
           "actor": {"login": "AyobamiH", "id": 12345}}
    label = f"clawsweeper-ci-{cls}-{run_id}-{job_id}"
    if path == ".github/workflows/ci.yml" and job_id in ("check", "sparse-repair-builds"):
        label = f"clawsweeper-ci-validation-{run_id}-" + (
            "check" if job_id == "check" else "sparse")
    job_name = item["display_name"]
    if cls == "codeql":
        job_name = "Analyze (actions)"
        label = f"clawsweeper-ci-security-{run_id}-actions"
    job = {"id": 34567, "run_id": run_id, "name": job_name,
           "status": "queued", "labels": ["self-hosted", "Linux", "X64", label]}
    return item, run, job


def permit(candidate, item, **kwargs):
    approved = {
        "class": candidate.job_class, "source_sha256": item["source_sha256"],
        "run_ids": [candidate.run_id], "head_shas": [candidate.sha],
        "approved_attempts": [{
            "run_id": candidate.run_id, "job_id": candidate.job_id,
            "attempt": candidate.attempt, "head_sha": candidate.sha,
            "job_name": candidate.name
        }],
        "tokens": "read-only", "egress_policy": "public-egress-private-denied",
        "idempotent_effect_recovery": True,
        "verified_event_actors": {
            candidate.event: {"login": "AyobamiH", "id": 12345}
        },
        "complete_changed_source": True,
        "image_sha256": "a" * 64,
        "no_host_docker_socket": True, "full_scenarios": True,
        "windows_isolation": True, "native_tests": True,
    }
    controls = {
        "enabled": True, "repo": REPO, "enabled_classes": [candidate.job_class],
        "approved_jobs": {candidate.job_key: approved}, "trusted_main_sha": SHA,
        "untrusted_isolation_verified": True, "runner_network_isolation_verified": True, "operations_accepted": True,
        "review_source_verified": True, "model_inference_permitted": True,
        "codeql_sarif_accepted": True, "rootless_nested_container_proven": True,
        "native_windows_runner_proven": True,
    }
    controls.update(kwargs)
    return controls


class ManifestPolicy(unittest.TestCase):
    def test_unreviewed_hosted_fallback_refuses_every_release_manifest(self):
        import tempfile
        unsafe = copy.deepcopy(MANIFEST)
        unsafe["summary"]["dynamic_hosted_fallback"] = 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "estate.json"
            path.write_text(json.dumps(unsafe))
            with self.assertRaisesRegex(Hold, "github_hosted_execution_still_present"):
                load_manifest(path)
        unsafe = copy.deepcopy(MANIFEST)
        unsafe["jobs"][0]["runs_on"] = "ubuntu-latest"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "estate.json"
            path.write_text(json.dumps(unsafe))
            with self.assertRaisesRegex(Hold, "hosted_runner_fallback_not_migrated"):
                load_manifest(path)

    def test_exact_source_and_no_silent_new_critical_job(self):
        self.assertEqual(MANIFEST["summary"]["jobs"], len(MANIFEST["jobs"]))
        self.assertEqual(MANIFEST["summary"]["workflows"], len(MANIFEST["sources"]))
        self.assertEqual(len(OVERRIDES), len(set(OVERRIDES)))
        for key in OVERRIDES:
            self.assertEqual(len([j for j in MANIFEST["jobs"] if j["workflow"] + "#" + j["id"] == key]), 1)

    def test_each_class_is_explicit_and_other_jobs_are_privileged(self):
        classes = {job_class(j) for j in MANIFEST["jobs"]}
        self.assertEqual(classes, {"ordinary", "privileged", "review", "codeql", "e2e", "windows"})
        self.assertEqual(job_class(entry(".github/workflows/sweep.yml", "event-review-apply")), "privileged")
        self.assertEqual(job_class(entry(".github/workflows/ci.yml", "check")), "ordinary")
        self.assertEqual(job_class(entry(".github/workflows/codeql.yml", "analyze")), "codeql")

    def test_readonly_checks_admit_in_verified_container(self):
        item, run, job = runner(".github/workflows/ci.yml", "check", event="pull_request", branch="test")
        candidate = classify(MANIFEST, run, job)
        controls = permit(candidate, item)
        self.assertTrue(admit(candidate, MANIFEST, controls, source_sha256=item["source_sha256"]))
        for field, value, err in [
            ("enabled", False, "estate_controller_disabled"),
            ("untrusted_isolation_verified", False, "untrusted_runner_isolation_not_proven"),
        ]:
            with self.subTest(field=field), self.assertRaisesRegex(Hold, err):
                admit(candidate, MANIFEST, {**controls, field: value}, source_sha256=item["source_sha256"])
        with self.assertRaisesRegex(Hold, "untrusted_permissions_not_bounded"):
            altered = copy.deepcopy(controls)
            altered["approved_jobs"][candidate.job_key]["tokens"] = "write"
            admit(candidate, MANIFEST, altered, source_sha256=item["source_sha256"])

    def test_invalid_github_job_or_run_refused(self):
        item, run, job = runner(".github/workflows/ci.yml", "check", event="pull_request")
        mutations = [
            ({**run, "repository": {"full_name": "attacker/other"}}, job, "foreign_repository"),
            ({**run, "run_attempt": True}, job, "invalid_job_identity"),
            ({**run, "head_sha": "0" * 39}, job, "unverifiable_head_sha"),
            (run, {**job, "status": "completed"}, "job_not_queued"),
            (run, {**job, "labels": ["self-hosted"]}, "run_bound_runner_label_missing"),
            (run, {**job, "labels": job["labels"] + [job["labels"][-1]]}, "duplicate_runner_label"),
            (run, {**job, "name": "Another job"}, "workflow_job_not_in_manifest"),
            (run, {**job, "run_id": 1}, "job_run_identity_mismatch"),
        ]
        for r, j, reason in mutations:
            with self.subTest(reason=reason), self.assertRaisesRegex(Hold, reason):
                classify(MANIFEST, r, j)
        c = classify(MANIFEST, run, job)
        with self.assertRaisesRegex(Hold, "workflow_source_digest_mismatch"):
            admit(c, MANIFEST, permit(c, item), source_sha256="b" * 64)

    def test_privileged_operations_requires_main_owner_authority_and_recovery(self):
        item, run, job = runner(".github/workflows/dashboard-ci.yml", "refresh")
        c = classify(MANIFEST, run, job)
        controls = permit(c, item)
        self.assertEqual(c.job_class, "privileged")
        self.assertTrue(admit(c, MANIFEST, controls, source_sha256=item["source_sha256"]))
        for changed, reason in [
            ({"operations_accepted": False}, "privileged_operations_not_accepted"),
            ({"trusted_main_sha": "b" * 40}, "privileged_source_not_exact_main"),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(Hold, reason):
                admit(c, MANIFEST, {**controls, **changed}, source_sha256=item["source_sha256"])
        changed = copy.deepcopy(controls)
        changed["approved_jobs"][c.job_key]["idempotent_effect_recovery"] = False
        with self.assertRaisesRegex(Hold, "external_effect_recovery_not_proven"):
            admit(c, MANIFEST, changed, source_sha256=item["source_sha256"])
        # A PR cannot obtain a privileged admission merely by matching the actor.
        item2, run2, job2 = runner(".github/workflows/dashboard-ci.yml", "refresh", event="pull_request")
        with self.assertRaisesRegex(Hold, "unapproved_workflow_event"):
            classify(MANIFEST, run2, job2)

    def test_source_review_keeps_inference_default_denied(self):
        item, run, job = runner(".github/workflows/workers-ai-fallback-acceptance.yml",
                                "release-source-review")
        c = classify(MANIFEST, run, job)
        controls = permit(c, item, model_inference_permitted=False)
        with self.assertRaisesRegex(Hold, "review_inference_not_authorised"):
            admit(c, MANIFEST, controls, source_sha256=item["source_sha256"])
        controls["model_inference_permitted"] = True
        self.assertTrue(admit(c, MANIFEST, controls, source_sha256=item["source_sha256"]))
        controls["review_source_verified"] = False
        with self.assertRaisesRegex(Hold, "review_source_not_independently_verified"):
            admit(c, MANIFEST, controls, source_sha256=item["source_sha256"])

    def test_codeql_two_languages_preserve_actual_registered_labels(self):
        item, run, job = runner(".github/workflows/codeql.yml", "analyze", event="pull_request", branch="feature")
        for language in ("actions", "javascript-typescript"):
            with self.subTest(language=language):
                job["name"] = "Analyze (" + language + ")"
                job["labels"][-1] = "clawsweeper-ci-security-54321-" + language
                c = classify(MANIFEST, run, job)
                self.assertEqual(c.job_class, "codeql")
                self.assertTrue(admit(c, MANIFEST, permit(c, item), source_sha256=item["source_sha256"]))
                with self.assertRaisesRegex(Hold, "codeql_admission_not_accepted"):
                    admit(c, MANIFEST, permit(c, item, codeql_sarif_accepted=False),
                          source_sha256=item["source_sha256"])
        job["name"] = "Analyze (unlisted-language)"
        with self.assertRaisesRegex(Hold, "workflow_job_not_in_manifest"):
            classify(MANIFEST, run, job)

    def test_rootless_e2e_and_native_windows_are_strictly_separate(self):
        for path, job_id, opt, failure in [
            (".github/workflows/automerge-e2e.yml", "automerge-e2e",
             "rootless_nested_container_proven", "nested_container_isolation_not_proven"),
            (".github/workflows/ci.yml", "windows-codex-launch",
             "native_windows_runner_proven", "native_windows_runner_unavailable"),
        ]:
            item, run, job = runner(path, job_id)
            c = classify(MANIFEST, run, job)
            expected_host = "windows" if c.job_class == "windows" else "linux"
            controls = permit(c, item)
            with self.subTest(cls=c.job_class), self.assertRaisesRegex(Hold, failure):
                admit(c, MANIFEST, permit(c, item, **{opt: False}),
                      source_sha256=item["source_sha256"], host_platform=expected_host)
            self.assertTrue(admit(c, MANIFEST, controls,
                                  source_sha256=item["source_sha256"], host_platform=expected_host))
            if c.job_class == "windows":
                with self.assertRaisesRegex(Hold, "native_windows_runner_unavailable"):
                    admit(c, MANIFEST, controls, source_sha256=item["source_sha256"],
                          host_platform="linux")

    def test_every_class_requires_immutable_explicit_job_and_run(self):
        targets = [
            (".github/workflows/ci.yml", "check"),
            (".github/workflows/dashboard-ci.yml", "refresh"),
            (".github/workflows/workers-ai-fallback-acceptance.yml", "release-source-review"),
            (".github/workflows/codeql.yml", "analyze"),
            (".github/workflows/automerge-e2e.yml", "automerge-e2e"),
            (".github/workflows/ci.yml", "windows-codex-launch"),
        ]
        for path, job_id in targets:
            item, run, job = runner(path, job_id)
            c = classify(MANIFEST, run, job)
            controls = permit(c, item)
            with self.subTest(job=job_id):
                controls["approved_jobs"] = {}
                with self.assertRaisesRegex(Hold, "job_not_explicitly_approved"):
                    admit(c, MANIFEST, controls, source_sha256=item["source_sha256"])
                controls = permit(c, item)
                controls["approved_jobs"][c.job_key]["source_sha256"] = "b" * 64
                with self.assertRaisesRegex(Hold, "workflow_source_digest_mismatch"):
                    admit(c, MANIFEST, controls, source_sha256=item["source_sha256"])
