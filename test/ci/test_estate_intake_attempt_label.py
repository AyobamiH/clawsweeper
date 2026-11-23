"""Bind privileged intake classification to the real workflow attempt guard.

Offline admission proof only: no runner registration, inference or provider effects.
"""
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
from estate_policy import Hold, REPO, admit, classify, load_manifest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/repair-issue-implementation-intake.yml"
KEY = WORKFLOW + "#intake"
SHA = "a" * 40
MANIFEST = load_manifest()
ENTRY = next(j for j in MANIFEST["jobs"] if j["workflow"] == WORKFLOW and j["id"] == "intake")


def workflow_label(run_id, attempt):
    """Use the actual source guard, not a separately invented expected label."""
    text = (ROOT / WORKFLOW).read_text()
    matches = re.findall(
        r"vars\.CLAWSWEEPER_ISSUE_IMPLEMENTATION_INTAKE_RUNNER == "
        r"format\('([^']+)', github\.run_id, github\.run_attempt\)", text)
    if len(matches) != 1:
        raise AssertionError("missing or ambiguous run-and-attempt intake guard")
    return matches[0].format(run_id, attempt)


def inputs(*, attempt=1, label=None, event="workflow_dispatch"):
    run = {"id": 54321, "run_attempt": attempt, "head_sha": SHA,
           "head_branch": "main", "repository": {"full_name": REPO},
           "path": WORKFLOW, "event": event,
           "actor": {"login": "AyobamiH", "id": 12345}}
    requested = ENTRY["runs_on"]
    if not isinstance(requested, list):
        requested = [requested]
    resolved = workflow_label(54321, attempt) if label is None else label
    labels = [resolved if "${{" in value else value for value in requested]
    job = {"id": 34567, "run_id": 54321, "name": "intake", "status": "queued",
           "labels": labels}
    return run, job


def approved(candidate):
    # Synthetic proof of pure policy; never written to live owner controls.
    return {"enabled": True, "repo": REPO, "enabled_classes": ["privileged"],
            "trusted_main_sha": SHA, "operations_accepted": True,
            "approved_jobs": {KEY: {
                "class": "privileged", "source_sha256": ENTRY["source_sha256"],
                "run_ids": [candidate.run_id], "head_shas": [candidate.sha],
                "approved_attempts": [{"run_id": candidate.run_id,
                    "job_id": candidate.job_id, "attempt": candidate.attempt,
                    "head_sha": candidate.sha, "job_name": candidate.name}],
                "verified_event_actors": {candidate.event: {"login": "AyobamiH", "id": 12345}},
                "idempotent_effect_recovery": True}}}


class IntakeAttemptLabels(unittest.TestCase):
    def test_workflow_selector_declares_owner_platform_labels(self):
        self.assertIsInstance(ENTRY["runs_on"], list)
        self.assertEqual(ENTRY["runs_on"][:3], ["self-hosted", "Linux", "X64"])
        self.assertEqual(len(ENTRY["runs_on"]), 4)
        self.assertIn("vars.CLAWSWEEPER_ISSUE_IMPLEMENTATION_INTAKE_RUNNER", ENTRY["runs_on"][3])
        self.assertNotIn("client_payload", ENTRY["runs_on"][3])

    def test_current_workflow_guard_classifies_each_exact_attempt(self):
        for attempt in (1, 2, 17):
            with self.subTest(attempt=attempt):
                run, job = inputs(attempt=attempt)
                c = classify(MANIFEST, run, job)
                self.assertEqual(c.label, workflow_label(54321, attempt))
                self.assertEqual((c.job_key, c.job_class, c.attempt), (KEY, "privileged", attempt))

    def test_stale_unscoped_or_foreign_label_never_classifies(self):
        labels = [workflow_label(54321, 1), workflow_label(54322, 2),
                  "clawsweeper-ci-privileged-54321-intake", "ubuntu-latest",
                  "clawsweeper-unprovisioned-runner-held", "clawsweeper-ci-privileged-54321-2-other"]
        for label in labels:
            with self.subTest(label=label), self.assertRaisesRegex(Hold, "run_bound_runner_label_missing"):
                classify(MANIFEST, *inputs(attempt=2, label=label))

    def test_duplicate_correct_label_remains_rejected(self):
        run, job = inputs(attempt=2)
        job["labels"].append(job["labels"][-1])
        with self.assertRaisesRegex(Hold, "duplicate_runner_label"):
            classify(MANIFEST, run, job)

    def test_owner_pinned_attempt_can_pass_pure_policy(self):
        c = classify(MANIFEST, *inputs(attempt=2))
        self.assertTrue(admit(c, MANIFEST, approved(c), source_sha256=ENTRY["source_sha256"]))

    def test_label_does_not_replace_exact_attempt_approval(self):
        c = classify(MANIFEST, *inputs(attempt=2))
        controls = approved(c)
        controls["approved_jobs"][KEY]["approved_attempts"][0]["attempt"] = 1
        with self.assertRaisesRegex(Hold, "sensitive_attempt_not_explicitly_pinned"):
            admit(c, MANIFEST, controls, source_sha256=ENTRY["source_sha256"])

    def test_default_denial_and_event_adapter_gates_remain(self):
        c = classify(MANIFEST, *inputs(attempt=2))
        for field, value, reason in (("enabled", False, "estate_controller_disabled"),
                ("operations_accepted", False, "privileged_operations_not_accepted")):
            controls = approved(c)
            controls[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(Hold, reason):
                admit(c, MANIFEST, controls, source_sha256=ENTRY["source_sha256"])
        dispatched = classify(MANIFEST, *inputs(event="repository_dispatch"))
        with self.assertRaisesRegex(Hold, "privileged_event_adapter_not_accepted"):
            admit(dispatched, MANIFEST, approved(dispatched), source_sha256=ENTRY["source_sha256"])

    def test_unrelated_intake_job_keeps_its_existing_label(self):
        other = next(j for j in MANIFEST["jobs"] if j["id"] == "intake" and j["workflow"] != WORKFLOW)
        run, job = inputs(attempt=2)
        run["path"] = other["workflow"]
        run["event"] = other["events"][0]
        job["name"] = other["display_name"]
        job["labels"][-1] = "clawsweeper-ci-privileged-54321-intake"
        c = classify(MANIFEST, run, job)
        self.assertEqual(c.label, job["labels"][-1])
        self.assertNotEqual(c.job_key, KEY)


if __name__ == "__main__":
    unittest.main()
