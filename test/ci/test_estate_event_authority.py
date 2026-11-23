"""Privileged GitHub event authority is bound to the actual run actor.

No Github requests, runner registrations, model inference or external effects.
"""
from dataclasses import replace
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "ci"))
from estate_policy import Hold, classify, admit, load_manifest, REPO

MANIFEST = load_manifest()
SHA = "a" * 40


def make_candidate(workflow, job_id, *, event, actor=None, payload=None):
    item = next(j for j in MANIFEST["jobs"] if j["workflow"] == workflow and j["id"] == job_id)
    job = {
        "id": 45678, "run_id": 34567, "status": "queued",
        "name": item["display_name"],
        "labels": ["self-hosted", "Linux", "X64",
                   f"clawsweeper-ci-privileged-34567-{job_id}"],
    }
    run = {
        "id": 34567, "run_attempt": 1, "head_sha": SHA,
        "head_branch": "main", "repository": {"full_name": REPO},
        "path": workflow, "event": event,
    }
    if actor is not None:
        run["actor"] = actor
    if payload is not None:
        run["client_payload"] = payload
    return item, classify(MANIFEST, run, job)


def approved(candidate, entry, **overrides):
    config = {
        "enabled": True, "operations_accepted": True,
        "repo": REPO, "enabled_classes": ["privileged"],
        "trusted_main_sha": SHA,
        "approved_jobs": {candidate.job_key: {
            "class": "privileged",
            "source_sha256": entry["source_sha256"],
            "run_ids": [candidate.run_id],
            "head_shas": [candidate.sha],
            "approved_attempts": [{
                "run_id": candidate.run_id,
                "job_id": candidate.job_id,
                "attempt": candidate.attempt,
                "head_sha": candidate.sha,
                "job_name": candidate.name,
            }],
            "idempotent_effect_recovery": True,
            "verified_event_actors": {
                candidate.event: {"login": "AyobamiH", "id": 12345}
            },
        }},
    }
    config.update(overrides)
    return config


class PrivilegedEventAuthority(unittest.TestCase):
    def test_pinned_run_actor_and_immutable_workflow_can_admit(self):
        for event in ("workflow_dispatch", "schedule"):
            item, c = make_candidate(".github/workflows/dashboard-ci.yml", "refresh",
                event=event, actor={"login": "AyobamiH", "id": 12345})
            self.assertEqual(c.actor_login, "AyobamiH")
            self.assertEqual(c.actor_id, 12345)
            self.assertTrue(admit(c, MANIFEST, approved(c, item),
                source_sha256=item["source_sha256"]))

    def test_absent_actor_cannot_be_substituted_from_event_payload(self):
        for missing in (None, {"login": "AyobamiH"}, {"id": 12345},
                        {"login": "AyobamiH", "id": True}):
            with self.subTest(missing=missing):
                item, c = make_candidate(".github/workflows/dashboard-ci.yml", "refresh",
                    event="workflow_dispatch", actor=missing,
                    payload={"actor": {"login": "AyobamiH", "id": 12345}})
                with self.assertRaisesRegex(Hold, "privileged_event_actor_identity_mismatch"):
                    admit(c, MANIFEST, approved(c, item),
                        source_sha256=item["source_sha256"])

    def test_owner_login_and_id_are_both_mandatory(self):
        item, c = make_candidate(".github/workflows/dashboard-ci.yml", "refresh",
            event="workflow_dispatch", actor={"login": "AyobamiH", "id": 12345})
        for changed in (
            replace(c, actor_login="another-user"),
            replace(c, actor_login="ayobamih"),
            replace(c, actor_id=12346),
            replace(c, actor_id=None),
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                Hold, "privileged_event_actor_identity_mismatch"):
                admit(changed, MANIFEST, approved(c, item),
                      source_sha256=item["source_sha256"])

    def test_missing_or_malformed_owner_event_contract_is_not_accepted(self):
        item, c = make_candidate(".github/workflows/dashboard-ci.yml", "refresh",
            event="workflow_dispatch", actor={"login": "AyobamiH", "id": 12345})
        for invalid in (None, {}, {"workflow_dispatch": {}},
                        {"workflow_dispatch": {"login": "AyobamiH", "id": True}},
                        {"workflow_dispatch": {"login": "AyobamiH", "id": "12345"}},
                        {"schedule": {"login": "AyobamiH", "id": 12345}}):
            controls = approved(c, item)
            controls["approved_jobs"][c.job_key]["verified_event_actors"] = invalid
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                Hold, "privileged_event_actor_not_pinned"):
                admit(c, MANIFEST, controls,
                      source_sha256=item["source_sha256"])

    def test_github_activity_external_events_hold_even_for_owner_actor(self):
        for event in (
            "issues", "issue_comment", "repository_dispatch", "workflow_run",
            "pull_request_target", "pull_request_review", "pull_request_review_comment",
        ):
            item, c = make_candidate(".github/workflows/github-activity.yml", "notify",
                event=event, actor={"login": "AyobamiH", "id": 12345})
            reason = ("privileged_pr_event_denied" if event.startswith("pull_request")
                      else "privileged_event_adapter_not_accepted")
            with self.subTest(event=event), self.assertRaisesRegex(Hold, reason):
                admit(c, MANIFEST, approved(c, item),
                      source_sha256=item["source_sha256"])

    def test_actor_pinning_does_not_substitute_for_source_pin_or_recovery(self):
        item, c = make_candidate(".github/workflows/dashboard-ci.yml", "refresh",
            event="workflow_dispatch", actor={"login": "AyobamiH", "id": 12345})
        config = approved(c, item)
        config["approved_jobs"][c.job_key]["idempotent_effect_recovery"] = False
        with self.assertRaisesRegex(Hold, "external_effect_recovery_not_proven"):
            admit(c, MANIFEST, config, source_sha256=item["source_sha256"])
        config = approved(c, item, trusted_main_sha="b"*40)
        with self.assertRaisesRegex(Hold, "privileged_source_not_exact_main"):
            admit(c, MANIFEST, config, source_sha256=item["source_sha256"])
        config = approved(c, item)
        with self.assertRaisesRegex(Hold, "workflow_source_digest_mismatch"):
            admit(c, MANIFEST, config, source_sha256="b"*64)


if __name__ == "__main__":
    unittest.main()
