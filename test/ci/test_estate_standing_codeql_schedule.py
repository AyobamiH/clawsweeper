"""Safe automatic scheduled CodeQL; no provider side effects in tests."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from estate_policy import (AUTO_CODEQL_JOB, SAFE_AUTO_MODE, REPO, Hold,
                           admit, classify, load_manifest)
from estate_controller import verify_automatic_codeql_source

MANIFEST = load_manifest()
MAIN = "a" * 40
SOURCE = next(
    j for j in MANIFEST["jobs"]
    if j["workflow"] + "#" + j["id"] == AUTO_CODEQL_JOB
)
IMAGE = "b" * 64
RUN = 456789


def candidate(event="schedule", branch="main", sha=MAIN, attempt=1,
              language="actions", run_id=RUN):
    run = {
        "id": run_id, "run_attempt": attempt, "head_sha": sha,
        "head_branch": branch, "repository": {"full_name": REPO},
        "path": SOURCE["workflow"], "event": event,
        "actor": {"login": "AyobamiH", "id": 123},
    }
    label = f"clawsweeper-ci-security-{run_id}-{language}"
    job = {
        "id": run_id + 11, "run_id": run_id,
        "name": f"Analyze ({language})", "status": "queued",
        "labels": ["self-hosted", "Linux", "X64", label],
    }
    return classify(MANIFEST, run, job)


def controls(c, *, mode=SAFE_AUTO_MODE):
    approved = {
        "class": "codeql",
        "source_sha256": SOURCE["source_sha256"],
        "image_sha256": IMAGE,
        "standing_schedule": {
            "accepted": True,
            "main_sha": MAIN,
            "source_sha256": SOURCE["source_sha256"],
            "image_sha256": IMAGE,
            "languages": ["actions", "javascript-typescript"],
        },
    }
    return {
        "repo": REPO, "enabled": True, "allow_live_mutations": True,
        "operating_mode": mode, "enabled_classes": ["codeql"],
        "trusted_main_sha": MAIN,
        "operations_accepted": False,
        "model_inference_permitted": False,
        "codeql_sarif_accepted": True,
        "security_image_sha256": "sha256:" + IMAGE,
        "approved_jobs": {c.job_key: approved},
    }


class StandingCodeQLTests(unittest.TestCase):
    def test_both_natural_languages_auto_admit_only_on_trusted_main(self):
        for language in ("actions", "javascript-typescript"):
            with self.subTest(language=language):
                c = candidate(language=language)
                cfg = controls(c)
                self.assertTrue(admit(c, MANIFEST, cfg,
                                      source_sha256=SOURCE["source_sha256"]))
                calls = []
                def read(path):
                    calls.append(path)
                    if path.endswith("/git/ref/heads/main"):
                        return {"object": {"sha": MAIN}}
                    return {"sha": MAIN, "commit": {"verification": {
                        "verified": True, "reason": "valid"
                    }}}
                self.assertTrue(verify_automatic_codeql_source(
                    c, SOURCE, cfg, api=read))
                self.assertEqual(calls, [
                    f"repos/{REPO}/git/ref/heads/main",
                    f"repos/{REPO}/commits/{MAIN}",
                ])

    def test_inspect_distinguishes_configured_from_provider_verified(self):
        from estate_controller import inspect
        class EmptyLedger:
            def inspect(self):
                return {"attempts": {}}
        c = candidate()
        ctl = controls(c)
        report = inspect(MANIFEST, ctl, EmptyLedger())
        self.assertEqual(report["operating_mode"], SAFE_AUTO_MODE)
        self.assertTrue(report["standing_codeql_schedule_configured"])
        self.assertFalse(report["standing_codeql_schedule_live_verified"])
        ctl["enabled"] = False
        self.assertFalse(inspect(MANIFEST, ctl, EmptyLedger())[
            "standing_codeql_schedule_configured"])

    def test_changed_branch_event_retry_and_source_refuse_auto_admission(self):
        cases = [
            ("workflow_dispatch", "main", MAIN, 1, "sensitive_run_not_explicitly_pinned"),
            ("pull_request", "feature", MAIN, 1, "sensitive_run_not_explicitly_pinned"),
            ("schedule", "develop", MAIN, 1, "sensitive_run_not_explicitly_pinned"),
            ("schedule", "main", "f" * 40, 1, "sensitive_run_not_explicitly_pinned"),
            ("schedule", "main", MAIN, 2, "sensitive_run_not_explicitly_pinned"),
        ]
        for event, branch, sha, attempt, reason in cases:
            with self.subTest(event=event, branch=branch, sha=sha[:2], attempt=attempt):
                c = candidate(event=event, branch=branch, sha=sha, attempt=attempt)
                with self.assertRaisesRegex(Hold, reason):
                    admit(c, MANIFEST, controls(c),
                          source_sha256=SOURCE["source_sha256"])
        c = candidate()
        with self.assertRaisesRegex(Hold, "workflow_source_digest_mismatch"):
            admit(c, MANIFEST, controls(c), source_sha256="f" * 64)

    def test_missing_or_broadened_grants_fail_closed(self):
        c = candidate()
        examples = [
            lambda d: d.update(operating_mode=None),
            lambda d: d.update(enabled_classes=["codeql", "privileged"]),
            lambda d: d.update(operations_accepted=True),
            lambda d: d.update(model_inference_permitted=True),
            lambda d: d.update(codeql_sarif_accepted=False),
            lambda d: d.update(trusted_main_sha="f" * 40),
            lambda d: d.update(security_image_sha256="sha256:" + "f" * 64),
            lambda d: d["approved_jobs"][c.job_key].update(standing_schedule=None),
            lambda d: d["approved_jobs"][c.job_key]["standing_schedule"].update(accepted=False),
            lambda d: d["approved_jobs"][c.job_key]["standing_schedule"].update(
                source_sha256="f" * 64),
            lambda d: d["approved_jobs"][c.job_key]["standing_schedule"].update(
                languages=["actions"]),
            lambda d: d["approved_jobs"][c.job_key].update(image_sha256="f" * 64),
            lambda d: d["approved_jobs"][c.job_key].update(source_sha256="f" * 64),
            lambda d: d.update(enabled=False),
            lambda d: d.update(allow_live_mutations=False),
        ]
        for index, mutate in enumerate(examples):
            with self.subTest(i=index):
                ctrl = copy.deepcopy(controls(c))
                mutate(ctrl)
                with self.assertRaises(Hold):
                    admit(c, MANIFEST, ctrl, source_sha256=SOURCE["source_sha256"])

    def test_signed_source_must_be_independently_verified(self):
        c = candidate()
        cfg = controls(c)
        with self.assertRaisesRegex(Hold, "automatic_codeql_protected_main_drift"):
            verify_automatic_codeql_source(c, SOURCE, cfg,
                api=lambda _path: {"object": {"sha": "f" * 40}})
        for returned in (
            {"sha": MAIN, "commit": {"verification": {"verified": False, "reason": "valid"}}},
            {"sha": MAIN, "commit": {"verification": {"verified": True, "reason": "unknown"}}},
            {"sha": "f" * 40, "commit": {"verification": {"verified": True, "reason": "valid"}}},
            {},
        ):
            with self.subTest(returned=returned), self.assertRaisesRegex(
                    Hold, "automatic_codeql_main_signature_unverified"):
                verify_automatic_codeql_source(
                    c, SOURCE, cfg,
                    api=lambda path: ({"object": {"sha": MAIN}}
                                      if path.endswith("/git/ref/heads/main") else returned))
        with self.assertRaisesRegex(Hold, "automatic_codeql_main_signature_unavailable"):
            verify_automatic_codeql_source(c, SOURCE, cfg,
                api=lambda path: ({"object": {"sha": MAIN}}
                                  if path.endswith("/git/ref/heads/main") else
                                  (_ for _ in ()).throw(RuntimeError("unavailable"))))

    def test_manual_exact_attempt_remains_supported_without_auto_mode(self):
        c = candidate(event="workflow_dispatch")
        cfg = controls(c, mode=None)
        cfg["approved_jobs"][c.job_key].update({
            "run_ids": [c.run_id],
            "head_shas": [c.sha],
            "approved_attempts": [{
                "run_id": c.run_id, "job_id": c.job_id,
                "attempt": c.attempt, "head_sha": c.sha,
                "job_name": c.name,
            }],
        })
        self.assertTrue(admit(c, MANIFEST, cfg, source_sha256=SOURCE["source_sha256"]))
        self.assertFalse(verify_automatic_codeql_source(c, SOURCE, cfg,
            api=lambda _path: self.fail("manual approval must not request signature")))

    def test_sensitive_other_classes_do_not_inherit_codeql_standing_grant(self):
        other = next(j for j in MANIFEST["jobs"]
                     if j["workflow"] == ".github/workflows/dashboard-ci.yml"
                     and j["id"] == "refresh")
        run = {
            "id": RUN, "run_attempt": 1, "head_sha": MAIN,
            "head_branch": "main", "repository": {"full_name": REPO},
            "path": other["workflow"], "event": "schedule",
            "actor": {"login": "AyobamiH", "id": 123},
        }
        job = {
            "id": 98765, "run_id": RUN, "status": "queued",
            "name": other["display_name"],
            "labels": ["self-hosted", "Linux", "X64",
                       f"clawsweeper-ci-privileged-{RUN}-refresh"],
        }
        c = classify(MANIFEST, run, job)
        cfg = controls(c)
        cfg["enabled_classes"] = ["codeql", "privileged"]
        cfg["approved_jobs"] = {
            c.job_key: {"class": "privileged", "source_sha256": other["source_sha256"],
                        "standing_schedule": cfg["approved_jobs"][c.job_key]["standing_schedule"]}
        }
        with self.assertRaisesRegex(Hold, "sensitive_run_not_explicitly_pinned"):
            admit(c, MANIFEST, cfg, source_sha256=other["source_sha256"])


if __name__ == "__main__":
    unittest.main()
