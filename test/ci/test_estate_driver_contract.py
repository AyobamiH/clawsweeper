"""P1 regression: only exact-digest CodeQL may enter the legacy security JIT.

Every external interface is mocked. There is no GitHub, Docker or registration.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import estate_controller as ctl
from estate_policy import Hold


def candidate(role="codeql"):
    return SimpleNamespace(
        job_class=role, job_key=".github/workflows/codeql.yml#analyze",
        run_id=423001, job_id=124001, attempt=1,
        sha="a" * 40, workflow=".github/workflows/codeql.yml",
        event="pull_request", label="clawsweeper-ci-security-423001-actions",
    )


def config(digest="b" * 64):
    return {
        "approved_jobs": {
            candidate().job_key: {
                "class": "codeql", "image_sha256": digest,
            }
        },
        "security_image_sha256": "sha256:" + digest,
    }


class P1DriverBoundary(unittest.TestCase):
    def test_no_generic_ops_executor_for_any_non_codeql_class(self):
        for role in ("privileged", "review", "ordinary", "windows", "e2e"):
            with (
                self.subTest(role=role),
                patch.object(ctl.existing, "runner_job") as registration,
                patch.object(ctl.existing, "approved_job_image") as image_lookup,
                patch.object(ctl, "git_api") as gh,
            ):
                with self.assertRaisesRegex(Hold, "dedicated_class_driver_not_accepted"):
                    ctl.native_driver(candidate(role), config())
                registration.assert_not_called()
                image_lookup.assert_not_called()
                gh.assert_not_called()

    def test_missing_approval_and_wrong_class_are_fail_closed(self):
        for controls in (
            {},
            {"approved_jobs": {}},
            {"approved_jobs": {candidate().job_key: {"class": "privileged", "image_sha256": "b"*64}}},
        ):
            with self.subTest(controls=controls), patch.object(
                ctl.existing, "runner_job"
            ) as register:
                with self.assertRaisesRegex(Hold, "codeql_job_approval_missing"):
                    ctl.native_driver(candidate(), controls)
                register.assert_not_called()

    def test_approved_digest_control_mismatch_and_local_image_drift_refuse_pre_post(self):
        for controls, reason in (
            ({**config(), "security_image_sha256": "sha256:" + "c"*64}, "codeql_image_control_mismatch"),
            ({**config(), "approved_jobs": {candidate().job_key: {
                "class": "codeql", "image_sha256": "bad"
            }}}, "codeql_image_digest_unverifiable"),
        ):
            with self.subTest(reason=reason), patch.object(ctl.existing, "runner_job") as post:
                with self.assertRaisesRegex(Hold, reason):
                    ctl.native_driver(candidate(), controls)
                post.assert_not_called()
        with (
            patch.object(ctl.existing, "runner_job") as post,
            patch.object(ctl.existing, "approved_job_image", return_value="sha256:" + "c"*64)
        ):
            with self.assertRaisesRegex(Hold, "codeql_image_inspection_mismatch"):
                ctl.native_driver(candidate(), config())
            post.assert_not_called()

    def test_held_runner_result_never_claims_success(self):
        with (
            patch.object(ctl.existing, "approved_job_image", return_value="sha256:"+"b"*64),
            patch.object(ctl.existing, "runner_job", return_value={"state": "held"}) as post,
            patch.object(ctl, "git_api") as gh
        ):
            with self.assertRaisesRegex(Hold, "codeql_jit_result_unverified"):
                ctl.native_driver(candidate(), config())
            self.assertEqual(post.call_count, 1)
            gh.assert_not_called()

    def test_positive_mock_receipt_still_does_not_claim_sarif(self):
        c=candidate()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"receipt.json"
            path.write_text(json.dumps({
                "runner_name":"csw-ci-423001-124001-1", "runner_id":99,
                "image_sha256":"sha256:"+"b"*64, "head_sha":c.sha,
                "run_id":c.run_id,"job_id":c.job_id,"attempt":c.attempt,
                "state":"passed","issues":[],"log_sha256":"d"*64,
            }))
            job={"id":c.job_id,"run_id":c.run_id,"status":"completed",
                 "runner_name":"csw-ci-423001-124001-1","conclusion":"success"}
            with (
                patch.object(ctl.existing, "approved_job_image", return_value="sha256:"+"b"*64),
                patch.object(ctl.existing, "runner_job", return_value={
                    "state":"passed","receipt":str(path),
                }),
                patch.object(ctl, "git_api", return_value=job),
                patch.object(ctl.existing, "runner_absent_verified", return_value=True),
                patch.object(ctl.existing, "inspect_owned", return_value=None),
            ):
                outcome=ctl.native_driver(c,config())
            self.assertTrue(outcome["github_terminal_verified"])
            self.assertTrue(outcome["runner_absent_verified"])
            self.assertTrue(outcome["containers_absent_verified"])
            self.assertFalse(outcome["sarif_upload_verified"])
            self.assertEqual(outcome["log_sha256"], "d"*64)

    def test_image_mismatch_in_receipt_cannot_claim_validity(self):
        c=candidate()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"receipt.json"
            path.write_text(json.dumps({
                "runner_name":"csw-ci-423001-124001-1","runner_id":99,
                "image_sha256":"sha256:"+"c"*64,"head_sha":c.sha,
                "run_id":c.run_id,"job_id":c.job_id,"attempt":c.attempt,
                "state":"passed","issues":[],
            }))
            with (
                patch.object(ctl.existing, "approved_job_image", return_value="sha256:"+"b"*64),
                patch.object(ctl.existing, "runner_job", return_value={"state":"passed","receipt":str(path)}),
                patch.object(ctl, "git_api") as api
            ):
                with self.assertRaisesRegex(Hold, "codeql_jit_receipt_identity_mismatch"):
                    ctl.native_driver(c,config())
                api.assert_not_called()


if __name__ == "__main__":
    unittest.main()

