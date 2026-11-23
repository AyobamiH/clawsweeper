"""Held CodeQL JIT may disable its own run scope, never replay a JIT POST."""
import io
import os
import subprocess
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as ex
from self_hosted_policy import Candidate, AdmissionHold

RUN, JOB = 123, 456
HEAD = "a" * 40
NAME = "csw-ci-123-456-1"
LABEL = "clawsweeper-ci-security-123-actions"
WORKFLOW = ".github/workflows/codeql.yml"


def candidate():
    return Candidate(RUN, JOB, 1, HEAD, WORKFLOW, "workflow_dispatch",
                     "security", "actions", LABEL, "Analyze (actions)", "main")


def active_scope():
    return {"repo": "AyobamiH/clawsweeper", "enabled": True,
            "enabled_roles": ["security"], "allowed_run_ids": [RUN],
            "allowed_branches": ["main"], "operations_accepted": False,
            "max_jobs_per_cycle": 1,
            "security_image_sha256": "sha256:" + "b" * 64}


class HeldNoIdScopeFence(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        receipts = root / "receipts"
        receipts.mkdir(mode=0o700)
        original = receipts / "run-123-job-456-attempt-1"
        original.mkdir(mode=0o700)
        payload = {
            "schema": "clawsweeper.selfhosted-jit.v1",
            "run_id": RUN, "job_id": JOB, "attempt": 1,
            "head_sha": HEAD, "role": "security", "workflow": WORKFLOW,
            "event": "workflow_dispatch", "label": LABEL, "runner_name": NAME,
            "image_sha256": "sha256:" + "b" * 64,
            "state": "held", "issues": ["execution_error_RuntimeError"],
            "uncertain_registration_absent": True,
            "finished_at": "2026-11-11T08:29:35Z",
        }
        ex.atomic(original / "receipt.json", payload)
        controls = root / "controls.json"
        ex.atomic(controls, active_scope())
        lock = root / "owner-codeql-acceptance.lock"
        lock.write_text("")
        lock.chmod(0o600)
        return receipts, controls, lock, original / "receipt.json"

    def context(self, receipts, controls, lock):
        return (patch.object(ex, "RECEIPTS", receipts),
                patch.object(ex, "CONTROLS", controls),
                patch.object(ex, "OWNER_CODEQL_LOCK", lock))

    def test_terminal_uncertain_failure_disarms_only_own_scope(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            original = rpath.read_bytes()
            with self.context(receipts, controls, lock)[0] as _, \
                 self.context(receipts, controls, lock)[1] as _, \
                 self.context(receipts, controls, lock)[2] as _, \
                 patch.object(ex, "gh") as gh, patch.object(ex, "runner_job") as runner:
                result = ex.disarm_security_after_held(candidate(), active_scope(), rpath)
            self.assertEqual(result["state"], "security_scope_disarmed")
            updated = json.loads(controls.read_text())
            self.assertFalse(updated["enabled"])
            self.assertFalse(updated["enabled_roles"])
            self.assertFalse(updated["allowed_run_ids"])
            self.assertFalse(updated["allowed_branches"])
            self.assertFalse(updated["operations_accepted"])
            self.assertEqual(updated["security_image_sha256"], active_scope()["security_image_sha256"])
            self.assertEqual(rpath.read_bytes(), original)
            self.assertTrue((rpath.parent / "held-scope-disarm-intent.json").is_file())
            self.assertTrue((rpath.parent / "held-scope-disarm-result.json").is_file())
            gh.assert_not_called()
            runner.assert_not_called()

    def test_wrong_scope_and_changed_controls_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            cases = [
                dict(active_scope(), allowed_run_ids=[999]),
                dict(active_scope(), operations_accepted=True),
                dict(active_scope(), enabled_roles=["security", "ops"]),
                dict(active_scope(), allowed_branches=["other"]),
            ]
            for scope in cases:
                with self.subTest(scope=scope), \
                     patch.object(ex, "RECEIPTS", receipts), \
                     patch.object(ex, "CONTROLS", controls), \
                     patch.object(ex, "OWNER_CODEQL_LOCK", lock):
                    with self.assertRaises((AdmissionHold, RuntimeError)):
                        ex.disarm_security_after_held(candidate(), scope, rpath)
                    self.assertEqual(json.loads(controls.read_text()), active_scope())
                    self.assertFalse((rpath.parent / "held-scope-disarm-intent.json").exists())

    def test_tampered_receipt_refused_before_scope_change(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            data = json.loads(rpath.read_text())
            data["job_id"] = 888
            ex.atomic(rpath, data)
            with patch.object(ex, "RECEIPTS", receipts), \
                 patch.object(ex, "CONTROLS", controls), \
                 patch.object(ex, "OWNER_CODEQL_LOCK", lock):
                with self.assertRaises((AdmissionHold, RuntimeError)):
                    ex.disarm_security_after_held(candidate(), active_scope(), rpath)
            self.assertTrue(json.loads(controls.read_text())["enabled"])

    def test_repeated_disarm_rejected_without_overwriting_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, rpath = self.fixture(td)
            with patch.object(ex, "RECEIPTS", receipts), \
                 patch.object(ex, "CONTROLS", controls), \
                 patch.object(ex, "OWNER_CODEQL_LOCK", lock):
                ex.disarm_security_after_held(candidate(), active_scope(), rpath)
                first = (rpath.parent / "held-scope-disarm-intent.json").read_bytes()
                with self.assertRaises((AdmissionHold, RuntimeError)):
                    ex.disarm_security_after_held(candidate(), active_scope(), rpath)
                self.assertEqual(first, (rpath.parent / "held-scope-disarm-intent.json").read_bytes())

    def test_failed_replacement_is_detected_without_new_registration(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, original = self.fixture(td)
            first = json.loads(original.read_text())
            first["state"] = "runner_started"
            first.pop("finished_at", None)
            first.pop("issues", None)
            ex.atomic(original, first)
            child = receipts / "run-123-job-456-attempt-1-replacement-1"
            child.mkdir(mode=0o700)
            second = dict(first, state="held",
                          runner_name=NAME + "-replacement-1",
                          issues=["execution_error_RuntimeError"],
                          finished_at="2026-11-11T08:44:00Z")
            ex.atomic(child / "receipt.json", second)
            with patch.object(ex, "RECEIPTS", receipts), patch.object(ex, "gh") as gh:
                seen = ex.existing_security_held_receipt(candidate())
            self.assertEqual(seen, child / "receipt.json")
            gh.assert_not_called()

    def test_symlinked_receipt_root_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, lock, original = self.fixture(td)
            link = Path(td) / "linked-receipts"
            link.symlink_to(receipts, target_is_directory=True)
            with patch.object(ex, "RECEIPTS", link):
                with self.assertRaisesRegex(AdmissionHold, "unsafe_prior_receipt_root"):
                    ex.existing_security_held_receipt(candidate())

    def test_main_prior_held_scope_never_registers_another_runner(self):
        with tempfile.TemporaryDirectory() as td:
            receipts, controls, owner_lock, receipt = self.fixture(td)
            root = Path(td)
            executor_lock = root / "executor.lock"
            executor_lock.write_text("")
            executor_lock.chmod(0o600)
            result = {"state": "security_scope_disarmed", "run_id": RUN}
            with patch.object(ex, "ROOT", root), \
                 patch.object(ex, "LOCK", executor_lock), \
                 patch.object(ex, "discover", return_value=[candidate()]), \
                 patch.object(ex, "load_controls", return_value=active_scope()), \
                 patch.object(ex, "category_enabled"), \
                 patch.object(ex, "source_authorised"), \
                 patch.object(ex, "existing_security_held_receipt", return_value=receipt), \
                 patch.object(ex, "disarm_security_after_held", return_value=result) as disarm, \
                 patch.object(ex, "runner_job") as runner, \
                 patch.object(sys, "argv", ["self_hosted_executor.py", "cycle"]), \
                 patch("sys.stdout", new_callable=io.StringIO) as stdout:
                ex.main()
            self.assertEqual(json.loads(stdout.getvalue())["state"], "security_scope_disarmed")
            disarm.assert_called_once()
            runner.assert_not_called()


class RegistrationFailureDiagnostics(unittest.TestCase):
    SECRET = "ghp_FIXTURE_NEVER_PERSIST_OR_PRINT"

    def fixture_run(self, *, stderr="", stdout="", code=1, network_failure=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            tools = root / "tools"
            tools.mkdir()
            calls = root / "calls.jsonl"
            gh = tools / "gh"
            gh.write_text("#!" + sys.executable + "\n"
                          "import sys,json\nfrom pathlib import Path\n"
                          f"p=Path({str(calls)!r})\n"
                          "with p.open('a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                          f"sys.stdout.write({stdout!r})\n"
                          f"sys.stderr.write({stderr!r})\n"
                          f"raise SystemExit({code})\n")
            gh.chmod(0o700)
            with ExitStack() as patches:
                patches.enter_context(patch.object(ex, "ROOT", root))
                patches.enter_context(patch.object(ex, "RECEIPTS", root / "receipts"))
                patches.enter_context(patch.dict(os.environ, {"PATH": str(tools) + os.pathsep + os.environ["PATH"]}))
                patches.enter_context(patch.object(ex, "approved_job_image", return_value="sha256:" + "b" * 64))
                patches.enter_context(patch.object(ex, "stop_owned"))
                patches.enter_context(patch.object(ex, "lookup_owned_runner", return_value=None))
                patches.enter_context(patch.object(ex, "runner_absent_verified"))
                network = patches.enter_context(patch.object(ex, "prepare_network", side_effect=network_failure))
                result = ex.runner_job(candidate(), active_scope())
            receipt = json.loads(Path(result["receipt"]).read_text())
            operations = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual(len(operations), 1)
            self.assertIn("POST", operations[0])
            self.assertEqual(receipt["state"], "held")
            self.assertNotIn(self.SECRET, json.dumps(receipt))
            self.assertNotIn(self.SECRET, json.dumps(result))
            if network_failure is None:
                network.assert_not_called()
            return receipt

    def test_http_failure_retains_only_numeric_status_and_phase(self):
        receipt = self.fixture_run(stderr=f"gh: denied credential {self.SECRET} (HTTP 403)\n")
        proof = receipt["failure_diagnostic"]
        self.assertEqual(proof["phase"], "registration_request")
        self.assertEqual(proof["code"], "external_command_refused")
        self.assertEqual(proof["http_status"], 403)
        self.assertEqual(proof["cli_exit_code"], 1)
        self.assertIsNone(proof["transport_hint"])
        self.assertFalse(proof["registration_replay_allowed"])
        self.assertIn("execution_error_RuntimeError", receipt["issues"])

    def test_transport_failure_is_observable_without_echoing_network_data(self):
        receipt = self.fixture_run(stderr=f'Post "https://secret.invalid/{self.SECRET}": connect: network is unreachable\n')
        proof = receipt["failure_diagnostic"]
        self.assertEqual(proof["transport_hint"], "network_unreachable")
        self.assertIsNone(proof["http_status"])
        self.assertFalse(proof["registration_replay_allowed"])

    def test_unknown_failure_does_not_invent_http_or_transport_cause(self):
        receipt = self.fixture_run(stderr=self.SECRET + " unrecognised error\n")
        proof = receipt["failure_diagnostic"]
        self.assertIsNone(proof["http_status"])
        self.assertIsNone(proof["transport_hint"])

    def test_malformed_json_success_response_never_leaks_payload(self):
        receipt = self.fixture_run(stdout=self.SECRET + " not json", code=0)
        self.assertEqual(receipt["failure_diagnostic"]["code"], "github_response_invalid")
        self.assertEqual(receipt["failure_diagnostic"]["phase"], "registration_request")
        self.assertIsNone(receipt["failure_diagnostic"]["http_status"])

    def test_incomplete_configuration_identifies_response_phase(self):
        receipt = self.fixture_run(stdout=json.dumps({"encoded_jit_config": self.SECRET}), code=0)
        self.assertEqual(receipt["failure_diagnostic"]["code"], "jit_registration_response_incomplete")
        self.assertEqual(receipt["failure_diagnostic"]["phase"], "registration_response")
        self.assertNotIn("runner_id", receipt)

    def test_network_preparation_failure_preserves_known_runner_identity(self):
        receipt = self.fixture_run(stdout=json.dumps({"runner": {"id": 99}, "encoded_jit_config": self.SECRET}),
                                   code=0, network_failure=RuntimeError(self.SECRET))
        self.assertEqual(receipt["runner_id"], 99)
        self.assertEqual(receipt["failure_diagnostic"]["phase"], "network_preparation")
        self.assertEqual(receipt["failure_diagnostic"]["code"], "unclassified_failure")
        self.assertFalse(receipt["failure_diagnostic"]["registration_replay_allowed"])

    def test_timeout_diagnostic_does_not_retain_exception_output(self):
        with patch.object(ex.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                ["gh", "api"], 30, output=self.SECRET, stderr=self.SECRET)):
            with self.assertRaises(RuntimeError) as held:
                ex.run_cli(["gh", "api", "--method", "POST", "untrusted"])
        proof = ex.execution_failure_diagnostic(held.exception, "registration_request")
        self.assertEqual(proof["code"], "command_timeout")
        self.assertEqual(proof["transport_hint"], "timeout")
        self.assertNotIn(self.SECRET, json.dumps(proof))

    def test_adversarial_metadata_cannot_enter_receipt(self):
        exc = RuntimeError(self.SECRET)
        exc.safe_cli_diagnostic = {"http_status": True, "cli_exit_code": "secret",
                                   "transport_hint": self.SECRET, "credential": self.SECRET}
        proof = ex.execution_failure_diagnostic(exc, "registration_request")
        self.assertIsNone(proof["http_status"])
        self.assertIsNone(proof["cli_exit_code"])
        self.assertIsNone(proof["transport_hint"])
        self.assertNotIn(self.SECRET, json.dumps(proof))
        self.assertNotIn("credential", proof)

    def test_output_bound_and_typed_fields_prevent_diagnostic_injection(self):
        exc = ex.cli_failure("external_command_refused", ["gh", "api"], returncode=True,
                             stderr="gh: old (HTTP 403)\n" + "x" * 9000)
        proof = ex.execution_failure_diagnostic(exc, [self.SECRET])
        self.assertIsNone(proof["http_status"])
        self.assertIsNone(proof["cli_exit_code"])
        self.assertEqual(proof["phase"], "unclassified")
        self.assertEqual(set(proof), {"schema", "phase", "code", "http_status",
                                     "cli_exit_code", "transport_hint", "registration_replay_allowed"})
        unrelated = ex.cli_failure("external_command_refused", ["docker", "inspect"],
                                   returncode=1, stderr="gh: fake (HTTP 403)")
        self.assertIsNone(ex.execution_failure_diagnostic(unrelated, "network_preparation")["http_status"])

    def test_diagnostic_receipt_still_disarms_once_without_replay(self):
        receipt = self.fixture_run(stderr=f"gh: refused {self.SECRET} (HTTP 422)\n")
        with tempfile.TemporaryDirectory() as td:
            helper = HeldNoIdScopeFence()
            receipts, controls, lock, original = helper.fixture(td)
            ex.atomic(original, receipt)
            before = original.read_bytes()
            with ExitStack() as patches:
                for context in helper.context(receipts, controls, lock):
                    patches.enter_context(context)
                gh = patches.enter_context(patch.object(ex, "gh"))
                result = ex.disarm_security_after_held(candidate(), active_scope(), original)
                self.assertEqual(result["state"], "security_scope_disarmed")
                self.assertFalse(json.loads(controls.read_text())["enabled"])
                self.assertEqual(original.read_bytes(), before)
                with self.assertRaises(AdmissionHold):
                    ex.disarm_security_after_held(candidate(), active_scope(), original)
                gh.assert_not_called()

    def test_embedded_status_text_without_gh_status_suffix_is_not_trusted(self):
        receipt = self.fixture_run(stderr=f"message says (HTTP 401) but ends with {self.SECRET}\n")
        self.assertIsNone(receipt["failure_diagnostic"]["http_status"])



if __name__ == "__main__":
    unittest.main()
