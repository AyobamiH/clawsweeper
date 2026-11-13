"""Cross-lane integration regression; external runner and provider calls are fakes.

Exercise the merged lifecycle with real private receipt/vault files. This is not
provider-backed E2E acceptance and never contacts GitHub, Docker or systemd.
"""
from contextlib import ExitStack
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as executor
from self_hosted_policy import Candidate

IMAGE = "sha256:" + "a" * 64
HEAD = "b" * 40
MERGE = "c" * 40


def candidate(role):
    is_e2e = role == "isolation"
    return Candidate(123, 456, 1, HEAD,
                     ".github/workflows/automerge-e2e.yml" if is_e2e else ".github/workflows/codeql.yml",
                     "pull_request", role, "e2e" if is_e2e else "actions",
                     "clawsweeper-ci-" + role + "-123-" + ("e2e" if is_e2e else "actions"),
                     "production automerge flow" if is_e2e else "Analyze (actions)",
                     "owner-branch", "d" * 40, 101)


class FakeProcess:
    def __init__(self):
        self.stdin = io.StringIO()

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0


class ControllerLaneCompositionTests(unittest.TestCase):
    def exercise(self, role, *, replacement=False, reject_evidence=False):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory) / "receipts"
            root.mkdir(mode=0o700)
            key = "run-123-job-456-attempt-1" + ("-replacement-1" if replacement else "")
            name = "csw-ci-123-456-1" + ("-replacement-1" if replacement else "")
            target = root / key
            commands = []
            registration_calls = []
            current = candidate(role)

            def remote(path, method="GET", body=None):
                if method == "POST" and path.endswith("/generate-jitconfig"):
                    receipt = json.loads((target / "receipt.json").read_text())
                    self.assertEqual(receipt["state"], "registration_uncertain")
                    self.assertEqual(receipt["runner_name"], name)
                    self.assertEqual((target / "e2e-evidence").exists(), role == "isolation")
                    registration_calls.append(body)
                    return {"encoded_jit_config": "opaque-fixture-only", "runner": {"id": 22}}
                if method == "GET" and path.endswith("/actions/jobs/456"):
                    return {"id": 456, "run_id": 123, "status": "completed",
                            "conclusion": "success", "runner_name": name}
                raise AssertionError((method, path))

            def start(command, **kwargs):
                commands.append(command)
                kwargs["stdout"].write(b"fixture-only terminal log\n")
                kwargs["stdout"].flush()
                return FakeProcess()

            stack.enter_context(patch.object(executor, "RECEIPTS", root))
            stack.enter_context(patch.object(executor, "gh", side_effect=remote))
            stack.enter_context(patch.object(executor, "approved_job_image", return_value=IMAGE))
            stack.enter_context(patch.object(executor, "prepare_network"))
            # Real Docker-volume calls are covered by a separate kernel quota
            # fixture; preserve lifecycle proof without contacting a daemon.
            prepare = stack.enter_context(patch.object(
                executor, "prepare_isolation_volume",
                return_value=("csw-e2e-vault-" + name, name + "-vault-holder")))
            export = stack.enter_context(patch.object(executor, "export_isolation_volume"))
            cleanup = stack.enter_context(patch.object(executor, "cleanup_isolation_volume"))
            stack.enter_context(patch.object(executor.subprocess, "Popen", side_effect=start))
            stack.enter_context(patch.object(executor, "stop_owned"))
            stack.enter_context(patch.object(executor, "lookup_owned_runner", return_value=None))
            stack.enter_context(patch.object(executor, "runner_absent_verified"))
            stack.enter_context(patch.object(executor, "expected_isolation_checkout", return_value=MERGE))
            vault = stack.enter_context(patch.object(executor, "create_vault", wraps=executor.create_vault))
            proof = stack.enter_context(patch.object(executor, "verify_vault", return_value={"scenario_count": 28}))
            if reject_evidence:
                proof.side_effect = RuntimeError("fixture evidence incomplete")
            if replacement:
                lineage = {"replacement_for": "csw-ci-123-456-1",
                           "original_receipt_sha256": "e" * 64,
                           "replacement_proof_sha256": "f" * 64,
                           "original_image_sha256": IMAGE}
                stack.enter_context(patch.object(executor, "select_runner_intent",
                                                 return_value=(target, name, lineage)))
            result = executor.runner_job(current, {})
            self.assertEqual(len(registration_calls), 1)
            self.assertEqual(len(commands), 1)
            cmd = commands[0]
            self.assertNotIn("--privileged", cmd)
            self.assertNotIn("/var/run/docker.sock", " ".join(cmd))
            self.assertEqual(vault.call_count, int(role == "isolation"))
            self.assertEqual(proof.call_count, int(role == "isolation"))
            if role == "isolation":
                self.assertEqual(cmd[0], "/usr/bin/prlimit")
                self.assertIn(
                    "type=volume,src=csw-e2e-vault-" + name
                    + ",dst=/e2e-evidence,volume-nocopy", cmd)
                self.assertNotIn("type=bind", " ".join(cmd))
                self.assertIn("--read-only", cmd)
                self.assertIn("type=volume,src="
                              + executor.isolation_home_volume_name(name)
                              + ",dst=/home/runner", cmd)
                self.assertEqual(sum(arg == "--tmpfs" for arg in cmd), 3)
                self.assertEqual(prepare.call_count, 1)
                self.assertEqual(export.call_count, 1)
                self.assertEqual(cleanup.call_count, 1)
                self.assertEqual(proof.call_args.kwargs["checkout_sha"], MERGE)
                self.assertEqual(proof.call_args.kwargs["source_head"], HEAD)
            else:
                self.assertNotIn("--mount", cmd)
                prepare.assert_not_called()
                export.assert_not_called()
                cleanup.assert_not_called()
            receipt = json.loads((target / "receipt.json").read_text())
            self.assertEqual(receipt["runner_name"], name)
            if replacement:
                self.assertEqual(receipt["replacement_for"], "csw-ci-123-456-1")
            expected = "held" if reject_evidence else "passed"
            self.assertEqual(result["state"], expected)
            self.assertEqual(receipt["state"], expected)
            if reject_evidence:
                self.assertIn("isolation_evidence_not_independently_verified", receipt["issues"])

    def test_security_has_no_vault_or_mount(self):
        self.exercise("security")

    def test_isolation_preserves_run_scoped_vault_and_independent_evidence(self):
        self.exercise("isolation")

    def test_lineage_bound_security_replacement_still_has_no_vault(self):
        self.exercise("security", replacement=True)

    def test_green_github_job_with_rejected_e2e_evidence_remains_held(self):
        self.exercise("isolation", reject_evidence=True)


if __name__ == "__main__":
    unittest.main()
