"""No external credentials, runner registration, inference, or production effects."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import e2e_evidence_vault as evidence

HEAD = "a" * 40
MERGE = "c" * 40
RUN = 42566392780


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def execution_artifacts(fixture, scenario):
    """Harness-shaped trace inventory for the 28-case seal contract."""
    if scenario == "workflow-scheduler-convergence":
        return {"scheduler-trace.json": b'{"dispatches":[1],"records":[2]}\n',
                "verdict-123/readback.json": b'{"verified":true}\n'}
    if scenario == "github-api-quota-fail-fast":
        return {"github-403.stdout.log": b"403 observed\n",
                "github-403.stderr.log": b"retry refused\n",
                "github-429.stdout.log": b"429 observed\n",
                "github-429.stderr.log": b"rate limited\n"}
    files = {"01-validate.stdout.log": b"step started\n",
             "01-validate.stderr.log": b""}
    if scenario in ("happy-path", "pending-checks"):
        files["github-state.json"] = b'{"repository":"openclaw/openclaw"}\n'
    return files


class EvidenceVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "private-receipt"
        self.root.mkdir(mode=0o700)
        self.vault = evidence.create_vault(self.root)
        self.sealed = self.vault / f"run-{RUN}-attempt-1"
        self.sealed.mkdir(mode=0o755)
        self.entries = []
        self.paths = {}
        for fixture in sorted(evidence.FIXTURES):
            for scenario in sorted(evidence.SCENARIOS):
                target = self.sealed / fixture / scenario / "summary.json"
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                blob = encoded({"fixture": fixture, "scenario": scenario, "status": "passed"})
                target.write_bytes(blob)
                rel = target.relative_to(self.sealed).as_posix()
                self.paths[(fixture, scenario)] = target
                self.entries.append({"path": rel, "size": len(blob), "sha256": sha(blob)})
                for name, content in execution_artifacts(fixture, scenario).items():
                    target = self.sealed / fixture / scenario / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
                    relative = target.relative_to(self.sealed).as_posix()
                    self.entries.append({"path": relative, "size": len(content),
                                         "sha256": sha(content)})
        self.write_receipt()

    def write_receipt(self, **overrides):
        manifest = {
            "schema": "clawsweeper.e2e-artifact-manifest.v1",
            "source_head": HEAD,
            "files": self.entries,
        }
        manifest_data = encoded(manifest)
        (self.sealed / "manifest.json").write_bytes(manifest_data)
        receipt = {
            "schema": "clawsweeper.e2e-local-seal.v1",
            "github_run_id": RUN,
            "github_attempt": 1,
            "source_head_sha": HEAD,
            "checkout_sha": MERGE,
            "scenario_count": 28,
            "expected_cases": 28,
            "missing_or_failed": [],
            "file_count": len(self.entries),
            "bytes": sum(x["size"] for x in self.entries),
            "manifest_sha256": sha(manifest_data),
            "verdict": "SEALED_28_CASES",
        }
        receipt.update(overrides)
        receipt_data = encoded(receipt)
        (self.sealed / "receipt.json").write_bytes(receipt_data)
        (self.sealed / "receipt.sha256").write_bytes(
            f"{sha(receipt_data)}  receipt.json\n".encode())

    def verify(self, **kwargs):
        params = {"run_id": RUN, "attempt": 1, "source_head": HEAD,
                  "checkout_sha": MERGE}
        params.update(kwargs)
        return evidence.verify_vault(self.vault, **params)

    def test_push_and_dispatch_checkout_are_exact_pinned_main(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        import self_hosted_executor as executor
        head = "a" * 40
        controls = {"trusted_main_sha": head}
        for event in ("push", "workflow_dispatch"):
            candidate = SimpleNamespace(event=event, branch="main", sha=head)
            with self.subTest(event=event), patch.object(
                    executor, "gh", return_value={"object": {"sha": head}}) as get:
                self.assertEqual(executor.expected_isolation_checkout(
                    candidate, controls), head)
                get.assert_called_once_with(f"{executor.REPO_SLUG}/git/ref/heads/main")
        with patch.object(executor, "gh", return_value={"object": {"sha": "b" * 40}}):
            with self.assertRaisesRegex(evidence.EvidenceHold, "default_head_not_pinned"):
                executor.expected_isolation_checkout(
                    SimpleNamespace(event="push", branch="main", sha=head), controls)
        with patch.object(executor, "gh", return_value={"object": {"sha": head}}):
            with self.assertRaisesRegex(evidence.EvidenceHold, "default_head_not_pinned"):
                executor.expected_isolation_checkout(
                    SimpleNamespace(event="push", branch="main", sha=head),
                    {"trusted_main_sha": "c" * 40})

    def test_pull_request_checkout_checks_live_merge_parentage(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        import self_hosted_executor as executor
        base, head, merge = ("b" * 40, "a" * 40, "c" * 40)
        candidate = SimpleNamespace(
            event="pull_request", branch="feature", sha=head,
            trusted_base_sha=base, pr_number=123)
        def response(name):
            if name.endswith("/merge"):
                return {"object": {"sha": merge}}
            return {"parents": [{"sha": base}, {"sha": head}]}
        with patch.object(executor, "gh", side_effect=response):
            self.assertEqual(executor.expected_isolation_checkout(candidate, {}), merge)
        with patch.object(executor, "gh", side_effect=[
                {"object": {"sha": merge}},
                {"parents": [{"sha": head}, {"sha": base}]}]):
            with self.assertRaisesRegex(evidence.EvidenceHold, "merge_ancestry_changed"):
                executor.expected_isolation_checkout(candidate, {})

    def test_unapproved_isolation_dispatch_branch_and_event_refused(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        import self_hosted_executor as executor
        with patch.object(executor, "gh") as get:
            for event, branch in (("workflow_dispatch", "feature"), ("issue_comment", "main")):
                with self.subTest(event=event, branch=branch):
                    with self.assertRaisesRegex(evidence.EvidenceHold, "unapproved_event"):
                        executor.expected_isolation_checkout(
                            SimpleNamespace(event=event, branch=branch), {})
            get.assert_not_called()

    def test_complete_28_case_matrix_with_byte_readback(self):
        output = self.verify()
        self.assertEqual(output["verdict"], "INDEPENDENT_E2E_VAULT_PASS")
        self.assertEqual(output["cases"], 28)
        self.assertEqual(output["file_count"], len(self.entries))
        self.assertEqual(output["bytes"], sum(x["size"] for x in self.entries))

    def test_private_parent_and_single_sticky_leaf(self):
        self.assertEqual(self.vault.stat().st_mode & 0o7777, 0o1777)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        volume = evidence.volume_name("csw-ci-123-456-1")
        self.assertEqual(evidence.mount_args(volume),
            ["--mount", f"type=volume,src={volume},dst=/e2e-evidence,volume-nocopy"])
        with self.assertRaisesRegex(evidence.EvidenceHold, "e2e_bounded_volume_required"):
            evidence.mount_args(self.vault)
        with self.assertRaisesRegex(evidence.EvidenceHold, "e2e_vault_creation_failed"):
            evidence.create_vault(self.root)
        self.root.chmod(0o777)
        with self.assertRaisesRegex(evidence.EvidenceHold, "e2e_receipt_owner_untrusted"):
            evidence.create_vault(self.root)

    def test_github_head_attempt_and_checkout_bound_independently(self):
        for key, value in (("run_id", RUN + 1), ("attempt", 2),
                           ("source_head", "b" * 40), ("checkout_sha", "d" * 40)):
            with self.subTest(key=key), self.assertRaises(evidence.EvidenceHold):
                self.verify(**{key: value})
        for field, value in (("checkout_sha", "d" * 40),
                             ("github_run_id", RUN + 1),
                             ("scenario_count", 27),
                             ("missing_or_failed", ["tiny/happy-path"]),
                             ("verdict", "NOT_VERIFIED")):
            with self.subTest(field=field):
                self.write_receipt(**{field: value})
                with self.assertRaisesRegex(evidence.EvidenceHold, "receipt_identity_or_case_count"):
                    self.verify()
                self.write_receipt()

    def test_tampered_file_and_receipt_digest_denied(self):
        self.paths[("tiny", "happy-path")].write_bytes(b"fake")
        with self.assertRaises(evidence.EvidenceHold):
            self.verify()
        self.paths[("tiny", "happy-path")].write_bytes(
            encoded({"fixture": "tiny", "scenario": "happy-path", "status": "passed"}))
        self.sealed.joinpath("receipt.sha256").write_text("deadbeef\n")
        with self.assertRaisesRegex(evidence.EvidenceHold, "receipt_digest_mismatch"):
            self.verify()

    def test_missing_case_and_extra_unsealed_work_denied(self):
        path = self.paths[("tiny", "happy-path")]
        path.unlink()
        with self.assertRaises(evidence.EvidenceHold):
            self.verify()
        path.write_bytes(encoded({"fixture": "tiny", "scenario": "happy-path", "status": "passed"}))
        (self.vault / ".run-unknown.partial").mkdir()
        with self.assertRaisesRegex(evidence.EvidenceHold, "unsealed_or_extra"):
            self.verify()

    def test_symlink_or_hardlink_denied_even_with_correct_contents(self):
        path = self.paths[("tiny", "happy-path")]
        backup = path.with_suffix(".backup")
        path.rename(backup)
        path.symlink_to(backup)
        with self.assertRaises(evidence.EvidenceHold):
            self.verify()
        path.unlink()
        backup.rename(path)
        os.link(path, backup)
        with self.assertRaises(evidence.EvidenceHold):
            self.verify()

    def test_changed_case_summary_even_with_updated_hash_denied(self):
        path = self.paths[("tiny", "planning-head-drift")]
        blob = encoded({"fixture": "tiny", "scenario": "planning-head-drift", "status": "failed"})
        path.write_bytes(blob)
        rel = path.relative_to(self.sealed).as_posix()
        for entry in self.entries:
            if entry["path"] == rel:
                entry.update(size=len(blob), sha256=sha(blob))
        self.write_receipt()
        with self.assertRaisesRegex(evidence.EvidenceHold, "case_summary_mismatch"):
            self.verify()

    def test_summary_only_matrix_is_not_execution_evidence(self):
        for file in self.sealed.rglob("*"):
            if file.is_file() and file.name not in (
                    "summary.json", "manifest.json", "receipt.json", "receipt.sha256"):
                file.unlink()
        self.entries = [item for item in self.entries
                        if item["path"].endswith("/summary.json")]
        self.write_receipt()
        with self.assertRaisesRegex(evidence.EvidenceHold, "execution.*trace_missing"):
            self.verify()

    def test_missing_execution_step_is_refused_even_after_resealing(self):
        target = self.sealed / "tiny/happy-path/01-validate.stdout.log"
        target.unlink()
        self.entries = [item for item in self.entries if item["path"] !=
                        "tiny/happy-path/01-validate.stdout.log"]
        self.write_receipt()
        with self.assertRaisesRegex(evidence.EvidenceHold, "step_trace_missing"):
            self.verify()

    def test_duplicate_manifest_file_denied(self):
        self.entries.append(dict(self.entries[0]))
        self.write_receipt()
        with self.assertRaisesRegex(evidence.EvidenceHold, "file_identity_invalid"):
            self.verify()

    def test_unlisted_extra_file_denied(self):
        (self.sealed / "extra.log").write_text("secret")
        with self.assertRaisesRegex(evidence.EvidenceHold, "missing_or_extra_evidence"):
            self.verify()

    def test_untrusted_mode_or_vault_symlink_denied(self):
        self.vault.chmod(0o777)
        with self.assertRaisesRegex(evidence.EvidenceHold, "owner_or_mode_changed"):
            self.verify()
        self.vault.chmod(0o1777)
        (self.sealed / "manifest.json").unlink()
        (self.sealed / "manifest.json").symlink_to(self.sealed / "receipt.json")
        with self.assertRaises(evidence.EvidenceHold):
            self.verify()

    def test_wrong_manifest_identity_denied(self):
        self.entries = [{"path": "../outside", "size": 1, "sha256": "b" * 64}]
        self.write_receipt()
        with self.assertRaisesRegex(evidence.EvidenceHold, "unsafe_relative_path"):
            self.verify()

    def test_empty_unlisted_directory_refused(self):
        (self.sealed / "never-in-manifest").mkdir()
        with self.assertRaisesRegex(evidence.EvidenceHold, "missing_or_extra_directories"):
            self.verify()

    def test_nested_symlinked_directory_refused(self):
        original = self.sealed / "tiny"
        target = self.sealed / "tiny-original"
        original.rename(target)
        original.symlink_to(target, target_is_directory=True)
        with self.assertRaises(evidence.EvidenceHold):
            self.verify()


    def test_node_sealer_round_trip_to_independent_host_verifier(self):
        # Real Node producer, host Python verifier, all 28 case identities.
        # This is a contract fixture, not provider-backed nested-Docker E2E.
        import subprocess
        input_dir = Path(self.temp.name) / "scenario-output"
        for fixture in sorted(evidence.FIXTURES):
            for scenario in sorted(evidence.SCENARIOS):
                case = input_dir / fixture / scenario
                case.mkdir(parents=True, exist_ok=True)
                (case / "summary.json").write_bytes(
                    encoded({"fixture": fixture, "scenario": scenario, "status": "passed"}))
                for name, content in execution_artifacts(fixture, scenario).items():
                    target = case / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(content)
        parent = Path(self.temp.name) / "sealer-private-parent"
        parent.mkdir(mode=0o700)
        vault = evidence.create_vault(parent)
        node_sealer = Path(__file__).parents[2] / "scripts/e2e/seal-automerge-evidence.mjs"
        env = dict(os.environ, GITHUB_RUN_ID=str(RUN), GITHUB_RUN_ATTEMPT="1",
                   GITHUB_SHA=MERGE)
        old_umask = os.umask(0o077)
        try:
            result = subprocess.run(
                ["node", str(node_sealer), "--input", str(input_dir),
                 "--vault", str(vault), "--expected-head", HEAD],
                env=env, capture_output=True, text=True, timeout=20,
                check=False)
        finally:
            os.umask(old_umask)
        self.assertEqual(result.returncode, 0, result.stderr)
        sealed = vault / f"run-{RUN}-attempt-1"
        self.assertEqual(sealed.stat().st_mode & 0o777, 0o755)
        self.assertEqual((sealed / "tiny/happy-path").stat().st_mode & 0o777, 0o755)
        self.assertEqual((sealed / "tiny/happy-path/summary.json").stat().st_mode & 0o777, 0o644)
        proof = evidence.verify_vault(
            vault, run_id=RUN, attempt=1, source_head=HEAD, checkout_sha=MERGE)
        self.assertEqual(proof["verdict"], "INDEPENDENT_E2E_VAULT_PASS")
        self.assertEqual(proof["cases"], 28)
        self.assertEqual(proof["file_count"], len(self.entries))
        # Duplicate run identity may not overwrite or replay a successful seal.
        replay = subprocess.run(
            ["node", str(node_sealer), "--input", str(input_dir),
             "--vault", str(vault), "--expected-head", HEAD],
            env=env, capture_output=True, text=True, timeout=20,
            check=False)
        self.assertNotEqual(replay.returncode, 0)
        self.assertEqual(evidence.verify_vault(
            vault, run_id=RUN, attempt=1, source_head=HEAD,
            checkout_sha=MERGE)["receipt_sha256"], proof["receipt_sha256"])


if __name__ == "__main__":
    unittest.main()
