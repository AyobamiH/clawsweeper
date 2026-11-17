"""Offline two-source release regression: no queue, network, or production writes."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "split_release_test", ROOT / "scripts/ci/direct_local_receiver_integration.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def commit(directory: Path) -> str:
    subprocess.run(["/usr/bin/git", "-C", str(directory), "init", "-q"], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(directory), "add", "."], check=True)
    subprocess.run(
        ["/usr/bin/git", "-C", str(directory), "-c", "commit.gpgsign=false",
         "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
         "commit", "-qm", "verified fixture"], check=True)
    return subprocess.check_output(
        ["/usr/bin/git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()


class SplitExecutionReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.implementation = self.root / "frozen-implementation"
        self.execution = self.root / "frozen-develop"
        self.fleet = self.root / "existing-fleet"
        for directory in (self.implementation, self.execution, self.fleet):
            directory.mkdir()
        for name in release.DISTINCT_SOURCE_FILES:
            file = self.implementation / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("# source-bound module fixture\n")
        (self.execution / "README.md").write_text("Reviewed CI target\n")
        implementation_head = commit(self.implementation)
        self.target_head = commit(self.execution)
        self.assertNotEqual(implementation_head, self.target_head)
        self.policy_file = self.fleet / "fleet-policy.json"
        self.policy = {
            "repositories": {"AyobamiH/clawsweeper": {
                "enrolled_head": self.target_head}},
            "execution_hosts": {"AyobamiH/clawsweeper": os.uname().nodename},
        }
        self.save_policy()
        self.doc = {
            "schema": release.SPLIT_SOURCE_SCHEMA,
            "repo": "AyobamiH/clawsweeper",
            "implementation_checkout": str(self.implementation),
            "implementation_commit": implementation_head,
            "execution_checkout": str(self.execution),
            "execution_commit": self.target_head,
            "execution_ref": "develop",
            "fleet_root": str(self.fleet),
            "sha256": {
                name: hashlib.sha256(
                    (self.implementation / name).read_bytes()).hexdigest()
                for name in release.DISTINCT_SOURCE_FILES
            },
        }
        self.file = self.root / "owner-split-release.json"
        self.save()

    def save(self):
        self.file.write_text(json.dumps(self.doc, sort_keys=True))
        self.file.chmod(0o600)

    def save_policy(self):
        self.policy_file.write_text(json.dumps(self.policy, sort_keys=True))
        self.policy_file.chmod(0o600)

    def test_distinct_implementation_and_execution_commits_are_verified(self):
        doc = release.read_split_source_release(self.file)
        release.verify_split_source_release(doc, enrolled_sha=self.target_head)
        observed = []
        hook = release._load_split_source_claim(
            self.file, enrolled_sha=self.target_head,
            adapter=lambda **kwargs: observed.append(kwargs) or {"admission": "held"})
        answer = hook(body=b"{}", event_name="push", signature="never",
                      delivery_id="fixture", secret=b"fixture")
        self.assertEqual(answer, {"admission": "held"})
        self.assertEqual(observed[0]["checkout"], self.execution)
        self.assertEqual(observed[0]["fleet_root"], self.fleet)
        self.assertEqual(list(self.fleet.iterdir()), [self.policy_file])

    def test_production_entrypoint_does_not_accept_an_injected_claim(self):
        with self.assertRaises(TypeError):
            release.load_split_source_claim(
                self.file, enrolled_sha=self.target_head,
                adapter=lambda **kwargs: {"admission": "forged"})

    def test_v1_and_v2_release_are_not_implicitly_promoted(self):
        for schema in (release.SCHEMA, release.DISTINCT_SCHEMA):
            self.doc["schema"] = schema
            self.save()
            with self.assertRaisesRegex(RuntimeError, "identity"):
                release.read_split_source_release(self.file)

    def test_both_source_trees_are_independently_immutable(self):
        for target, filename in (
                (self.implementation, "scripts/ci/direct_local_distinct_admission.py"),
                (self.execution, "README.md")):
            f = target / filename
            original = f.read_bytes()
            try:
                f.write_bytes(original + b"tampered")
                with self.assertRaises(RuntimeError):
                    release.verify_split_source_release(
                        release.read_split_source_release(self.file),
                        enrolled_sha=self.target_head)
            finally:
                f.write_bytes(original)

    def test_enrolled_target_cannot_be_substituted(self):
        with self.assertRaisesRegex(RuntimeError, "not_enrolled"):
            release.verify_split_source_release(
                release.read_split_source_release(self.file), enrolled_sha="a" * 40)
        self.doc["execution_commit"] = "b" * 40
        self.save()
        with self.assertRaisesRegex(RuntimeError, "not_exact_clean_head"):
            release.verify_split_source_release(
                release.read_split_source_release(self.file), enrolled_sha="b" * 40)

    def test_no_ambient_path_git_exec_before_trust_checks(self):
        shimdir = self.root / "shim"
        shimdir.mkdir()
        marker = self.root / "shim-executed"
        fake = shimdir / "git"
        fake.write_text("#!/bin/sh\nprintf executed > " + str(marker) + "\nexit 0\n")
        fake.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(shimdir), "HOME": str(shimdir)}):
            release.verify_split_source_release(
                release.read_split_source_release(self.file),
                enrolled_sha=self.target_head)
        self.assertFalse(marker.exists())

    def test_partial_manifest_tampering_symlink_and_permissions_hold(self):
        self.doc["sha256"].pop("scripts/ci/direct_local_distinct_admission.py")
        self.save()
        with self.assertRaisesRegex(RuntimeError, "identity"):
            release.read_split_source_release(self.file)
        self.doc["sha256"] = {
            name: hashlib.sha256((self.implementation / name).read_bytes()).hexdigest()
            for name in release.DISTINCT_SOURCE_FILES}
        self.save()
        link = self.root / "repointed-execution"
        link.symlink_to(self.execution)
        self.doc["execution_checkout"] = str(link)
        self.save()
        with self.assertRaisesRegex(RuntimeError, "unsafe_split_source_directory"):
            release.read_split_source_release(self.file)
        self.doc["execution_checkout"] = str(self.execution)
        self.save()
        self.file.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "permissions"):
            release.read_split_source_release(self.file)

    def test_live_fleet_policy_is_independent_enrolment_authority(self):
        self.policy["repositories"]["AyobamiH/clawsweeper"]["enrolled_head"] = "f" * 40
        self.save_policy()
        with self.assertRaisesRegex(RuntimeError, "not_enrolled_in_live_policy"):
            release.verify_split_source_release(
                release.read_split_source_release(self.file),
                enrolled_sha=self.target_head)
        self.policy["repositories"]["AyobamiH/clawsweeper"]["enrolled_head"] = self.target_head
        self.policy["execution_hosts"]["AyobamiH/clawsweeper"] = "foreign-worker"
        self.save_policy()
        with self.assertRaisesRegex(RuntimeError, "not_enrolled_in_live_policy"):
            release.verify_split_source_release(
                release.read_split_source_release(self.file),
                enrolled_sha=self.target_head)

    def test_missing_or_writable_installed_policy_refuses_before_admission(self):
        self.policy_file.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "untrusted_split_source_fleet_policy"):
            release.verify_split_source_release(
                release.read_split_source_release(self.file),
                enrolled_sha=self.target_head)
        self.policy_file.unlink()
        with self.assertRaisesRegex(RuntimeError, "missing_split_source_fleet_policy"):
            release.verify_split_source_release(
                release.read_split_source_release(self.file),
                enrolled_sha=self.target_head)
        target = self.root / "foreign-policy"
        target.write_text(json.dumps(self.policy))
        self.policy_file.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "missing_split_source_fleet_policy"):
            release.verify_split_source_release(
                release.read_split_source_release(self.file),
                enrolled_sha=self.target_head)

    def test_revocation_after_startup_blocks_claim(self):
        observed = []
        hook = release._load_split_source_claim(
            self.file, enrolled_sha=self.target_head,
            adapter=lambda **kwargs: observed.append(kwargs))
        self.doc["execution_checkout"] = str(self.implementation)
        self.save()
        with self.assertRaisesRegex(RuntimeError, "revoked_or_changed"):
            hook(body=b"{}", event_name="push", signature="x",
                 delivery_id="id", secret=b"x")
        self.assertFalse(observed)


if __name__ == "__main__":
    unittest.main()
