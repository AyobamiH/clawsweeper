"""Fail-closed whole-worker filesystem quotas; no provider or Docker execution."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import self_hosted_executor as executor
from e2e_evidence_vault import EvidenceHold


class IsolationWorkerRootfsQuota(unittest.TestCase):
    OWNER = "csw-ci-70000000000-170000000000-1"

    def test_all_writable_worker_paths_are_kernel_quota_limited(self):
        args = executor.isolation_worker_storage_args(self.OWNER)
        self.assertEqual(args[0], "--read-only")
        self.assertEqual(args.count("--tmpfs"), 3)
        self.assertEqual(args.count("--mount"), 1)
        self.assertIn("type=volume,src=" + executor.isolation_home_volume_name(
            self.OWNER) + ",dst=/home/runner", args)
        self.assertEqual(executor.ISOLATION_HOME_VOLUME_BYTES, 3 * 1024 ** 3)
        self.assertEqual(executor.ISOLATION_HOME_VOLUME_INODES, 262144)
        self.assertIn("size=3221225472", executor.ISOLATION_HOME_OPTIONS)
        self.assertIn("nr_inodes=262144", executor.ISOLATION_HOME_OPTIONS)
        self.assertIn("uid=1001,gid=1001", executor.ISOLATION_HOME_OPTIONS)
        self.assertEqual({x.split(":", 1)[0] for x in args if
                          x.startswith(("/tmp:", "/var/tmp:", "/run:"))},
                         {"/tmp", "/var/tmp", "/run"})
        for option in executor.ISOLATION_WORKER_TMPFS:
            self.assertIn("size=", option)
            self.assertIn("nr_inodes=", option)
            self.assertIn("nosuid,nodev", option)
        self.assertNotIn("type=bind", " ".join(args))
        self.assertNotIn("docker.sock", " ".join(args))
        self.assertNotIn("--storage-opt", args)

    def test_each_run_has_independent_home_identity(self):
        a = executor.isolation_home_volume_name(self.OWNER)
        b = executor.isolation_home_volume_name(
            "csw-ci-70000000000-170000000001-1")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, executor.volume_name(self.OWNER))
        self.assertEqual(a, executor.volume_name(self.OWNER) + "-home")
        with self.assertRaises(EvidenceHold):
            executor.isolation_worker_storage_args("../foreign")

    def test_foreign_or_unbounded_home_volume_refused_before_use(self):
        name = executor.isolation_home_volume_name(self.OWNER)
        result = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps([{
            "Name": name, "Driver": "local", "Labels": {
                executor.LABEL: self.OWNER},
            "Options": {"type": "tmpfs", "device": "tmpfs",
                        "o": executor.VOLUME_OPTIONS},
        }]))
        with patch.object(executor.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(executor.AdmissionHold,
                                        "isolation_volume_identity_unverifiable"):
                executor.inspect_isolation_volume(
                    name, self.OWNER, options=executor.ISOLATION_HOME_OPTIONS)
        result.stdout = json.dumps([{
            "Name": name, "Driver": "local", "Labels": {
                executor.LABEL: "another-run"},
            "Options": {"type": "tmpfs", "device": "tmpfs",
                        "o": executor.ISOLATION_HOME_OPTIONS},
        }])
        with patch.object(executor.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(executor.AdmissionHold,
                                        "isolation_volume_identity_unverifiable"):
                executor.inspect_isolation_volume(
                    name, self.OWNER, options=executor.ISOLATION_HOME_OPTIONS)

    def test_bounded_isolation_command_requires_readonly_and_home_quota(self):
        args = executor.isolation_worker_storage_args(self.OWNER)
        base = ["docker", "run", "--rm", *args, "sha256:" + "a" * 64,
                "true"]
        limiter = "/usr/bin/prlimit"
        self.assertEqual(executor.isolation_bounded_command(base, limiter)[0],
                         limiter)
        for dropped in ("--read-only", "type=volume,src=" +
                        executor.isolation_home_volume_name(self.OWNER) +
                        ",dst=/home/runner"):
            with self.subTest(dropped=dropped):
                with self.assertRaisesRegex(executor.AdmissionHold,
                                            "isolation_worker_storage_unbounded"):
                    executor.isolation_bounded_command(
                        [item for item in base if item != dropped], limiter)


if __name__ == "__main__":
    unittest.main()
