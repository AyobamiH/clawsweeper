"""Kernel-enforced isolation output cap, no network/JIT/Docker effects."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import self_hosted_executor as runner


class IsolationLogResourceLimit(unittest.TestCase):
    def test_trusted_kernel_file_limit_applies_to_child_stdout(self):
        launcher = runner.isolation_log_limiter()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bounded.log"
            with path.open("wb") as log:
                child = subprocess.run(
                    [launcher, "--fsize=1024", "--", sys.executable, "-c",
                     "import os; left = 8192\nwhile left:\n left -= os.write(1, b'A' * left)"],
                    stdout=log, stderr=subprocess.STDOUT, timeout=10,
                    check=False)
            self.assertNotEqual(child.returncode, 0)
            self.assertLessEqual(path.stat().st_size, 1024)

    def test_both_daemon_and_cli_output_are_bounded_without_socket_mounts(self):
        owner = "csw-ci-70000000000-170000000000-1"
        cmd = ["docker", "run", "--rm", "--interactive", "--network", "none",
               "--cap-drop", "ALL", *runner.isolation_worker_storage_args(owner),
               "sha256:" + "a" * 64, "true"]
        bounded = runner.isolation_bounded_command(cmd, runner.isolation_log_limiter())
        self.assertEqual(bounded[:4], [
            "/usr/bin/prlimit", f"--fsize={runner.ISOLATION_MAX_LOG_BYTES}",
            "--", "docker"])
        self.assertEqual(bounded[4:8], [
            "run", "--log-driver=json-file", "--log-opt=max-size=16m",
            "--log-opt=max-file=2"])
        self.assertEqual(bounded[8:], cmd[2:])
        self.assertFalse(any("docker.sock" in arg for arg in bounded))
        self.assertIn("--read-only", bounded)
        self.assertIn("type=volume,src=" + runner.isolation_home_volume_name(owner)
                      + ",dst=/home/runner", bounded)
        self.assertEqual(sum(x == "--tmpfs" for x in bounded), 3)
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_worker_storage_unbounded"):
            runner.isolation_bounded_command(
                [x for x in cmd if x != "--read-only"], runner.isolation_log_limiter())
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_worker_storage_unbounded"):
            runner.isolation_bounded_command(
                ["docker", "run", "--rm", "--read-only", "sha256:" + "a" * 64],
                runner.isolation_log_limiter())
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_log_command_invalid"):
            runner.isolation_bounded_command(["docker", "rm", "--force"], runner.isolation_log_limiter())

    def test_owned_sealed_log_digest_is_streaming_and_length_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runner.log"
            path.write_bytes(b"0123456789")
            path.chmod(0o600)
            digest, size = runner.isolation_log_digest(path, limit=10)
            self.assertEqual((digest, size), (hashlib.sha256(b"0123456789").hexdigest(), 10))
            with self.assertRaisesRegex(runner.AdmissionHold, "isolation_log_unsafe_or_oversized"):
                runner.isolation_log_digest(path, limit=9)
            path.unlink()
            target = Path(tmp) / "other.log"
            target.write_bytes(b"0123456789")
            target.chmod(0o600)
            path.symlink_to(target)
            with self.assertRaisesRegex(runner.AdmissionHold, "isolation_log_unsafe_or_oversized"):
                runner.isolation_log_digest(path, limit=10)

    def test_invalid_size_never_admitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runner.log"
            path.write_bytes(b"ok")
            path.chmod(0o600)
            for bound in (0, -1, True, runner.ISOLATION_MAX_LOG_BYTES + 1):
                with self.subTest(bound=bound):
                    with self.assertRaisesRegex(runner.AdmissionHold, "isolation_log_limit_invalid"):
                        runner.isolation_log_digest(path, limit=bound)


if __name__ == "__main__":
    unittest.main()
