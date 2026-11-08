"""Actual flock and owner-boundary tests. Uses only private temporary files."""
import fcntl
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
from estate_fleet_lock import shared_fleet_exclusive, legacy_executor_exclusive
import estate_controller as controller
from estate_policy import Hold


class SharedFleetExclusion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "local-ci"
        self.root.mkdir(mode=0o700)
        (self.root / "OWNED_BY_LOCAL_CI").write_bytes(b"local-ci-v1\n")
        self.lock = self.root / "control.lock"
        self.lock.touch(mode=0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_excludes_competing_inodes_and_releases_after_scope(self):
        with shared_fleet_exclusive(self.root):
            fd = os.open(self.lock, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        with shared_fleet_exclusive(self.root):
            pass

    def test_wrong_owner_marker_is_not_trusted(self):
        (self.root / "OWNED_BY_LOCAL_CI").write_text("something-else")
        with self.assertRaisesRegex(Hold, "ownership_marker_mismatch"):
            with shared_fleet_exclusive(self.root):
                pass

    def test_missing_lock_not_created(self):
        self.lock.unlink()
        with self.assertRaisesRegex(Hold, "shared_fleet_lock_unavailable"):
            with shared_fleet_exclusive(self.root):
                pass
        self.assertFalse(self.lock.exists())

    def test_symlink_and_world_readable_lock_refused(self):
        self.lock.chmod(0o644)
        with self.assertRaisesRegex(Hold, "unsafe_shared_fleet_lock"):
            with shared_fleet_exclusive(self.root):
                pass
        self.lock.unlink()
        self.lock.symlink_to(self.root / "other")
        with self.assertRaisesRegex(Hold, "shared_fleet_lock_unavailable"):
            with shared_fleet_exclusive(self.root):
                pass

    def test_legacy_jit_controller_lock_excludes_concurrent_registration(self):
        legacy = self.root / "executor.lock"
        legacy.touch(mode=0o600)
        with legacy_executor_exclusive(legacy):
            fd = os.open(legacy, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        with legacy_executor_exclusive(legacy):
            pass

    def test_legacy_jit_lock_must_be_private_and_preexisting(self):
        legacy = self.root / "executor.lock"
        with self.assertRaisesRegex(Hold, "legacy_jit_lock_unavailable"):
            with legacy_executor_exclusive(legacy):
                pass
        self.assertFalse(legacy.exists())
        legacy.touch(mode=0o600)
        legacy.chmod(0o644)
        with self.assertRaisesRegex(Hold, "unsafe_legacy_jit_lock"):
            with legacy_executor_exclusive(legacy):
                pass

    def test_enabled_controller_refuses_busy_legacy_jit_lock(self):
        with (patch.object(controller, "shared_fleet_exclusive",
                           side_effect=lambda: __import__("contextlib").nullcontext()),
              patch.object(controller, "legacy_executor_exclusive",
                           side_effect=Hold("legacy_jit_controller_busy")),
              patch.object(controller, "discover",
                           side_effect=AssertionError("must not discover"))):
            with self.assertRaisesRegex(Hold, "legacy_jit_controller_busy"):
                controller.cycle(controls={"enabled": True, "allow_live_mutations": True})

    def test_controller_disabled_does_not_take_global_lock(self):
        with patch.object(controller, "shared_fleet_exclusive",
                          side_effect=AssertionError("must not take lock")):
            self.assertEqual(controller.cycle(controls={}),
                             {"held": "estate_controller_disabled"})

    def test_enabled_controller_refuses_busy_global_lock_before_discovery(self):
        with (patch.object(controller, "shared_fleet_exclusive",
                           side_effect=Hold("shared_fleet_lock_busy")),
              patch.object(controller, "discover",
                           side_effect=AssertionError("must not discover"))):
            with self.assertRaisesRegex(Hold, "shared_fleet_lock_busy"):
                controller.cycle(controls={"enabled": True, "allow_live_mutations": True})


if __name__ == "__main__":
    unittest.main()
