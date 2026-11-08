"""JIT admission must not misclassify detached local fleet work as idle.

All service/container calls below are mocks. No runner, container or GitHub
operation is performed by this test.
"""
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts/ci"))
import self_hosted_executor as e
import self_hosted_policy as p


class SharedFleetCapacityTests(unittest.TestCase):
    def capacity_case(self, *, scheduler="inactive", jobs="", containers="",
                      error=None, timeout=None):
        calls = []

        def result(args, returncode=0, stdout=""):
            return subprocess.CompletedProcess(args, returncode, stdout, "")

        def shell(args, **kwargs):
            calls.append(args)
            if timeout and timeout in args:
                raise subprocess.TimeoutExpired(args, 5)
            if args[0] == "systemctl" and "is-active" in args:
                return result(args, 0 if scheduler == "active" else 3, scheduler + "\n")
            if args[0] == "systemctl" and "list-units" in args:
                return result(args, 1 if error == "units" else 0, jobs)
            if args[0] == "docker" and "ps" in args:
                return result(args, 1 if error == "docker" else 0, containers)
            self.fail("unexpected system inventory command: " + repr(args))

        def image(args, **kwargs):
            if args[:2] == ["docker", "info"]:
                return "28.0.0"
            if args[:3] == ["docker", "image", "inspect"]:
                return e.IMAGE
            self.fail("unexpected mutating command: " + repr(args))

        with (patch.object(e.subprocess, "run", side_effect=shell),
              patch.object(e, "run_cli", side_effect=image),
              patch.object(e, "approved_job_image", return_value=e.IMAGE),
              patch.object(e.shutil, "disk_usage",
                           return_value=SimpleNamespace(free=45 * 1024**3))):
            try:
                value = e.capacity(SimpleNamespace(role="ops"), {})
                return value, calls, None
            except p.AdmissionHold as exc:
                return None, calls, str(exc)

    def test_idle_scheduler_and_empty_detached_inventories_admit(self):
        value, calls, reason = self.capacity_case()
        self.assertTrue(value)
        self.assertIsNone(reason)
        self.assertEqual(len(calls), 3)

    def test_scheduler_running_blocks_without_querying_further(self):
        value, calls, reason = self.capacity_case(scheduler="active")
        self.assertIsNone(value)
        self.assertEqual(reason, "shared_fleet_busy")
        self.assertEqual(len(calls), 1)

    def test_detached_active_service_blocks_without_docker_query(self):
        value, calls, reason = self.capacity_case(
            jobs="local-ci-job-fleet-123.service loaded active running\n")
        self.assertIsNone(value)
        self.assertEqual(reason, "shared_fleet_busy")
        self.assertEqual(len(calls), 2)

    def test_inventory_includes_transitional_units_before_admitting(self):
        value, calls, reason = self.capacity_case()
        self.assertTrue(value)
        self.assertIsNone(reason)
        list_units = next(call for call in calls if "list-units" in call)
        self.assertIn("--state=active,activating,reloading,deactivating", list_units)
        for label in ("activating", "deactivating"):
            with self.subTest(label=label):
                value, calls, reason = self.capacity_case(
                    jobs=f"local-ci-job-recovery.service loaded {label} start\n")
                self.assertIsNone(value)
                self.assertEqual(reason,"shared_fleet_busy")
                self.assertEqual(len(calls), 2)

    def test_orphaned_local_fleet_container_blocks(self):
        value, calls, reason = self.capacity_case(containers="local-fleet-abcd\n")
        self.assertIsNone(value)
        self.assertEqual(reason, "shared_fleet_busy")
        self.assertEqual(len(calls), 3)

    def test_inventory_failure_never_counts_as_idle(self):
        for bad in ("units", "docker"):
            with self.subTest(bad=bad):
                value, _, reason = self.capacity_case(error=bad)
                self.assertIsNone(value)
                self.assertEqual(reason, "shared_fleet_inventory_unavailable")

    def test_max_jobs_requires_literal_integer_one(self):
        # bool and float compare equal to 1 in Python but must not grant
        # additional authority to the installed one-job JIT controller.
        candidate = SimpleNamespace(
            role="security", slot="actions", run_id=123,
            branch="main", event="push",
        )
        base = {
            "enabled": True, "repo": p.REPOSITORY,
            "enabled_roles": ["security"], "allowed_branches": ["main"],
        }
        for bad in (True, 1.0, "1", 0, 2, -1):
            with self.subTest(value=bad):
                with self.assertRaisesRegex(
                    p.AdmissionHold, "unbounded_worker_configuration"
                ):
                    p.category_enabled(candidate, {**base, "max_jobs_per_cycle": bad})
        self.assertTrue(p.category_enabled(candidate, {**base, "max_jobs_per_cycle": 1}))

    def test_inventory_timeouts_never_count_as_idle(self):
        for command in ("list-units", "ps", "is-active"):
            with self.subTest(command=command):
                value, _, reason = self.capacity_case(timeout=command)
                self.assertIsNone(value)
                self.assertEqual(reason, "shared_fleet_inventory_unavailable")


if __name__ == "__main__":
    unittest.main()
