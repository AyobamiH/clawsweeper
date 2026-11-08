"""No local CI fleet contention may be mistaken for idle JIT capacity."""
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts/ci"))
import estate_controller as ctl


def result(status, output):
    return subprocess.CompletedProcess([], status, stdout=output, stderr="")


class DetachedFleetGuardTests(unittest.TestCase):
    def capacity_with(self, *responses):
        with patch.object(ctl.subprocess, "run", side_effect=responses) as calls, \
             patch.object(ctl.existing, "detached_fleet_quiescent", return_value=True):
            capacity = ctl.host_capacity()
        return capacity, calls.call_count

    def test_detached_ci_unit_blocks_while_scheduler_inactive(self):
        capacity, reads = self.capacity_with(
            result(3, "inactive\n"),
            result(0, "local-ci-job-local-fleet-123.service loaded active running\n"))
        self.assertTrue(capacity["fleet_busy"])
        self.assertEqual(reads, 2)

    def test_orphaned_fleet_container_blocks_even_without_unit(self):
        capacity, reads = self.capacity_with(
            result(3, "inactive\n"), result(0, ""),
            result(0, "local-fleet-abcd\n"))
        self.assertTrue(capacity["fleet_busy"])
        self.assertEqual(reads, 3)

    def test_inventory_error_refuses_idle_assumption(self):
        for fault in (result(1, ""), OSError("systemctl missing"),
                      subprocess.TimeoutExpired("systemctl", 5)):
            with self.subTest(fault=type(fault).__name__):
                capacity, _ = self.capacity_with(result(3, "inactive\n"), fault)
                self.assertTrue(capacity["fleet_busy"])

    def test_docker_inventory_error_or_timeout_refuses(self):
        for fault in (result(1, ""), subprocess.TimeoutExpired("docker", 8)):
            with self.subTest(fault=type(fault).__name__):
                capacity, _ = self.capacity_with(
                    result(3, "inactive\n"), result(0, ""), fault)
                self.assertTrue(capacity["fleet_busy"])

    def test_hidden_sqlite_detached_lease_denies_admission(self):
        with patch.object(ctl.subprocess, "run", side_effect=[
            result(3, "inactive\\n"), result(0, ""), result(0, "")
        ]), patch.object(ctl.existing, "detached_fleet_quiescent",
                        side_effect=ctl.existing.AdmissionHold("detached_ci_lease_reserved")):
            self.assertTrue(ctl.host_capacity()["fleet_busy"])

    def test_no_active_fleet_allows_physical_capacity_readback(self):
        capacity, reads = self.capacity_with(
            result(3, "inactive\n"), result(0, ""), result(0, ""))
        self.assertFalse(capacity["fleet_busy"])
        self.assertGreaterEqual(capacity["memory_available_mib"], 0)
        self.assertGreaterEqual(capacity["disk_free_gib"], 0)
        self.assertEqual(reads, 3)


if __name__ == "__main__":
    unittest.main()
