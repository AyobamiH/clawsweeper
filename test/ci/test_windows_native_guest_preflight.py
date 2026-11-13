"""Fail-closed native Windows CI host preflight and exact release boundary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "windows_native_guest_preflight.ps1"


class WindowsNativeGuestPreflightTests(unittest.TestCase):
    def test_preflight_source_never_registers_a_jit_or_executes_code(self):
        source = SCRIPT.read_text(encoding="utf-8").lower()
        forbidden = (
            "generate-jitconfig", "registration-token",
            "gh api --method post", "invoke-restmethod",
            "start-process", "enable-windowsoptionalfeature",
            "set-itemproperty", "new-localuser", "new-service",
            "ssh_auth_sock", "github_token", "run.cmd",
            "actions/runner", "docker.sock",
        )
        for fragment in forbidden:
            self.assertNotIn(fragment, source, fragment)
        self.assertIn("runner_registration_performed = $false", source)
        self.assertIn("admitted = $false", source)
        self.assertIn("exit 75", source)

    def test_host_policy_denies_even_supported_edition_without_guest_attestation(self):
        text = SCRIPT.read_text(encoding="utf-8").lower()
        self.assertIn("disposable_guest_execution_not_independently_attested", text)
        self.assertIn("ephemeral_windows_guest_verified = $false", text)
        self.assertIn("hold_isolated_windows_guest_required", text)

    @staticmethod
    def _windows_script_path(source, *, native_windows):
        if native_windows:
            return str(source)
        if not shutil.which("wslpath"):
            raise unittest.SkipTest("WSL path conversion unavailable")
        return subprocess.run(
            ["wslpath", "-w", str(source)],
            capture_output=True, text=True, timeout=10, check=True
        ).stdout.strip()

    @classmethod
    def _run_mode(cls, mode):
        runner = shutil.which("powershell.exe")
        if not runner:
            return None
        converted = cls._windows_script_path(SCRIPT, native_windows=os.name == "nt")
        result = subprocess.run(
            [runner, "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", converted, "-Mode", mode],
            capture_output=True, text=True, timeout=35,
        )
        # A failed WSL-to-Windows transport proves neither a source failure nor
        # native Windows guest acceptance. Record it as an explicit skipped
        # environmental probe; all other PowerShell failures remain failures.
        if (os.name != "nt" and result.returncode == 1
                and not result.stdout.strip()
                and result.stderr.startswith("<3>WSL ")
                and "UtilAcceptVsock:" in result.stderr
                and "accept4 failed 110" in result.stderr):
            raise unittest.SkipTest(
                "WSL PowerShell interop transport unavailable; native Windows "
                "guest execution remains unverified")
        return result

    def test_non_transport_powershell_failure_is_not_hidden(self):
        from unittest.mock import patch
        failure = subprocess.CompletedProcess([], 1, "", "Access denied")
        with (patch.object(shutil, "which", return_value="powershell.exe"),
              patch.object(self, "_windows_script_path", return_value="C:/mock.ps1"),
              patch.object(subprocess, "run", return_value=failure)):
            result = self._run_mode("Inspect")
            self.assertEqual(result.returncode, 1)

    def test_native_windows_does_not_require_wslpath(self):
        self.assertEqual(self._windows_script_path(SCRIPT, native_windows=True), str(SCRIPT))

    def test_real_windows_read_only_inspection(self):
        p = self._run_mode("Inspect")
        if p is None:
            self.skipTest("Native Windows interop not installed on test host")
        self.assertEqual(p.returncode, 0, p.stderr[-600:])
        record = json.loads(p.stdout.strip())
        self.assertEqual(record["schema"], "clawsweeper.windows-native-preflight.v1")
        self.assertEqual(record["host_platform"], "Win32NT")
        self.assertFalse(record["admitted"])
        self.assertFalse(record["github_runner_registration_performed"])
        self.assertFalse(record["host_configuration_mutated"])
        self.assertFalse(record["ephemeral_windows_guest_verified"])
        self.assertIn("disposable_guest_execution_not_independently_attested", record["reasons"])

    def test_real_windows_admission_refuses_without_registration(self):
        p = self._run_mode("Admit")
        if p is None:
            self.skipTest("Native Windows interop not installed on test host")
        self.assertEqual(p.returncode, 75, p.stderr[-600:])
        record = json.loads(p.stdout.strip())
        self.assertEqual(record["mode"], "Admit")
        self.assertEqual(record["decision"], "HOLD_ISOLATED_WINDOWS_GUEST_REQUIRED")
        self.assertFalse(record["admitted"])
        self.assertFalse(record["github_runner_registration_performed"])
        self.assertFalse(record["host_configuration_mutated"])


if __name__ == "__main__":
    unittest.main()
