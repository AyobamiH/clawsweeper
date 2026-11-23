"""Static plus pure semantic checks for the uninstalled estate timer."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]
CI = ROOT / "scripts" / "ci"


class EstateOperationalInstaller(unittest.TestCase):
    def test_installer_requires_signed_main_and_source_only_preflight(self):
        source = (CI / "install-estate-controller.sh").read_text()
        for required in (
            "--preflight", "--install",
            "git status --porcelain=v1",
            "git/ref/heads/main",
            '[[ "$main" == "$head" ]]',
            ".commit.verification.verified",
            "standing_codeql_profile_configured",
            "mode",
            "immutable_git_source_bytes_match",
            'flock -n 9',
            "clawsweeper-estate.service",
            "clawsweeper-estate.timer",
            "systemctl --user enable --now clawsweeper-estate.timer",
        ):
            self.assertIn(required, source, required)
        # Every source-only check returns before any installation, runner
        # registration, systemd reload or provider mutation.
        self.assertLess(source.index('if [[ "$mode" == --preflight ]]'),
                        source.index("main="))
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("gh workflow run", source)
        self.assertNotIn("runs-on: ubuntu", source)
        self.assertNotIn("sudo ", source)

    def test_estate_service_is_separate_from_existing_validation_controller(self):
        service = (CI / "clawsweeper-estate.service").read_text()
        timer = (CI / "clawsweeper-estate.timer").read_text()
        self.assertIn("/active/repo/scripts/ci/estate_controller.py cycle", service)
        self.assertIn("Type=oneshot", service)
        self.assertIn("KillMode=control-group", service)
        self.assertIn("UMask=0077", service)
        self.assertIn("Persistent=true", timer)
        self.assertIn("Unit=clawsweeper-estate.service", timer)
        self.assertNotIn("clawsweeper-selfhosted.service", service+timer)

    def test_default_example_still_preserves_protected_release_scope(self):
        c = json.loads((ROOT/"config/ci-estate-controls.example.json").read_text())
        self.assertEqual(c["operating_mode"], "manual_exact_run_only")
        self.assertIs(c["enabled"], False)
        self.assertIs(c["allow_live_mutations"], False)
        self.assertIs(c["operations_accepted"], False)
        self.assertEqual(c["approved_jobs"], {})
        self.assertEqual(c["enabled_classes"], [])


if __name__ == "__main__":
    unittest.main()
