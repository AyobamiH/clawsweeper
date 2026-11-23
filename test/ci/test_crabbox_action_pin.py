"""Regression for the exact, signed pnpm/action-setup supply-chain pin."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/crabbox-hydrate.yml"
ACTION_COMMIT = "0ebf47130e4866e96fce0953f49152a61190b271"


class CrabboxHydratePin(unittest.TestCase):
    def test_exact_commit_preserves_declared_release(self):
        source = WORKFLOW.read_text()
        self.assertIn(
            f"uses: pnpm/action-setup@{ACTION_COMMIT} # v6.0.9",
            source,
        )
        lines = [
            line.strip()
            for line in source.splitlines()
            if "pnpm/action-setup@" in line
        ]
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^-[ ]uses:[ ]pnpm/action-setup@[a-f0-9]{40}[ ]#[ ]v6\.0\.9$")
        self.assertNotRegex(lines[0], r"pnpm/action-setup@v\d")


if __name__ == "__main__":
    unittest.main()
