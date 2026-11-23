"""Fail closed if the complete owner-hosted check cannot finish within its job budget."""

from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from self_hosted_executor import MAX_SECONDS


def full_check_section():
    """Read exact workflow source without depending on host YAML packages."""
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    marker = "  check:\n"
    if text.count(marker) != 1:
        raise AssertionError("missing or ambiguous canonical check job")
    body = text.split(marker, 1)[1]
    next_job = re.search(r"(?m)^  [a-zA-Z][a-zA-Z0-9_-]+:\s*$", body)
    return body[:next_job.start()] if next_job else body


class BoundedOwnerCheckTests(unittest.TestCase):
    def test_real_full_check_can_complete_inside_owner_job_budget(self):
        body = full_check_section()
        match = re.search(r"(?m)^    timeout-minutes:\s*([0-9]+)\s*$", body)
        self.assertIsNotNone(match, "missing bounded Actions timeout")
        minutes = int(match.group(1))
        # Measured 26m42s (8 November 2026, two owner-operated CPUs),
        # including no GitHub action startup overhead. Keep at least 8m spare.
        self.assertGreaterEqual(minutes, 35)
        # Executor forcibly expires any JIT at 42m. Permit orderly GH
        # conclusion, runner deregistration and container cleanup first.
        self.assertLessEqual(minutes * 60, MAX_SECONDS - 3 * 60)
        self.assertIn("run: pnpm run check", body)
        self.assertIn("scripts/ci/actionlint_queue_compat.py", body)
        self.assertIn("persist-credentials: false", body)
        self.assertIn("clawsweeper-ci-validation-", body)

    def test_full_check_cannot_ever_move_to_paid_or_generic_runner(self):
        body = full_check_section()
        self.assertIn("runs-on: [self-hosted, Linux, X64,", body)
        for forbidden in ("ubuntu-latest", "windows-latest", "macos-latest", "runs-on: ubuntu-"):
            self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
