"""Adversarial tests for the pinned actionlint queue-schema compatibility gate."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from actionlint_queue_compat import (  # noqa: E402
    CompatibilityFailure,
    EXPECTED_QUEUES,
    OLD_SCHEMA_MESSAGE,
    adjudicate,
    verified_queue_sites,
)


class QueueCompatTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sites = verified_queue_sites(ROOT)

    def diagnostics(self):
        return [
            {
                "filepath": path,
                "line": line,
                "column": column,
                "message": OLD_SCHEMA_MESSAGE,
                "kind": "syntax-check",
                "snippet": "  queue: max\n  ^~~~~~",
                "end_column": column + 5,
            }
            for path, line, column in sorted(self.sites)
        ]

    def test_real_checked_in_six_reviewed_sites(self):
        self.assertEqual(len(self.sites), 6)
        self.assertEqual(len(EXPECTED_QUEUES), 5)

    def test_exact_old_parser_messages_admitted(self):
        self.assertEqual(
            adjudicate(self.sites, 1, json.dumps(self.diagnostics()), ""),
            "ACTIONLINT_1_7_12_REVIEWED_QUEUE_COMPAT_PASS",
        )

    def test_future_native_success_needs_no_exception(self):
        self.assertEqual(adjudicate(self.sites, 0, "[]", ""), "ACTIONLINT_NATIVE_PASS")

    def test_unrelated_error_is_not_hidden(self):
        data = self.diagnostics()
        data[0]["message"] = 'unexpected key "evil"'
        with self.assertRaises(CompatibilityFailure):
            adjudicate(self.sites, 1, json.dumps(data), "")

    def test_added_unreviewed_diagnostic_is_not_hidden(self):
        data = self.diagnostics()
        data.append(dict(data[0]))
        with self.assertRaises(CompatibilityFailure):
            adjudicate(self.sites, 1, json.dumps(data), "")

    def test_missing_diagnostic_is_not_pass(self):
        with self.assertRaises(CompatibilityFailure):
            adjudicate(self.sites, 1, json.dumps(self.diagnostics()[:-1]), "")

    def test_wrong_path_or_line_is_not_pass(self):
        data = self.diagnostics()
        data[0]["line"] += 1
        with self.assertRaises(CompatibilityFailure):
            adjudicate(self.sites, 1, json.dumps(data), "")

    def test_wrong_kind_or_snippet_is_not_pass(self):
        for field, value in (("kind", "expression"), ("snippet", "  queue: evil")):
            data = self.diagnostics()
            data[0][field] = value
            with self.subTest(field=field), self.assertRaises(CompatibilityFailure):
                adjudicate(self.sites, 1, json.dumps(data), "")

    def test_crash_and_malformed_json_are_not_pass(self):
        for code, output in ((2, "[]"), (1, "invalid json"), (1, "[]")):
            with self.subTest(code=code, output=output), self.assertRaises(CompatibilityFailure):
                adjudicate(self.sites, code, output, "")

    def test_stderr_is_not_silenced(self):
        with self.assertRaises(CompatibilityFailure):
            adjudicate(self.sites, 1, json.dumps(self.diagnostics()), "unexpected CLI output")

    def with_modified_sources(self, file, before, after):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for rel in EXPECTED_QUEUES:
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / rel, path)
            path = root / ".github/workflows" / file
            original = path.read_text()
            self.assertIn(before, original)
            path.write_text(original.replace(before, after, 1))
            return verified_queue_sites(root)

    def test_cancel_true_is_rejected(self):
        with self.assertRaisesRegex(CompatibilityFailure, "conflicting cancellation"):
            self.with_modified_sources(
                "cloudflare-repair-provision.yml",
                "cancel-in-progress: false",
                "cancel-in-progress: true",
            )

    def test_invalid_value_is_rejected(self):
        with self.assertRaisesRegex(CompatibilityFailure, "queue value"):
            self.with_modified_sources(
                "cloudflare-repair-provision.yml", "queue: max", "queue: single"
            )

    def test_unreviewed_additional_queue_is_rejected(self):
        with self.assertRaises(CompatibilityFailure):
            self.with_modified_sources(
                "cloudflare-repair-provision.yml", "  queue: max",
                "  queue: max\n  queue: max",
            )

    def test_missing_concurrency_parent_is_rejected(self):
        with self.assertRaisesRegex(CompatibilityFailure, "not in concurrency"):
            self.with_modified_sources(
                "cloudflare-operator-fixtures.yml",
                "concurrency:\n",
                "concurrency_shadow:\n",
            )

    def test_missing_reviewed_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(CompatibilityFailure, "missing"):
                verified_queue_sites(Path(temp))


if __name__ == "__main__":
    unittest.main()
