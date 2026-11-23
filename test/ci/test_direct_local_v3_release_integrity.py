"""Source-only integrity verifier regressions: no shared fleet mutations."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import hashlib


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/ci/direct_local_v3_release_integrity.py"
spec = importlib.util.spec_from_file_location("v3_release_integrity_under_test", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class IntegrityTests(unittest.TestCase):
    def test_sha256_exact_and_refuse_altered_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "object.txt"
            p.write_bytes(b"reviewed")
            expected = hashlib.sha256(b"reviewed").hexdigest()
            self.assertEqual(gate.verified_file(p, expected), b"reviewed")
            p.write_bytes(b"altered")
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                gate.verified_file(p, expected)

    def test_refuse_path_traversal_and_absolute(self):
        for path in ("../escape", "/tmp/outside", "./relative", "a//b", "a\\b"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    gate.strict_relative(path)

    def test_refuse_symlink_and_missing_file(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = Path(root)/"actual", Path(root)/"linked"
            a.write_bytes(b"some contents")
            b.symlink_to(a)
            with self.assertRaises(ValueError):
                gate.safe_file(b)
            with self.assertRaises(FileNotFoundError):
                gate.safe_file(Path(root)/"absent")

    def test_refuse_duplicate_manifest_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate_manifest_key"):
            gate.unique_pairs([("source", 1), ("source", 2)])

    def test_refuse_invalid_manifest_hash(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)/"object"
            p.write_bytes(b"some content")
            with self.assertRaisesRegex(ValueError, "invalid_digest"):
                gate.verified_file(p, "a"*63)

    def test_refuse_group_writable_release_directory(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)/"stage"
            p.mkdir()
            p.chmod(0o770)
            with self.assertRaisesRegex(ValueError, "untrusted_directory"):
                gate.safe_dir(p)


if __name__ == "__main__":
    unittest.main()
