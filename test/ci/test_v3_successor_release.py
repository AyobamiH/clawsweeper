"""Successor release must be signed, source-bound, rollback-ready and inert."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2] / "scripts/ci"
sys.path.insert(0, str(ROOT))
import direct_local_v3_successor_integrity as integrity
import stage_v3_successor_release as builder


class SuccessorReleaseTests(unittest.TestCase):
    def test_exact_successor_provenance(self):
        self.assertEqual(integrity.PARENT_CONTROLLER,
                         "87e89f1cbfca7a1e33bc5601ef84a6a6e292c80663fcc635e67396a1a573b528")
        self.assertEqual(integrity.NEW_CONTROLLER,
                         "dbfeb11511c3104b46c4f729642a5af27a054bc40db2aae6cebc11b23b246b37")
        self.assertNotEqual(integrity.PARENT_CONTROLLER, integrity.NEW_CONTROLLER)
        self.assertNotEqual(integrity.PARENT, builder.NEW_RELEASE)

    def test_both_units_verify_same_source_and_both_units(self):
        units = builder.unit_content()
        self.assertEqual(set(units), {"fleet", "webhook"})
        for label,data in units.items():
            self.assertIn(b"ExecStartPre=\nExecStartPre=/usr/bin/python3 -I",data)
            self.assertIn(b"/control/direct_local_v3_successor_integrity.py installed",data)
            self.assertIn(b"--fleet-unit",data)
            self.assertIn(b"--webhook-unit",data)
            self.assertNotIn(b"2026.11.15-r7",data)
            self.assertNotIn(b"allow-unsigned",data)

    def test_closed_owner_and_scope(self):
        self.assertEqual(builder.SPLIT_IDS, (
            "local-fleet-bf40e3b5fe1b","local-fleet-602d95280d8f"))
        self.assertEqual(builder.HEAD,"fde3a88be0cd6bcdf07a758501f6bbf3e34ddbcb")
        self.assertIn("source_only_staging_collision",
                      builder.checked_copy.__code__.co_consts)

    def test_missing_source_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            with self.assertRaises(ValueError):
                integrity.checked_map(p,{"../malicious":"0"*64})
            with self.assertRaises(ValueError):
                integrity.checked_map(p,{"./malicious":"0"*64})
            with self.assertRaises(ValueError):
                integrity.checked_map(p,{"/absolute":"0"*64})

    def test_tampered_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"controller.py"
            p.write_bytes(b"test")
            with self.assertRaisesRegex(ValueError,"digest_mismatch"):
                integrity.digest_file(p,"0"*64)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/"owned").write_text("data")
            (p/"link").symlink_to(p/"owned")
            with self.assertRaisesRegex(ValueError,"symlinked_file"):
                integrity.regular(p/"link")

    def test_unsigned_or_extra_output_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/"RELEASE_MANIFEST.json").write_text("{}")
            with self.assertRaises(Exception):
                integrity.signed(p/"RELEASE_MANIFEST.json",p/"signers")

    def test_invalid_mode_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"invalid_verification_mode"):
            integrity.verify("bypass",Path("/no"),Path("/no"),
                             Path("/no"),Path("/no"),Path("/no"))


if __name__ == "__main__":
    unittest.main()
