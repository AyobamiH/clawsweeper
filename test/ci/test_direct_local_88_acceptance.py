"""Read-only 88-job ledger must never claim execution from routing alone."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import direct_local_88_acceptance as ledger
from estate_policy import Hold


def signed_fixture():
    rows = {}
    for key, expected in ledger.INITIAL.items():
        rows[expected["id"]] = {
            "suite": expected["suite"],
            "attempt": expected["attempt"],
            "execution_source_sha": ledger.EXECUTION_SHA,
            "durable_sqlite_state": "completed",
            "durable_sqlite_outcome": "success",
            "reported": True,
            "cleanup_verified": True,
            "owned_container_absent": True,
            "historical_proofs_retained": True,
            "started_at": "2026-11-20T08:00:00+00:00",
            "finished_at": "2026-11-20T08:30:00+00:00",
            "engine_container_id": ("a" if key.endswith("#check") else "e") * 64,
            "log_sha256": "b" * 64,
            "receipt_sha256": ("c" if key.endswith("#check") else "f") * 64,
            "signed_controller_sha256": "d" * 64,
            "steps": [
                {"name": name, "exit_code": 0}
                for name in (*ledger.COMMON_STEPS, expected["last_step"])
            ],
        }
    return {
        "schema": ledger.SCHEMA,
        "host": "web",
        "source_sha": ledger.EXECUTION_SHA,
        "required": 2,
        "distinct_ordinary_jobs_verified": 2,
        "execution_mode": "existing_detached_local_fleet",
        "fleet_database_quick_check": "ok",
        "detached_leases": 0,
        "pending_jobs": 0,
        "fleet_timer_active": True,
        "github_provider_accepted": False,
        "github_hosted_ci_proven": False,
        "new_controller_created": False,
        "new_job_ids_created": False,
        "signed_permanent_capacity_guard_passed": True,
        "paid_ci_dispatched": False,
        "other_86_workflow_definitions_accepted": False,
        "accepted_utc": "2026-11-20T08:29:26+00:00",
        "accepted_job_ids": [x["id"] for x in ledger.INITIAL.values()],
        "jobs": rows,
    }


class AcceptanceTests(unittest.TestCase):
    def test_owner_signed_two_do_not_imply_other_86_or_provider_checks(self):
        receipt = signed_fixture()
        with patch.object(ledger, "read_signed_receipt", return_value=receipt):
            result = ledger.compile_acceptance(
                root=ROOT, receipt=Path("not-read"), expected_digest="a" * 64,
                signers=Path("not-read"))
        self.assertEqual(result["summary"], {
            "total_workflows": 41, "total_jobs": 88,
            "historically_signed_terminal_success": 2,
            "not_yet_accepted": 86, "provider_accepted": 0,
        })
        self.assertFalse(result["current_fleet_database_reverified"])
        self.assertFalse(result["github_provider_accepted"])
        self.assertEqual(result["new_jobs_executed"], 0)
        accepted = [j for j in result["jobs"]
                    if j["local_terminal_acceptance"] == "historically_owner_signed_verified"]
        self.assertEqual({j["key"] for j in accepted}, set(ledger.INITIAL))
        self.assertTrue(all(j["local_terminal_acceptance"] == "not_accepted"
                            and j["local_proof"] is None and not j["github_provider_accepted"]
                            for j in result["jobs"] if j not in accepted))

    def test_historical_ci_source_drift_fails_closed(self):
        # A valid signed 2/2 receipt is insufficient if future ci.yml changes.
        with patch.object(ledger, "historical_ci_bytes",
                          return_value=b"different historical ci.yml bytes"):
            with patch.object(ledger, "read_signed_receipt",
                              return_value=signed_fixture()):
                with self.assertRaisesRegex(Hold, "historical_ci_workflow_source_drift"):
                    ledger.compile_acceptance(
                        root=ROOT, receipt=Path("unused"),
                        expected_digest="a" * 64, signers=Path("unused"))

    def test_missing_historical_git_blob_fails_closed(self):
        with patch.object(ledger.subprocess, "run",
                          side_effect=OSError("no historical commit")):
            with self.assertRaisesRegex(Hold, "historical_ci_workflow_unavailable"):
                ledger.historical_ci_bytes(ROOT)

    def test_invalid_history_fails_closed(self):
        changes = [
            lambda x: x.update({"source_sha": "a" * 40}),
            lambda x: x.update({"github_provider_accepted": True}),
            lambda x: x.update({"other_86_workflow_definitions_accepted": True}),
            lambda x: x.update({"detached_leases": 1}),
            lambda x: x.update({"required": 88}),
            lambda x: x.update({"accepted_job_ids": ["duplicate", "duplicate"]}),
            lambda x: x.update({"new_job_ids_created": True}),
            lambda x: x.update({"signed_permanent_capacity_guard_passed": False}),
            lambda x: x["jobs"][ledger.INITIAL[
                ".github/workflows/ci.yml#check"]["id"]].update({
                    "engine_container_id": x["jobs"][ledger.INITIAL[
                        ".github/workflows/ci.yml#sparse-repair-builds"]["id"]]
                        ["engine_container_id"]}),
            lambda x: x.update({"accepted_utc": "2026-11-20"}),
            lambda x: x["jobs"][ledger.INITIAL[
                ".github/workflows/ci.yml#check"]["id"]]["steps"][-1].update({"exit_code": 1}),
            lambda x: x["jobs"][ledger.INITIAL[
                ".github/workflows/ci.yml#check"]["id"]].update({"cleanup_verified": False}),
            lambda x: x["jobs"][ledger.INITIAL[
                ".github/workflows/ci.yml#check"]["id"]].update({"attempt": 3}),
            lambda x: x["jobs"][ledger.INITIAL[
                ".github/workflows/ci.yml#check"]["id"]].update({"engine_container_id": "short"}),
            lambda x: x["jobs"][ledger.INITIAL[
                ".github/workflows/ci.yml#check"]["id"]].update({
                    "started_at": "2026-11-20T09:00:00+00:00",
                    "finished_at": "2026-11-20T08:00:00+00:00"}),
        ]
        for change in changes:
            with self.subTest(change=repr(change)):
                document = signed_fixture()
                change(document)
                with self.assertRaises(Hold):
                    ledger.verify_two(document)

    def test_owner_receipt_digest_mismatch_precedes_signature_verification(self):
        with tempfile.TemporaryDirectory(prefix="claw-ledger-") as tmp:
            file = Path(tmp) / "receipt.json"
            file.write_text(json.dumps(signed_fixture()))
            with patch.object(ledger.signatures, "verify_signature") as verify:
                with self.assertRaises(Hold):
                    ledger.read_signed_receipt(file, "a" * 64, Path("signers"))
                verify.assert_not_called()

    def test_signed_exact_bytes_are_required_and_duplicate_json_keys_refused(self):
        with tempfile.TemporaryDirectory(prefix="claw-ledger-") as tmp:
            file = Path(tmp) / "receipt.json"
            raw = b'{"schema":"x","schema":"y"}'
            file.write_bytes(raw)
            with patch.object(ledger.signatures, "verify_signature", return_value=raw):
                with self.assertRaises(Hold):
                    ledger.read_signed_receipt(file, hashlib.sha256(raw).hexdigest(),
                                               Path("signers"))
            file.write_text(json.dumps(signed_fixture()))
            raw = file.read_bytes()
            with patch.object(ledger.signatures, "verify_signature", return_value=b"different"):
                with self.assertRaises(Hold):
                    ledger.read_signed_receipt(file, hashlib.sha256(raw).hexdigest(),
                                               Path("signers"))

    def test_missing_signature_cannot_be_implicitly_trusted(self):
        with tempfile.TemporaryDirectory(prefix="claw-ledger-") as tmp:
            file = Path(tmp) / "receipt.json"
            file.write_text(json.dumps(signed_fixture()))
            with self.assertRaises(Hold):
                ledger.read_signed_receipt(
                    file, hashlib.sha256(file.read_bytes()).hexdigest(),
                    Path(tmp) / "missing-signers")


if __name__ == "__main__":
    unittest.main()
