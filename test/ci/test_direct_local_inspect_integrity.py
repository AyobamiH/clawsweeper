"""Read-only signed-parent and exact two-file recovery scope proof."""
import importlib.util,json,os
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[2]/"scripts/ci"
spec=importlib.util.spec_from_file_location("inspect_integrity",HERE/"direct_local_inspect_recovery_integrity.py")
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

class ParentIntegrity(unittest.TestCase):
    def test_current_capacity_signature_and_full_inventory_verified(self):
        cap,parent,inventory=gate.owner_parent(gate.SIGNERS)
        self.assertEqual(len(inventory),69)
        self.assertEqual(parent["changed_runtime"]["fleet_ci.py"],
                         "f4c58b8b105792b60ab010464b433c10ebb222e559bff98243aa87aa0afbc1df")
        verified=cap.verify("installed",gate.CAPACITY_RELEASE,gate.RUNTIME,
                            gate.FLEET_UNIT,gate.WEBHOOK_UNIT,gate.SIGNERS,
                            parent["source_head"])
        self.assertTrue(verified["production_installed"])

    def test_unit_preflights_pin_the_new_release_and_exact_source(self):
        units=gate.unit_bytes("a"*40)
        self.assertEqual(set(units),{"fleet","webhook"})
        self.assertEqual(units["fleet"],units["webhook"])
        self.assertIn(b"direct_local_inspect_recovery_integrity.py installed",units["fleet"])
        self.assertIn(b"--source-head "+b"a"*40,units["fleet"])
        self.assertIn(b"clawsweeper-direct-local-release.json",units["fleet"])

    def test_bad_source_ref_rejected_before_write(self):
        for bad in ("not-a-sha","0"*39,"A"*40,"0"*40+"x"):
            with self.subTest(value=bad):
                with self.assertRaises(RuntimeError):gate.unit_bytes(bad)

    def test_parent_digest_is_strict(self):
        with patch.object(gate,"CAPACITY_CONTROL_SHA","0"*64):
            with self.assertRaisesRegex(RuntimeError,"parent_verifier_digest_changed"):
                gate.owner_parent(gate.SIGNERS)

    def test_exact_controller_and_receiver_are_the_only_changed_files(self):
        self.assertEqual(gate.CONTROL,"control/direct_local_inspect_recovery_integrity.py")
        self.assertEqual(gate.BUILDER,"source/direct_local_inspect_timeout_recovery.py")
        cap,parent,inventory=gate.owner_parent(gate.SIGNERS)
        with tempfile.TemporaryDirectory(prefix="claw-inspect-test-") as temp:
            directory=Path(temp)
            source_map={
                gate.CONTROL:HERE/"direct_local_inspect_recovery_integrity.py",
                gate.BUILDER:HERE/"direct_local_inspect_timeout_recovery.py",
                gate.RECEIVER_SOURCE:HERE/"direct_local_receiver_integration.py",
                "frozen/fleet_ci.py":gate.CAPACITY_RELEASE/"frozen/fleet_ci.py",
                "frozen/"+gate.RECEIVER_RUNTIME:HERE/"direct_local_receiver_integration.py",
            }
            for rel,source in source_map.items():
                path=directory/rel;path.parent.mkdir(parents=True,exist_ok=True)
                raw=source.read_bytes()
                if rel=="frozen/fleet_ci.py":
                    spec=importlib.util.spec_from_file_location(
                        "renderer",HERE/"direct_local_inspect_timeout_recovery.py")
                    renderer=importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(renderer)
                    raw=renderer.render(raw)
                path.write_bytes(raw);path.chmod(0o600)
            doc=gate.expected(directory,"a"*40,cap,parent,inventory)
            self.assertEqual(set(doc["changed_runtime"]),{"fleet_ci.py",gate.RECEIVER_RUNTIME})
            self.assertEqual(set(doc["rollback_runtime"]),{"fleet_ci.py",gate.RECEIVER_RUNTIME})
            self.assertEqual(set(doc["rollback_units"]),{"fleet","webhook"})
            self.assertEqual(doc["unchanged_runtime_files"],67)
            self.assertEqual(doc["receiver_source_sha256"],doc["changed_runtime"][gate.RECEIVER_RUNTIME])
            self.assertEqual(doc["parent_receiver_sha256"],inventory[gate.RECEIVER_RUNTIME])
            self.assertFalse(doc["github_actions_dispatched"])
            candidate=gate.candidate_bytes(directory,parent)
            self.assertEqual(set(candidate),set(doc["changed_runtime"]))
            self.assertEqual(gate.sha(candidate["fleet_ci.py"]),doc["changed_runtime"]["fleet_ci.py"])
            self.assertEqual(gate.sha(candidate[gate.RECEIVER_RUNTIME]),doc["changed_runtime"][gate.RECEIVER_RUNTIME])
            (directory/"frozen"/gate.RECEIVER_RUNTIME).write_bytes(b"unsafe receiver")
            with self.assertRaisesRegex(RuntimeError,"receiver_candidate_not_frozen_exact_source"):
                gate.candidate_bytes(directory,parent)

if __name__=="__main__":unittest.main()
