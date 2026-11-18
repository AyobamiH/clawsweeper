"""Read-only signed-parent and exact one-file scope proof for a new staged gate."""
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

    def test_only_one_controller_file_is_allowed_by_release_schema(self):
        self.assertEqual(gate.CONTROL,"control/direct_local_inspect_recovery_integrity.py")
        self.assertEqual(gate.BUILDER,"source/direct_local_inspect_timeout_recovery.py")
        cap,parent,inventory=gate.owner_parent(gate.SIGNERS)
        with tempfile.TemporaryDirectory(prefix="claw-inspect-test-") as temp:
            directory=Path(temp)
            for rel in (gate.CONTROL,gate.BUILDER,"frozen/fleet_ci.py"):
                path=directory/rel;path.parent.mkdir(parents=True,exist_ok=True)
                if rel==gate.CONTROL:source=HERE/"direct_local_inspect_recovery_integrity.py"
                elif rel==gate.BUILDER:source=HERE/"direct_local_inspect_timeout_recovery.py"
                else:source=gate.CAPACITY_RELEASE/"frozen/fleet_ci.py"
                path.write_bytes(source.read_bytes());path.chmod(0o600)
            doc=gate.expected(directory,"a"*40,cap,parent,inventory)
            self.assertEqual(set(doc["changed_runtime"]),{"fleet_ci.py"})
            self.assertEqual(set(doc["rollback_runtime"]),{"fleet_ci.py"})
            self.assertEqual(set(doc["rollback_units"]),{"fleet","webhook"})
            self.assertEqual(doc["unchanged_runtime_files"],68)
            self.assertFalse(doc["github_actions_dispatched"])

if __name__=="__main__":unittest.main()
