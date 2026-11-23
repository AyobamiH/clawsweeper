"""No-provider v3 split-source controller renderer regression checks."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

def load(label, file):
    spec = importlib.util.spec_from_file_location(label, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

wiring = load("v3_wiring", ROOT / "scripts/ci/direct_local_fleet_cycle_wiring.py")
fixture = load("v3_fixture", ROOT / "test/ci/test_direct_local_fleet_cycle_wiring.py")

class SplitV3InstalledUpgradeTests(unittest.TestCase):
    def render(self):
        v1 = fixture.render()["content"]
        return wiring.compile_split_v3_installed_upgrade(
            v1, expected_sha256=hashlib.sha256(v1).hexdigest())

    def test_dual_source_release_before_ingress_and_detached_worker(self):
        result = self.render()
        source = result["content"].decode()
        ast.parse(source)
        self.assertEqual(result["schema"], wiring.V3_SCHEMA)
        self.assertEqual(result["state"], "source_only_not_installed")
        self.assertEqual(result["proposed_sha256"], wiring.sha(result["content"]))
        self.assertEqual(source.count("read_split_source_release(_dl_bound)"), 2)
        self.assertEqual(source.count("verify_split_source_release("), 2)
        self.assertEqual(source.count("enrolled_sha=_dl_cfg['enrolled_head']"), 2)
        self.assertEqual(source.count("_dl_doc.get('execution_commit')"), 2)
        self.assertIn("profile='split')", source)
        self.assertNotIn("read_distinct_release(_dl_bound)", source)
        self.assertNotIn("verify_distinct_release(_dl_doc)", source)
        self.assertNotIn("profile='distinct')", source)
        self.assertEqual(source.count("with core.lock():"), 1)
        self.assertLess(source.index("verify_split_source_release("),
                        source.index("result=detached.execute("))
        self.assertLess(source.rindex("verify_split_source_release("),
                        source.index("reconcile_existing_fleet_ingress("))

    def test_exact_original_and_no_double_upgrade(self):
        v1 = fixture.render()["content"]
        for changed, expected in ((v1 + b"#malicious\n", wiring.sha(v1)),
                                  (v1, "0" * 64)):
            with self.assertRaisesRegex(RuntimeError, "distinct_upgrade_exact_installed"):
                wiring.compile_split_v3_installed_upgrade(
                    changed, expected_sha256=expected)
        v3 = self.render()["content"]
        with self.assertRaisesRegex(RuntimeError,
                                    "distinct_upgrade_unreviewed_v1_fleet_shape"):
            wiring.compile_split_v3_installed_upgrade(
                v3, expected_sha256=wiring.sha(v3))

    def test_policy_guard_or_legacy_release_drift_fails_closed(self):
        v1 = fixture.render()["content"]
        for changed in (
            v1.replace(b"_dl_doc.get('commit')", b"_dl_doc.get('other')"),
            v1.replace(b"'direct-local:%' LIMIT 2049", b"'direct-local:%' LIMIT 2048"),
        ):
            with self.assertRaises(RuntimeError):
                wiring.compile_split_v3_installed_upgrade(
                    changed, expected_sha256=wiring.sha(changed))

if __name__ == "__main__":
    unittest.main()
