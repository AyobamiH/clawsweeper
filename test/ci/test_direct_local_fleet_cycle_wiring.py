"""Isolated, no-provider integration gate for an exact frozen fleet cycle."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts" / "ci"
spec = importlib.util.spec_from_file_location(
    "direct_local_fleet_cycle_wiring_test", SOURCE / "direct_local_fleet_cycle_wiring.py")
wiring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wiring)

BASE = b"""import json
def main():
    a=p.parse_args()
    policy=load_policy()
    db=setup()
    if a.mode=='execute-job':
        return
    with core.lock():
        if a.mode in ('discover','cycle'):
            discover(db,policy)
        if a.mode in ('work','cycle'):
            run(db,policy)
"""
INGRESS = (SOURCE / "direct_local_ingress_reconcile.py").read_bytes()
VERIFIER = (SOURCE / "direct_local_receiver_integration.py").read_bytes()


def render(source=BASE, digest=None, ingress=INGRESS, verifier=VERIFIER):
    return wiring.compile_prelock_source(
        source, expected_sha256=digest or hashlib.sha256(source).hexdigest(),
        ingress_adapter=ingress, release_verifier=verifier)


class ExactFleetSourceTests(unittest.TestCase):
    def test_hook_is_before_existing_canonical_lock_and_after_setup(self):
        result = render()
        text = result["content"].decode()
        ast.parse(text)
        self.assertLess(text.index("verified_clawsweeper_local_ingress"),
                        text.index("with core.lock():"))
        self.assertGreater(text.index("verified_clawsweeper_local_ingress"),
                           text.index("if a.mode=='execute-job':"))
        self.assertEqual(text.count("with core.lock():"), 1)
        self.assertEqual(text.count("db=setup()"), 1)
        self.assertIn("if a.mode in ('discover', 'cycle') and HOST == 'web':", text)
        self.assertIn("if _dl_release:", text)
        self.assertIn("exec(compile(_dl_bytes[_dl_entry.name]", text)
        self.assertEqual(result["ingress_sha256"], wiring.sha(INGRESS))
        self.assertEqual(result["verifier_sha256"], wiring.sha(VERIFIER))
        self.assertEqual(result["proposed_sha256"], wiring.sha(result["content"]))
        self.assertNotEqual(result["current_sha256"], result["proposed_sha256"])

    def test_source_drift_refused_without_installation(self):
        with self.assertRaisesRegex(RuntimeError, "fleet_controller_exact_source_mismatch"):
            render(digest="0" * 64)
        with self.assertRaisesRegex(RuntimeError, "fleet_controller_exact_source_mismatch"):
            render(source=BASE + b"# altered", digest=wiring.sha(BASE))

    def test_duplicate_patch_not_silently_allowed(self):
        with self.assertRaisesRegex(RuntimeError, "unrecognised_canonical_fleet_cycle_shape"):
            render(source=render()["content"])

    def test_unrecognised_fleet_cycle_rejected(self):
        for change in (
            BASE.replace(b"with core.lock():", b"with different.lock():"),
            BASE.replace(b"with core.lock():", b"with core.lock():\n        pass\n    with core.lock():"),
            BASE.replace(b"if a.mode in ('work','cycle'):", b"if a.mode == 'work':"),
            BASE.replace(b"    db=setup()\n", b""),
        ):
            with self.subTest(sample=change[:70]):
                with self.assertRaisesRegex(RuntimeError, "unrecognised_canonical_fleet_cycle_shape"):
                    render(change)

    def test_pins_are_per_exact_module_and_receipt_has_no_source(self):
        result = render()
        self.assertNotEqual(result["proposed_sha256"],
                            render(ingress=INGRESS + b"\n# changed")["proposed_sha256"])
        self.assertNotEqual(result["proposed_sha256"],
                            render(verifier=VERIFIER + b"\n# changed")["proposed_sha256"])
        self.assertNotIn("content", wiring.non_secret_receipt(result))

    def test_invalid_module_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "non_python_fleet_or_ingress_source"):
            render(ingress=b"def broken(:")
        with self.assertRaisesRegex(RuntimeError, "unrecognised_canonical_fleet_cycle_shape"):
            render(ingress=b"")

    def test_no_independent_queue_runner_or_hosted_provider_added(self):
        body = render()["content"].split(b"    # Signed ClawSweeper", 1)[1].split(
            b"    with core.lock():", 1)[0]
        for banned in (b"subprocess", b"workflow_dispatch", b"github-hosted",
                       b"ThreadingHTTPServer", b"sqlite3.connect", b"systemctl",
                       b"docker", b"runner_register"):
            self.assertNotIn(banned, body)


if __name__ == "__main__":
    unittest.main()
