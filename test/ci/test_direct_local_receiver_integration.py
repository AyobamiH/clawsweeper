"""No-provider tests for exact-hash owner release of the existing receiver."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "direct_local_receiver_release_test",
    HERE / "scripts" / "ci" / "direct_local_receiver_integration.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OwnerReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.root = self.home / "existing-checkout"
        self.root.mkdir()
        self.fleet = self.home / "existing-fleet"
        self.fleet.mkdir()
        self.moddir = self.root / "scripts" / "ci"
        self.moddir.mkdir(parents=True)
        for name in module.SOURCE_FILES:
            f = self.root / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("# owner source\n")
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Test",
                        "-c", "user.email=test@example.invalid", "-c",
                        "commit.gpgsign=false", "commit", "-qm", "fixture"],
                       check=True)
        self.head = subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        self.release = self.home / "release.json"
        self.doc = {
            "schema": module.SCHEMA, "repo": "AyobamiH/clawsweeper",
            "checkout": str(self.root), "fleet_root": str(self.fleet),
            "commit": self.head,
            "sha256": {name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                       for name in module.SOURCE_FILES},
        }
        self.save()

    def save(self):
        self.release.write_text(json.dumps(self.doc, sort_keys=True))
        self.release.chmod(0o600)

    def test_verified_local_owner_release_invokes_existing_claim_only(self):
        calls = []
        def adapter(**kwargs):
            calls.append(kwargs)
            return {"queue_admitted": True}
        hook = module.load_released_claim(self.release, adapter=adapter)
        result = hook(body=b"{}", event_name="push", signature="sig",
                      delivery_id="uuid", secret=b"secret")
        self.assertTrue(result["queue_admitted"])
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]["checkout"],self.root)
        self.assertEqual(calls[0]["fleet_root"],self.fleet)

    def test_mutated_module_after_startup_refuses_call(self):
        calls = []
        hook = module.load_released_claim(
            self.release, adapter=lambda **kw: calls.append(kw))
        (self.moddir / "direct_local_provider_ref.py").write_text("changed")
        with self.assertRaisesRegex(RuntimeError, "module_drift"):
            hook(body=b"{}", event_name="push", signature="sig",
                 delivery_id="uuid", secret=b"secret")
        self.assertEqual(calls,[])

    def test_revoked_release_config_fails_without_restart(self):
        calls = []
        hook = module.load_released_claim(
            self.release, adapter=lambda **kw: calls.append(kw))
        alternate = self.home / "different-fleet"
        alternate.mkdir()
        self.doc["fleet_root"] = str(alternate)
        self.save()
        with self.assertRaisesRegex(RuntimeError, "revoked_or_changed"):
            hook(body=b"{}", event_name="push", signature="sig",
                 delivery_id="uuid", secret=b"secret")
        self.assertEqual(calls, [])

    def test_deleted_release_config_fails_without_restart(self):
        calls = []
        hook = module.load_released_claim(
            self.release, adapter=lambda **kw: calls.append(kw))
        self.release.unlink()
        with self.assertRaisesRegex(RuntimeError, "missing_or_symlinked"):
            hook(body=b"{}", event_name="push", signature="sig",
                 delivery_id="uuid", secret=b"secret")
        self.assertEqual(calls, [])

    def test_dirty_source_refuses_startup(self):
        (self.moddir / "direct_local_workflow.py").write_text("dirty")
        with self.assertRaises(RuntimeError):
            module.load_released_claim(self.release, adapter=lambda **kw: None)

    def test_wrong_commit_refuses_startup(self):
        self.doc["commit"] = "a" * 40
        self.save()
        with self.assertRaisesRegex(RuntimeError, "source_not_exact_clean_head"):
            module.load_released_claim(self.release, adapter=lambda **kw: None)

    def test_writable_release_file_is_not_authority(self):
        self.release.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "permissions"):
            module.load_released_claim(self.release, adapter=lambda **kw: None)

    def test_incomplete_module_hash_map_is_not_authority(self):
        self.doc["sha256"].pop("scripts/ci/estate_policy.py")
        self.save()
        with self.assertRaisesRegex(RuntimeError, "identity"):
            module.load_released_claim(self.release, adapter=lambda **kw: None)

    def test_duplicate_release_json_keys_refused(self):
        self.release.write_text('{"schema":"x","schema":"y"}')
        with self.assertRaises(RuntimeError):
            module.load_released_claim(self.release, adapter=lambda **kw: None)

    def test_symlinked_release_path_refused(self):
        link = self.home / "symlink"
        link.symlink_to(self.release)
        with self.assertRaisesRegex(RuntimeError, "symlinked"):
            module.load_released_claim(link, adapter=lambda **kw: None)


if __name__ == "__main__":
    unittest.main()
