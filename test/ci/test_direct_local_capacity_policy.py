"""Portable capacity configuration tests; no owner filesystem or live service."""
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

SOURCE = Path(__file__).resolve().parents[2]/'scripts/ci'
if SOURCE.is_dir(): sys.path.insert(0, str(SOURCE))
import direct_local_capacity_policy as renderer

GIB = 1024**3


class CapacityConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.core = types.ModuleType('disposable_capacity_core')
        self.core.__dict__.update(os=os, json=json, ROOT=self.root, GIB=GIB)
        exec(compile(renderer.DISK_HELPER, '<capacity-policy-helper>', 'exec'), self.core.__dict__)

    def tearDown(self): self.temp.cleanup()

    def config(self, document):
        path = self.root/'config.json'
        path.write_text(json.dumps(document))
        path.chmod(0o600)

    def test_owner_lowered_values(self):
        self.config(renderer.CAPACITY)
        self.assertEqual(self.core.disk_policy(), (2*GIB, 4*GIB))

    def test_legacy_file_absent_retains_conservative_defaults(self):
        self.assertEqual(self.core.disk_policy(), (12*GIB, 14*GIB))

    def test_missing_legacy_fields_retain_conservative_defaults(self):
        self.config({'execution_mode':'detached'})
        self.assertEqual(self.core.disk_policy(), (12*GIB, 14*GIB))

    def test_fractional_reservations_round_up(self):
        self.config({'physical_disk_reserve_GiB':2.0000000001,
                     'minimum_admission_free_GiB':4.0000000001})
        self.assertEqual(self.core.disk_policy(), (2*GIB+1,4*GIB+1))

    def test_invalid_numeric_values_rejected(self):
        for key in ('physical_disk_reserve_GiB','minimum_admission_free_GiB'):
            for value in (True, False, None, 0, -1, '2', float('nan'), float('inf'), 10**1000):
                with self.subTest(key=key,value=repr(value)):
                    self.config({**renderer.CAPACITY,key:value})
                    with self.assertRaises(RuntimeError): self.core.disk_policy()

    def test_admission_below_stop_reserve_rejected(self):
        self.config({'physical_disk_reserve_GiB':5,'minimum_admission_free_GiB':4})
        with self.assertRaisesRegex(RuntimeError,'below its stop reserve'): self.core.disk_policy()

    def test_malformed_existing_json_is_not_defaulted(self):
        self.config({})
        (self.root/'config.json').write_text('{broken')
        with self.assertRaisesRegex(RuntimeError,'Malformed'): self.core.disk_policy()

    def test_duplicate_json_keys_rejected(self):
        self.config({})
        (self.root/'config.json').write_text('{"physical_disk_reserve_GiB":12,"physical_disk_reserve_GiB":2}')
        with self.assertRaisesRegex(RuntimeError,'Duplicate'): self.core.disk_policy()

    def test_non_object_config_rejected(self):
        for value in ([], 1, None):
            self.config(value)
            with self.assertRaisesRegex(RuntimeError,'must be an object'): self.core.disk_policy()

    def test_group_writable_config_rejected(self):
        self.config(renderer.CAPACITY)
        (self.root/'config.json').chmod(0o660)
        with self.assertRaisesRegex(RuntimeError,'Unsafe'): self.core.disk_policy()

    def test_symlink_config_rejected(self):
        target=self.root/'target.json';target.write_text(json.dumps(renderer.CAPACITY));target.chmod(0o600)
        (self.root/'config.json').symlink_to(target)
        with self.assertRaises(OSError): self.core.disk_policy()

    def test_oversized_config_rejected(self):
        self.config({'padding':'x'*65536})
        with self.assertRaisesRegex(RuntimeError,'Unsafe'): self.core.disk_policy()

    def test_non_file_config_rejected(self):
        (self.root/'config.json').mkdir()
        with self.assertRaisesRegex(RuntimeError,'Unsafe'): self.core.disk_policy()

    def test_fifo_config_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.root/'config.json',0o600)
        with self.assertRaisesRegex(RuntimeError,'Unsafe'): self.core.disk_policy()

    def test_renderer_refuses_incomplete_inventory(self):
        with self.assertRaisesRegex(ValueError,'inventory_changed'):
            renderer.render_runtime({'config.json':b'{}'})

    def test_renderer_refuses_unverified_baseline_bytes(self):
        with self.assertRaisesRegex(ValueError,'digest_mismatch'):
            renderer.render_runtime({name:b'not authorised' for name in renderer.BASELINE})

    def test_renderer_never_overwrites_existing_candidate(self):
        destination=self.root/'existing';destination.mkdir()
        with self.assertRaisesRegex(ValueError,'already_exists'):
            renderer.render_directory(self.root/'unused',destination)


if __name__=='__main__': unittest.main()
