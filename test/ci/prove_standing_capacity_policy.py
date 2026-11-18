#!/usr/bin/env python3
"""Exercise real signatures and mutations of an explicitly supplied runtime.

Run: python -I -B prove_standing_capacity_policy.py --runtime /reviewed/runtime
No live source is executed or changed; every mutation uses a private temp copy.
The required runtime is never silently skipped or substituted with mock code.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
GUARD = HERE/'standing_capacity_policy.py'
if not GUARD.is_file():
    GUARD = HERE.parents[1]/'scripts/ci/standing_capacity_policy.py'
spec = importlib.util.spec_from_file_location('standing_capacity_policy',GUARD)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
RUNTIME = None


def run(args):
    result = subprocess.run([str(a) for a in args],capture_output=True,timeout=15)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors='replace')[-500:])
    return result.stdout.decode()


class StandingCapacityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if RUNTIME is None:
            raise RuntimeError('Explicit --runtime required; no capacity proof is skipped')
        cls.source = {name:(RUNTIME/name).read_bytes() for name in (*guard.SOURCE_FILES,'config.json')}
        if guard.capacity_projections({name:cls.source[name] for name in guard.SOURCE_FILES}) != guard.EXPECTED_PROJECTIONS:
            raise RuntimeError('Supplied runtime does not have the reviewed capacity projections')
        cls.keys = tempfile.TemporaryDirectory(prefix='capacity-policy-keys-',dir=Path.home())
        cls.key = Path(cls.keys.name)/'key'
        run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',cls.key])
        cls.fingerprint = run(['/usr/bin/ssh-keygen','-lf',str(cls.key)+'.pub','-E','sha256']).split()[1]
        cls.public_key = Path(str(cls.key)+'.pub').read_text().strip()

    @classmethod
    def tearDownClass(cls): cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='capacity-policy-test-',dir=self.keys.name)
        self.root = Path(self.temp.name)
        self.runtime = self.root/'runtime';self.runtime.mkdir(mode=0o700)
        for name,raw in self.source.items():
            p=self.runtime/name;p.write_bytes(raw);p.chmod(0o600)
        self.guard_path = self.root/'standing_capacity_policy.py'
        self.guard_path.write_bytes(GUARD.read_bytes());self.guard_path.chmod(0o600)
        self.signers = self.root/'allowed_signers'
        self.signers.write_text(guard.SIGNER+' '+self.public_key+'\n');self.signers.chmod(0o600)
        self.policy = self.root/'policy.json'
        doc=guard.build_contract(self.runtime,self.guard_path)
        self.policy.write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n');self.policy.chmod(0o600)
        self.sign(self.policy);self.sign(self.guard_path)

    def tearDown(self): self.temp.cleanup()

    def sign(self,path):
        sig=Path(str(path)+'.sig')
        if sig.exists():sig.unlink()
        run(['/usr/bin/ssh-keygen','-Y','sign','-f',self.key,'-n',guard.NAMESPACE,path])
        sig.chmod(0o600)

    def verify(self):
        with patch.object(guard,'__file__',str(self.guard_path)), \
             patch.object(guard,'FINGERPRINT',self.fingerprint), \
             patch.object(guard.socket,'gethostname',return_value='web'):
            return guard.verify(self.policy,self.runtime,self.signers)

    def mutate(self,name,old,new):
        p=self.runtime/name;text=p.read_text()
        self.assertIn(old,text);p.write_text(text.replace(old,new,1))

    def config(self,key,value):
        p=self.runtime/'config.json';doc=json.loads(p.read_text())
        doc[key]=value;p.write_text(json.dumps(doc))

    def test_current_signed_policy_passes_without_mutations(self):
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.runtime.iterdir()}
        result=self.verify()
        self.assertEqual(result['capacity'],guard.CAPACITY)
        self.assertFalse(result['candidate_code_executed'])
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.runtime.iterdir()})

    def test_legacy_settings_and_concurrency_rejected(self):
        for key,value in (('physical_disk_reserve_GiB',12),('minimum_admission_free_GiB',14),
                          ('max_parallel_jobs',2),('execution_mode','inline'),('max_parallel_jobs',True)):
            with self.subTest(key=key,value=value):
                self.config(key,value)
                with self.assertRaisesRegex(ValueError,'setting_changed'):self.verify()
                self.config(key,guard.CAPACITY[key])

    def test_missing_capacity_key_rejected(self):
        p=self.runtime/'config.json';doc=json.loads(p.read_text());del doc['physical_disk_reserve_GiB']
        p.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError,'setting_changed'):self.verify()

    def test_missing_file_rejected(self):
        (self.runtime/'config.json').unlink()
        with self.assertRaises(FileNotFoundError):self.verify()

    def test_unrelated_config_preserved(self):
        self.config('unrelated_future_setting',{'retained':True})
        self.assertEqual(self.verify()['gate'],'STANDING_CAPACITY_POLICY_VERIFIED')

    def test_hardcoded_admission_regression_rejected_despite_correct_config(self):
        self.mutate('fleet_ci.py','required_disk=max(minimum,reserve+(writable_mib+512)*core.MIB)',
                    'required_disk=max(14*core.GIB,12*core.GIB+(writable_mib+512)*core.MIB)')
        with self.assertRaisesRegex(ValueError,'code_regression'):self.verify()

    def test_hardcoded_watchdog_regression_rejected(self):
        self.mutate('fleet_ci.py','free)<core.disk_policy()[0]:','free)<12*core.GIB:')
        with self.assertRaisesRegex(ValueError,'code_regression'):self.verify()

    def test_hardcoded_detached_budget_regression_rejected(self):
        self.mutate('fleet_detached.py','fleet.core.disk_policy()[0]-sum','12*fleet.core.GIB-sum')
        with self.assertRaisesRegex(ValueError,'code_regression'):self.verify()

    def test_concurrency_code_regression_rejected(self):
        self.mutate('fleet_detached.py','limit=fleet.configured_parallelism()','limit=2')
        with self.assertRaisesRegex(ValueError,'code_regression'):self.verify()

    def test_active_lease_accounting_regression_rejected(self):
        self.mutate('fleet_detached.py',"sum(l['disk_bytes'] for l in leases)", '0')
        with self.assertRaisesRegex(ValueError,'code_regression'):self.verify()

    def test_extra_early_legacy_capacity_hold_rejected(self):
        self.mutate('fleet_detached.py','resource=fleet.core.resources()',
            "resource=fleet.core.resources()\n    if resource['windows_free_bytes'] < 16.5*fleet.core.GIB:\n        return []")
        with self.assertRaisesRegex(ValueError,'code_regression'):self.verify()

    def test_watchdog_moved_under_dead_branch_rejected(self):
        self.mutate('fleet_ci.py',
            "                if min(core.shutil.disk_usage('/mnt/c').free,core.shutil.disk_usage(ROOT).free)<core.disk_policy()[0]:\n                    raise RuntimeError('Physical disk reserve reached')",
            "                if False:\n                    if min(core.shutil.disk_usage('/mnt/c').free,core.shutil.disk_usage(ROOT).free)<core.disk_policy()[0]:\n                        raise RuntimeError('Physical disk reserve reached')")
        with self.assertRaisesRegex(ValueError,'code_regression'):self.verify()

    def test_capacity_module_redirect_rejected(self):
        self.mutate('fleet_ci.py','import local_ci as core','import unrelated_runtime as core')
        with self.assertRaisesRegex(ValueError,'projection_shape'):self.verify()

    def test_unrelated_inspection_timeout_change_permitted(self):
        self.mutate('fleet_ci.py','obj=inspect(name,measure_size=measure)',
                    'obj=inspect(name,measure_size=measure,timeout=45)')
        self.verify()

    def test_comments_formatting_and_docstrings_permitted(self):
        p=self.runtime/'fleet_ci.py';text=p.read_text()
        text=text.replace('required_disk=max(minimum,reserve+(writable_mib+512)*core.MIB)',
                          '# Same owner capacity, reformatted.\n    required_disk = max(minimum, reserve + (writable_mib + 512) * core.MIB)')
        text=text.replace('Only the local owner-controlled setting can enable parallel jobs.',
                          'Owner-controlled concurrency setting.')
        p.write_text(text);self.verify()

    def test_candidate_code_never_executed(self):
        marker=self.root/'must-not-exist'
        p=self.runtime/'fleet_ci.py'
        p.write_text(p.read_text()+f'\n__import__("pathlib").Path({str(marker)!r}).write_text("executed")\n')
        self.verify();self.assertFalse(marker.exists())

    def test_invalid_policy_signature_rejected(self):
        self.policy.write_text(self.policy.read_text()+' ')
        with self.assertRaisesRegex(ValueError,'invalid_owner_signature'):self.verify()

    def test_invalid_guard_signature_rejected(self):
        self.guard_path.write_text(self.guard_path.read_text()+'\n# tampered\n')
        with self.assertRaisesRegex(ValueError,'invalid_owner_signature'):self.verify()

    def test_resigned_different_guard_hash_rejected(self):
        self.guard_path.write_text(self.guard_path.read_text()+'\n# different signed guard\n')
        self.sign(self.guard_path)
        with self.assertRaisesRegex(ValueError,'scope_or_guard_changed'):self.verify()

    def test_signed_scope_expansion_rejected(self):
        doc=json.loads(self.policy.read_text());doc['capacity']['physical_disk_reserve_GiB']=12
        self.policy.write_text(json.dumps(doc));self.sign(self.policy)
        with self.assertRaisesRegex(ValueError,'scope_or_guard_changed'):self.verify()

    def test_symlink_and_unsafe_runtime_files_rejected(self):
        p=self.runtime/'config.json';p.chmod(0o660)
        with self.assertRaises(ValueError):self.verify()
        p.chmod(0o600);target=self.root/'real-config';p.rename(target);p.symlink_to(target)
        with self.assertRaisesRegex(ValueError,'symlink'):self.verify()

    def test_intermediate_symlink_rejected(self):
        link=self.root/'linked-runtime';link.symlink_to(self.runtime,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'symlink'):guard.inspect_runtime(link)

    def test_fifo_rejected_without_waiting(self):
        p=self.runtime/'config.json';p.unlink();os.mkfifo(p,0o600)
        with self.assertRaisesRegex(ValueError,'unsafe_regular'):self.verify()

    def test_unit_maps_missing_guard_to_255(self):
        unit=guard.unit_bytes(self.root/'missing_guard.py',self.policy,self.runtime,self.signers).decode()
        self.assertIn('|| exit 255',unit)
        command=unit.split('ExecCondition=/bin/sh -c "',1)[1].rsplit('"\n',1)[0]
        result=subprocess.run(['/bin/sh','-c',command],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,255)

    def test_cli_argument_failure_is_255(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(guard.main([]),255)

    def namespace_path(self, root_uid, owner_uid=1000, home_uid=None):
        """Model only lstat metadata; no namespaces, chown or live files change."""
        path=Path('/home/johnh/.config/capacity/policy.json')
        records={}
        for item in [path,*path.parents]:
            is_file=item == path
            uid=owner_uid if item == guard.OWNER or guard.OWNER in item.parents else root_uid
            if item == Path('/home') and home_uid is not None:uid=home_uid
            mode=(stat.S_IFREG|0o600) if is_file else (stat.S_IFDIR|0o755)
            records[item]=os.stat_result((mode,1,1,1,uid,1000,100,0,0,0))
        with patch.object(Path,'lstat',lambda p:records[p]), \
             patch.object(Path,'resolve',lambda p:p):
            guard.safe_path(path)

    def test_normal_root_ancestors_accepted(self):
        self.namespace_path(0)

    def test_namespace_mapped_root_ancestors_accepted(self):
        self.namespace_path(65534)

    def test_foreign_system_ancestor_rejected(self):
        with self.assertRaisesRegex(ValueError,'foreign_owner'):
            self.namespace_path(65534,home_uid=12345)

    def test_mapped_root_does_not_authorise_owner_home(self):
        with self.assertRaisesRegex(ValueError,'foreign_owner'):
            self.namespace_path(65534,owner_uid=65534)

    def test_normal_root_does_not_authorise_owner_home(self):
        with self.assertRaisesRegex(ValueError,'foreign_owner'):
            self.namespace_path(0,owner_uid=0)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    args,remaining=parser.parse_known_args()
    RUNTIME=args.runtime
    unittest.main(argv=[sys.argv[0],*remaining])
