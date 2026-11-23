"""Disposable integrity proof with ephemeral SSH signatures, never production writes."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ENTRY = HERE/'direct_local_capacity_integrity.py'
if not ENTRY.is_file(): ENTRY = HERE.parents[1]/'scripts/ci/direct_local_capacity_integrity.py'
spec = importlib.util.spec_from_file_location('capacity_integrity', ENTRY)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
HEAD = 'a'*40

class CapacityIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.key = Path(cls.keys.name)/'key'
        subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(cls.key)],check=True,capture_output=True)
        cls.signers = Path(cls.keys.name)/'allowed_signers'
        cls.signers.write_text(v.SIGNER+' '+Path(str(cls.key)+'.pub').read_text())
        cls.signers.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def write(self, path, data):
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(data);path.chmod(0o600)

    def sign(self, path):
        Path(str(path)+'.sig').unlink(missing_ok=True)
        subprocess.run(['/usr/bin/ssh-keygen','-Y','sign','-f',str(self.key),'-n',v.NAMESPACE,str(path)],
                       check=True,capture_output=True)
        Path(str(path)+'.sig').chmod(0o600)

    def document(self, root, doc):
        self.write(root/'RELEASE_MANIFEST.json',(json.dumps(doc,sort_keys=True)+'\n').encode())
        self.sign(root/'RELEASE_MANIFEST.json')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.v3 = self.root/v.V3.name
        self.parent = self.root/v.PARENT.name
        self.stage = self.root/'stage'
        self.runtime = self.root/'runtime'
        for p in (self.v3,self.parent,self.stage,self.runtime):p.mkdir(mode=0o700)
        self.bytes = {}
        def payload(name):
            data=(name+'\n').encode();digest=v.sha(data);self.bytes[digest]=data;return digest
        manual=('direct_local_distinct_admission.py','direct_local_event_admission.py',
            'direct_local_fleet_claim.py','direct_local_manual_auth.py',
            'direct_local_receiver_integration.py','direct_local_signed_split_manual.py',
            'direct_local_workflow.py','estate_policy.py')
        # Deliberately synthetic predecessors: only their test hashes are patched.
        # Real SSH signature verification and every gate function run unchanged.
        self.old={'release':self.v3.name,'owner_uid':os.getuid(),
            'original_runtime':{k:'' for k in (*v.CHANGED,'fleet-policy.json',
                'secrets/clawsweeper-direct-local-release.json','fleet_webhook_server.py')},
            'source_files':{k:'' for k in ('controller/fleet_ci.py','policy/fleet-policy.json',
                'descriptor/clawsweeper-direct-local-release.json',*('manual/'+k for k in manual))},
            'rollback_files':{'runtime/original-'+str(i)+'.py':'' for i in range(11)}}
        self.parent_doc={'release':self.parent.name,'owner_uid':os.getuid(),
            'rollback_current_v3':{'runtime/v3-original-'+str(i)+'.py':'' for i in range(13)}}
        for key in ('original_runtime','source_files','rollback_files'):
            self.old[key]={name:payload(key+':'+name) for name in self.old[key]}
        config=(json.dumps({'physical_disk_reserve_GiB':12,'minimum_admission_free_GiB':14,
            'max_parallel_jobs':2,'execution_mode':'detached','job_memory_MiB':768,
            'workspace_MiB':256,'scope':'test-only'})+'\n').encode()
        self.bytes[v.sha(config)]=config
        self.old['original_runtime']['config.json']=v.sha(config)
        self.parent_doc['source_files']=dict(self.old['source_files'])
        self.parent_doc['source_files']['controller/fleet_ci.py']=payload('successor-controller')
        self.parent_doc['rollback_r8p3']=dict(self.old['rollback_files'])
        self.parent_doc['rollback_current_v3']={key:payload('current-v3:'+key)
            for key in self.parent_doc['rollback_current_v3']}
        self.parent_doc['unit_candidate_sha256']={key:payload('successor-unit:'+key) for key in ('fleet','webhook')}
        for root,doc,control in ((self.v3,self.old,'control/v3_integrity.py'),
                (self.parent,self.parent_doc,'control/direct_local_v3_successor_integrity.py')):
            data=(control+'\n').encode();doc['control_sha256']=v.sha(data)
            self.write(root/control,data);self.sign(root/control)
            for name,digest in doc['source_files'].items():self.write(root/'frozen'/name,self.bytes[digest])
        for name,digest in self.old['rollback_files'].items():self.write(self.v3/'rollback-r8p3'/name,self.bytes[digest])
        for key,path in (('rollback_r8p3','rollback-r8p3'),('rollback_current_v3','rollback-current-v3')):
            for name,digest in self.parent_doc[key].items():self.write(self.parent/path/name,self.bytes[digest])
        for label,digest in self.parent_doc['unit_candidate_sha256'].items():
            self.write(self.parent/'unit'/(label+'-20-direct-local.conf.candidate'),self.bytes[digest])
        self.document(self.v3,self.old)
        self.parent_doc['parent_manifest_sha256']=v.sha((self.v3/'RELEASE_MANIFEST.json').read_bytes())
        self.document(self.parent,self.parent_doc)
        self.patches=[patch.object(v,'V3',self.v3),patch.object(v,'PARENT',self.parent),
            patch.object(v,'V3_HASH',self.parent_doc['parent_manifest_sha256']),
            patch.object(v,'PARENT_HASH',v.sha((self.parent/'RELEASE_MANIFEST.json').read_bytes())),
            patch.object(v.socket,'gethostname',return_value='web')]
        for p in self.patches:p.start()
        inventory=v.current_inventory(self.old,self.parent_doc)
        for name,digest in inventory.items():self.write(self.runtime/name,self.bytes[digest])
        for name in v.CHANGED:
            self.write(self.stage/'rollback/runtime'/name,self.bytes[inventory[name]])
            if name=='config.json': data=(json.dumps({**json.loads(config),**v.CAPACITY},sort_keys=True)+'\n').encode()
            else:data=('capacity-candidate:'+name+'\n').encode()
            self.write(self.stage/'frozen'/name,data)
        self.fleet=self.root/'fleet-unit.conf';self.hook=self.root/'webhook-unit.conf'
        for label,dest in (('fleet',self.fleet),('webhook',self.hook)):
            data=self.bytes[self.parent_doc['unit_candidate_sha256'][label]]
            self.write(dest,data);self.write(self.stage/'rollback/unit'/(label+'-20-direct-local.conf'),data)
            self.write(self.stage/'unit'/(label+'-20-direct-local.conf.candidate'),v.unit_bytes(HEAD)[label])
        self.write(self.stage/v.CONTROL,ENTRY.read_bytes())
        self.sign(self.stage/v.CONTROL)
        self.manifest=v.build_manifest(self.stage,HEAD,signers=self.signers)
        self.document(self.stage,self.manifest)

    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()

    def check(self,mode='staged',head=HEAD):
        return v.verify(mode,self.stage,self.runtime,self.fleet,self.hook,self.signers,head)

    def install(self):
        for name in v.CHANGED:shutil.copyfile(self.stage/'frozen'/name,self.runtime/name)
        shutil.copyfile(self.stage/'unit/fleet-20-direct-local.conf.candidate',self.fleet)
        shutil.copyfile(self.stage/'unit/webhook-20-direct-local.conf.candidate',self.hook)

    def test_signed_staged_install_and_rollback(self):
        self.assertFalse(self.check()['production_installed'])
        self.install();result=self.check('installed')
        self.assertTrue(result['production_installed']);self.assertEqual(result['changed_runtime_files_verified'],4)
        for name in v.CHANGED:shutil.copyfile(self.stage/'rollback/runtime'/name,self.runtime/name)
        shutil.copyfile(self.stage/'rollback/unit/fleet-20-direct-local.conf',self.fleet)
        shutil.copyfile(self.stage/'rollback/unit/webhook-20-direct-local.conf',self.hook)
        self.assertFalse(self.check()['production_installed'])

    def test_signature_tamper_rejected(self):
        self.write(self.stage/'RELEASE_MANIFEST.json.sig',b'invalid-signature\n')
        with self.assertRaisesRegex(ValueError,'invalid_owner_signature'):self.check()

    def test_signed_expansion_of_runtime_scope_rejected(self):
        self.manifest['changed_runtime']['fleet_webhook_server.py']='0'*64
        self.document(self.stage,self.manifest)
        with self.assertRaisesRegex(ValueError,'scope_or_identity'):self.check()

    def test_wrong_source_head_rejected(self):
        with self.assertRaisesRegex(ValueError,'scope_or_identity'):self.check(head='b'*40)

    def test_candidate_tamper_rejected(self):
        self.write(self.stage/'frozen/fleet_ci.py',b'tampered\n')
        with self.assertRaises(ValueError):self.check()

    def test_rollback_tamper_rejected(self):
        self.write(self.stage/'rollback/runtime/local_ci.py',b'tampered\n')
        with self.assertRaisesRegex(ValueError,'digest_mismatch'):self.check()

    def test_live_unrelated_runtime_tamper_rejected(self):
        self.write(self.runtime/'fleet_webhook_server.py',b'tampered\n')
        with self.assertRaisesRegex(ValueError,'digest_mismatch'):self.check()

    def test_stale_loaded_unit_rejected(self):
        self.install();self.write(self.hook,b'old-preflight\n')
        with self.assertRaisesRegex(ValueError,'digest_mismatch'):self.check('installed')

    def test_signed_unrelated_config_change_rejected(self):
        path=self.stage/'frozen/config.json';value=json.loads(path.read_text());value['job_memory_MiB']=123
        self.write(path,(json.dumps(value)+'\n').encode())
        self.manifest=v.build_manifest(self.stage,HEAD,signers=self.signers);self.document(self.stage,self.manifest)
        with self.assertRaisesRegex(ValueError,'unrelated_or_invalid_config_change'):self.check()

    def test_extra_helper_and_symlink_rejected(self):
        self.write(self.runtime/'clawsweeper-manual-code-v3/unverified.py',b'bad\n')
        with self.assertRaisesRegex(ValueError,'unexpected_release_entries'):self.check()
        (self.runtime/'clawsweeper-manual-code-v3/unverified.py').unlink()
        original=self.stage/'rollback/runtime';original.rename(self.stage/'saved-rollback')
        original.symlink_to(self.stage/'saved-rollback',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'unsafe_directory'):self.check()

if __name__=='__main__':unittest.main()
