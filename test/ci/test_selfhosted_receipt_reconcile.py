import hashlib
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[2]/'scripts/ci'))
import reconcile_selfhosted_receipt as recon


class LateReconciliation(unittest.TestCase):
    def fixture(self,root,conclusion='success',issues=None):
        receipts=Path(root)/'receipts';receipts.mkdir(mode=0o700)
        directory=receipts/'run-123-job-456-attempt-1'; directory.mkdir(mode=0o700)
        log=b'original log contents\n'; (directory/'runner.log').write_bytes(log)
        r={'schema':'clawsweeper.selfhosted-jit.v1', 'runner_name':'csw-ci-123-456-1',
           'run_id':123,'job_id':456,'attempt':1,'head_sha':'a'*40,'runner_id':99,
           'state':'held','finished_at':'2026-11-06T23:42:00Z','runner_exit':0,
           'issues':issues or ['owned_cleanup_unverified'],
           'log_sha256':hashlib.sha256(log).hexdigest(),
           'github_job':{'conclusion':conclusion}}
        (directory/'receipt.json').write_text(json.dumps(r))
        run={'id':123,'head_sha':'a'*40,'run_attempt':1,
             'repository':{'full_name':'AyobamiH/clawsweeper'}}
        job={'id':456,'run_id':123,'runner_name':'csw-ci-123-456-1',
             'status':'completed','conclusion':conclusion}
        return receipts,directory,run,job

    def test_late_cleanup_keeps_original_held_and_appends_exact_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            receipts,directory,run,job=self.fixture(td)
            before=(directory/'receipt.json').read_bytes()
            with patch.object(recon,'RECEIPTS',receipts),patch.object(recon,'inspect_owned',return_value=None) as docker, \
                 patch.object(recon,'runner_absent_verified',return_value=True), \
                 patch.object(recon,'gh',side_effect=lambda p:run if '/actions/runs/' in p else job):
                result=recon.reconcile(directory)
                self.assertEqual(result['decision'],'late_cleanup_verified')
                self.assertEqual(docker.call_count,2)
            self.assertEqual((directory/'receipt.json').read_bytes(),before)
            added=json.loads((directory/'late-cleanup-reconciliation.json').read_text())
            self.assertEqual(added['original_state'],'held')
            self.assertEqual(stat.S_IMODE((directory/'late-cleanup-reconciliation.json').stat().st_mode),0o600)
            self.assertEqual(added['original_receipt_sha256'],hashlib.sha256(before).hexdigest())

    def test_completed_failed_codeql_cannot_be_made_successful_by_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            receipts,directory,run,job=self.fixture(td,conclusion='failure',issues=['github_job_not_successful','owned_cleanup_unverified'])
            with patch.object(recon,'RECEIPTS',receipts),patch.object(recon,'inspect_owned',return_value=None), \
                 patch.object(recon,'runner_absent_verified',return_value=True), \
                 patch.object(recon,'gh',side_effect=lambda p:run if '/actions/runs/' in p else job):
                self.assertEqual(recon.reconcile(directory)['decision'],'cleanup_only_no_acceptance')

    def test_existing_addendum_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            receipts,directory,run,job=self.fixture(td)
            (directory/'late-cleanup-reconciliation.json').write_text('{}')
            with patch.object(recon,'RECEIPTS',receipts):
                with self.assertRaisesRegex(RuntimeError,'reconciliation_already_exists'):
                    recon.reconcile(directory)

    def test_container_still_owned_refuses_addendum(self):
        with tempfile.TemporaryDirectory() as td:
            receipts,directory,run,job=self.fixture(td)
            with patch.object(recon,'RECEIPTS',receipts),patch.object(recon,'inspect_owned',return_value={'present':True}):
                with self.assertRaisesRegex(RuntimeError,'container_still_present'):
                    recon.reconcile(directory)
            self.assertFalse((directory/'late-cleanup-reconciliation.json').exists())


    def test_verified_replacement_held_receipt_reconciles_without_rewriting_sources(self):
        with tempfile.TemporaryDirectory() as td:
            receipts,original_dir,run,job=self.fixture(td)
            base='csw-ci-123-456-1'
            label='clawsweeper-ci-security-123-javascript-typescript'
            image='sha256:'+'f'*64

            def save(path,payload):
                path.write_text(json.dumps(payload,sort_keys=True))
                path.chmod(0o600)

            original={
                'schema':'clawsweeper.selfhosted-jit.v1',
                'runner_name':base,'run_id':123,'job_id':456,'attempt':1,
                'head_sha':'a'*40,'runner_id':99,'state':'runner_started',
                'role':'security','workflow':'.github/workflows/codeql.yml',
                'label':label,'image_sha256':image,
            }
            save(original_dir/'receipt.json',original)
            digest=hashlib.sha256((original_dir/'receipt.json').read_bytes()).hexdigest()
            proof={
                'schema':'clawsweeper.jit-interrupted-recovery.v1',
                'decision':'cleanup_verified_no_replay',
                'original_receipt_sha256':digest,'original_state':'runner_started',
                'runner_name':base,'head_sha':'a'*40,'run_id':123,
                'job_id':456,'attempt':1,'runner_absent':True,
                'owned_containers_absent':True,'new_registration_attempted':False,
                'release_acceptance':False,
                'github_job':{'id':456,'run_id':123,'status':'queued','conclusion':None},
            }
            save(original_dir/'interrupted-recovery-proof.json',proof)
            save(original_dir/'interrupted-recovery-intent.json',{
                'schema':'clawsweeper.jit-interrupted-intent.v1',
                'original_receipt_sha256':digest,'runner_name':base,
                'head_sha':'a'*40,'run_id':123,'job_id':456,'attempt':1,
                'replay_registration':False,
            })
            replacement=receipts/(original_dir.name+'-replacement-1')
            replacement.mkdir(mode=0o700)
            trace=b'replacement terminal local test trace'
            (replacement/'runner.log').write_bytes(trace)
            (replacement/'runner.log').chmod(0o600)
            name=base+'-replacement-1'
            new_receipt={
                'schema':'clawsweeper.selfhosted-jit.v1','runner_name':name,
                'run_id':123,'job_id':456,'attempt':1,'head_sha':'a'*40,
                'runner_id':100,'state':'held','finished_at':'2026-11-10T03:00:00Z',
                'runner_exit':0,'issues':['owned_cleanup_unverified'],
                'log_sha256':hashlib.sha256(trace).hexdigest(),
                'github_job':{'conclusion':'success','runner_name':name},
                'role':'security','workflow':'.github/workflows/codeql.yml',
                'label':label,'image_sha256':image,'replacement_for':base,
                'original_receipt_sha256':digest,
                'replacement_proof_sha256':hashlib.sha256(
                    (original_dir/'interrupted-recovery-proof.json').read_bytes()).hexdigest(),
            }
            save(replacement/'receipt.json',new_receipt)
            job['runner_name']=name
            job['labels']=['self-hosted','Linux','X64',label]
            base_bytes=(original_dir/'receipt.json').read_bytes()
            replacement_bytes=(replacement/'receipt.json').read_bytes()
            with patch.object(recon,'RECEIPTS',receipts),                 patch.object(recon,'inspect_owned',return_value=None),                 patch.object(recon,'runner_absent_verified',return_value=True),                 patch.object(recon,'gh',side_effect=lambda p:run if '/actions/runs/' in p else job):
                tampered=dict(proof,runner_absent=False)
                save(original_dir/'interrupted-recovery-proof.json',tampered)
                with self.assertRaisesRegex(RuntimeError,'replacement_cleanup_proof_invalid'):
                    recon.reconcile(replacement)
                self.assertFalse((replacement/'late-cleanup-reconciliation.json').exists())
                save(original_dir/'interrupted-recovery-proof.json',proof)
                outcome=recon.reconcile(replacement)
                self.assertEqual(outcome['decision'],'late_cleanup_verified')
                self.assertEqual(outcome['runner_name'],name)
                self.assertEqual(outcome['replacement']['original_receipt_sha256'],digest)
            self.assertEqual((original_dir/'receipt.json').read_bytes(),base_bytes)
            self.assertEqual((replacement/'receipt.json').read_bytes(),replacement_bytes)

if __name__=='__main__':unittest.main()
