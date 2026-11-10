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

if __name__=='__main__':unittest.main()
