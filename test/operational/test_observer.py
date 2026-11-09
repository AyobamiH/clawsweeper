import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
SCRIPT=pathlib.Path(__file__).resolve().parents[2]/'scripts/operational-observer.py'
module=SourceFileLoader('operational_observer',str(SCRIPT)).load_module()
class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=pathlib.Path(self.tmp.name);self.repo=self.base/'repo';self.repo.mkdir()
        subprocess.run(['git','init','-q',str(self.repo)],check=True)
        subprocess.run(['git','-C',str(self.repo),'config','user.name','test'],check=True)
        subprocess.run(['git','-C',str(self.repo),'config','user.email','test@example.test'],check=True)
        subprocess.run(['git','-C',str(self.repo),'config','commit.gpgsign','false'],check=True)
        folder=self.repo/'.github/workflows';folder.mkdir(parents=True)
        (folder/'exact-review-dead-letter-reconcile.yml').write_text("on:\n  schedule:\n    - cron: '0 * * * *'\njobs:\n  reconcile:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n")
        subprocess.run(['git','-C',str(self.repo),'add','.'],check=True)
        subprocess.run(['git','-C',str(self.repo),'commit','-qm','test'],check=True)
        self.head=subprocess.check_output(['git','-C',str(self.repo),'rev-parse','HEAD'],text=True).strip()
        self.runs=[{'id':123,'head_sha':self.head,'event':'schedule','status':'completed','conclusion':'failure'}]
    def fetch(self,args):
        if args[0].endswith('/commits/main'):return {'sha':self.head}
        return {'workflow_runs':self.runs}
    def test_first_observation_then_idempotent(self):
        first=module.observe(self.base/'state',self.repo,self.fetch)
        self.assertEqual(first['state'],'observed');self.assertEqual(first['effect_count'],0)
        receipt=json.loads(pathlib.Path(first['receipt']).read_text());self.assertFalse(receipt['workflow_admitted'])
        second=module.observe(self.base/'state',self.repo,self.fetch)
        self.assertEqual(second['state'],'already_observed');self.assertEqual(first['identity'],second['identity'])
        self.assertEqual(len(list((self.base/'state/receipts').glob('*.json'))),1)
    def test_stale_head_rejected(self):
        self.head='0'*40
        with self.assertRaisesRegex(RuntimeError,'stale'):module.observe(self.base/'state',self.repo,self.fetch)
        self.assertEqual(list((self.base/'state/receipts').glob('*.json')),[])
    def test_changed_external_read_creates_new_receipt(self):
        a=module.observe(self.base/'state',self.repo,self.fetch)
        self.runs=[dict(self.runs[0],id=124)]
        b=module.observe(self.base/'state',self.repo,self.fetch)
        self.assertNotEqual(a['identity'],b['identity'])
    def test_exclusive_lock(self):
        import fcntl
        state=self.base/'state';state.mkdir()
        with open(state/'owner.lock','a+') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            # flock is process-associated; a separate process is required to prove exclusion.
            code='import fcntl,sys; f=open(sys.argv[1],"a+");\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); sys.exit(1)\nexcept BlockingIOError: sys.exit(0)'
            p=subprocess.run(['python3','-c',code,str(state/'owner.lock')]);self.assertEqual(p.returncode,0)
if __name__=='__main__':unittest.main()
