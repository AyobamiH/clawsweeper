import json
import pathlib
import sqlite3
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
SCRIPT=pathlib.Path(__file__).resolve().parents[2]/'scripts/operational-executor.py'
module=SourceFileLoader('operational_executor',str(SCRIPT)).load_module()
class FakeResult:
    def __init__(self,code=0,out='',err=''):
        self.returncode=code;self.stdout=out;self.stderr=err
class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.repo=self.root/'checkout';self.repo.mkdir();self.state=self.root/'state'
        self.receipt=self.root/'receipt.json'
        self.receipt.write_text(json.dumps({'effect_count':0,'workflow_admitted':False,'mode':'read_only'}))
        self.calls=0
    def runner(self,args,**kwargs):
        self.calls+=1
        return FakeResult(out=json.dumps({'state':'observed','receipt':str(self.receipt),'effect_count':0}))
    def test_exactly_once_per_slot(self):
        a=module.execute(self.repo,self.state,now=900,runner=self.runner)
        b=module.execute(self.repo,self.state,now=910,runner=self.runner)
        self.assertEqual(a['state'],'completed');self.assertEqual(b['state'],'already_completed');self.assertEqual(self.calls,1)
    def test_new_slot_runs(self):
        module.execute(self.repo,self.state,now=900,runner=self.runner)
        module.execute(self.repo,self.state,now=1800,runner=self.runner)
        self.assertEqual(self.calls,2)
    def test_crash_recovery(self):
        db=module.connect(self.state)
        db.execute('INSERT INTO tasks(task,slot,state,attempts) VALUES(?,?,?,?)',(module.TASK,1,'running',1));db.close()
        r=module.execute(self.repo,self.state,now=900,runner=self.runner)
        self.assertEqual(r['state'],'completed')
    def test_failed_attempt_retries_bounded(self):
        def fail(*args,**kwargs):return FakeResult(1,err='network unavailable')
        for _ in range(3):self.assertEqual(module.execute(self.repo,self.state,now=900,runner=fail)['state'],'retryable_failure')
        self.assertEqual(module.execute(self.repo,self.state,now=900,runner=fail)['state'],'retry_limit')
    def test_rejects_mutating_receipt(self):
        self.receipt.write_text(json.dumps({'effect_count':1,'workflow_admitted':True,'mode':'mutating'}))
        with self.assertRaisesRegex(RuntimeError,'Invalid read-only'):module.execute(self.repo,self.state,now=900,runner=self.runner)
    def test_rejects_too_short_interval(self):
        with self.assertRaisesRegex(ValueError,'Minimum interval'):module.execute(self.repo,self.state,interval=1,runner=self.runner)
if __name__=='__main__':unittest.main()
