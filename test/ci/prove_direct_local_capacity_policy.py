#!/usr/bin/env python3
"""Explicit, effect-free proof against the exact installed source baseline.

Requires --baseline; never silently skips the owner-source integration proof.
Docker/systemd launches are intercepted and SQLite exists only in memory.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]/'scripts/ci'
if SOURCE.is_dir(): sys.path.insert(0,str(SOURCE))
import direct_local_capacity_policy as renderer

GIB=1024**3
MIB=1024**2


def definitions(raw, names):
    source=ast.parse(raw)
    body=[node for node in source.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names]
    if {node.name for node in body} != set(names): raise AssertionError('Expected runtime functions missing')
    return compile(ast.Module(body=body,type_ignores=[]),'<actual-rendered-runtime-functions>','exec')


class ActualRuntimeProof(unittest.TestCase):
    baseline = None
    candidate = None

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        (self.root/'config.json').write_bytes(self.candidate['config.json'])
        (self.root/'config.json').chmod(0o600)
        self.core=types.ModuleType('disposable_capacity_core')
        exec(compile(self.candidate['local_ci.py'],'<actual-local-ci>','exec'),self.core.__dict__)
        self.core.ROOT=self.root
        self.resources={'windows_free_bytes':8*GIB,'linux_free_bytes':100*GIB,
                        'available_memory_bytes':16*GIB,'retained_bytes':0}
        self.core.resources=lambda:dict(self.resources)
        self.fleet=types.ModuleType('fleet_ci')
        self.fleet.__dict__.update(core=self.core,ROOT=self.root,HOST='web',ENGINE='docker',
            json=json,os=os,time=time,subprocess=subprocess,
            NAME=re.compile(r'local-fleet-[0-9a-f]{12}\Z'),inspect=lambda *a,**k:{'SizeRw':0})
        exec(definitions(self.candidate['fleet_ci.py'],{'guard','configured_parallelism','bounded_command'}),self.fleet.__dict__)
        self.fleet.validate_job=lambda job,policy:None
        self.detached=types.ModuleType('disposable_capacity_detached')
        with patch.dict(sys.modules,{'fleet_ci':self.fleet}):
            exec(compile(self.candidate['fleet_detached.py'],'<actual-fleet-detached>','exec'),self.detached.__dict__)
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row
        self.db.execute('''CREATE TABLE jobs(id TEXT PRIMARY KEY,repo TEXT,sha TEXT,suite TEXT,
            policy TEXT,ref TEXT,state TEXT,attempt INTEGER,ready_at REAL,created_at TEXT,updated_at TEXT)''')
        self.repo='AyobamiH/clawsweeper'
        self.policy={'repositories':{self.repo:{'suites':{'check':{'memory_mib':1024,'writable_mib':4096,'cpus':1}}}},
                     'execution_hosts':{self.repo:'web'}}
        self.job_ids=['local-fleet-111111111111','local-fleet-222222222222']
        for number,ident in enumerate(self.job_ids):
            self.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                (ident,self.repo,'9'*40,'check','a'*64,'local-manual','queued',0,0,str(number),'before'))
        self.db.commit()

    def tearDown(self): self.db.close();self.temp.cleanup()

    def configure_parallelism(self,value):
        cfg=json.loads((self.root/'config.json').read_text());cfg['max_parallel_jobs']=value
        (self.root/'config.json').write_text(json.dumps(cfg))

    def dispatch(self):
        with patch.object(self.detached.os,'sched_getaffinity',return_value={0,1,2,3}), \
             patch.object(self.detached.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as launch:
            result=self.detached.dispatch(self.db,self.policy,10)
        return result,launch.call_count

    def existing_lease(self,disk=4608*MIB):
        self.detached.init(self.db)
        self.db.execute("UPDATE jobs SET state='claimed' WHERE id=?",(self.job_ids[0],))
        self.db.execute('INSERT INTO detached_leases VALUES(?,?,?,?,?,?,?,?)',
            (self.job_ids[0],'b'*32,'local-ci-job-'+self.job_ids[0]+'-'+'b'*8,'[0]',1408*MIB,disk,time.time(),time.time()))
        self.db.commit()

    def test_real_claw_guard_exact_lower_boundary(self):
        self.resources['windows_free_bytes']=int(6.5*GIB)
        self.assertEqual(self.fleet.guard(1024,4096),[])
        self.resources['windows_free_bytes']-=1
        self.assertEqual(self.fleet.guard(1024,4096),['physical disk headroom below the reviewed job profile'])

    def test_real_linux_capacity_is_also_required(self):
        self.resources['windows_free_bytes']=100*GIB
        self.resources['linux_free_bytes']=int(6.5*GIB)-1
        self.assertTrue(self.fleet.guard(1024,4096))

    def test_existing_profiles_keep_their_distinct_reservations(self):
        for writable,floor in ((1536,4),(2048,4.5),(4096,6.5)):
            with self.subTest(writable=writable):
                self.resources['windows_free_bytes']=int(floor*GIB)
                self.assertEqual(self.fleet.guard(1024,writable),[])
                self.resources['windows_free_bytes']-=1
                self.assertTrue(self.fleet.guard(1024,writable))

    def test_memory_hold_is_unchanged(self):
        self.resources.update(windows_free_bytes=100*GIB,available_memory_bytes=1408*MIB-1)
        self.assertEqual(self.fleet.guard(1024,4096),['RAM admission reserve unavailable'])

    def test_generic_admission_keeps_memory_and_evidence_guards(self):
        good={**self.resources,'windows_free_bytes':4*GIB,'available_memory_bytes':1280*MIB}
        self.assertEqual(self.core.admission(good),[])
        self.assertIn('less than 1280 MiB available RAM',self.core.admission({**good,'available_memory_bytes':1280*MIB-1}))
        self.assertIn('evidence/log budget nearly full; archive proof before accepting work',self.core.admission({**good,'retained_bytes':90*MIB}))

    def test_actual_dispatch_admits_one_at_boundary_and_not_another_tick(self):
        self.resources['windows_free_bytes']=int(6.5*GIB)
        admitted,calls=self.dispatch()
        self.assertEqual((len(admitted),calls),(1,1))
        self.assertEqual(admitted[0]['id'],self.job_ids[0])
        self.assertEqual(self.db.execute('SELECT disk_bytes FROM detached_leases').fetchone()[0],4608*MIB)
        again,calls=self.dispatch()
        self.assertEqual((again,calls),([],0))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM jobs WHERE state='queued'").fetchone()[0],1)

    def test_actual_dispatch_denies_one_byte_below_boundary(self):
        self.resources['windows_free_bytes']=int(6.5*GIB)-1
        self.assertEqual(self.dispatch(),([],0))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM detached_leases').fetchone()[0],0)

    def test_existing_lease_blocks_second_worker_despite_plentiful_disk(self):
        self.resources['windows_free_bytes']=100*GIB
        self.existing_lease()
        self.assertEqual(self.dispatch(),([],0))

    def test_lease_disk_reservations_still_subtracted(self):
        self.configure_parallelism(2)
        self.resources['windows_free_bytes']=11*GIB-1
        self.existing_lease()
        self.assertEqual(self.dispatch(),([],0))
        self.resources['windows_free_bytes']=11*GIB
        result,calls=self.dispatch()
        self.assertEqual((len(result),calls),(1,1))
        self.assertEqual(result[0]['id'],self.job_ids[1])

    def test_malformed_config_prevents_dispatch_before_launch(self):
        (self.root/'config.json').write_text('{malformed')
        with patch.object(self.detached.subprocess,'run') as launch:
            with self.assertRaises(ValueError): self.detached.dispatch(self.db,self.policy,10)
            launch.assert_not_called()

    def test_legacy_defaults_remain_conservative(self):
        (self.root/'config.json').unlink()
        self.resources['windows_free_bytes']=int(16.5*GIB)-1
        self.assertTrue(self.fleet.guard(1024,4096))
        self.resources['windows_free_bytes']+=1
        self.assertEqual(self.fleet.guard(1024,4096),[])

    def watchdog(self,free,log_bytes=0):
        class Process:
            def __init__(self):self.calls=0;self.returncode=None;self.terminated=False
            def poll(self):
                self.calls+=1
                if self.calls>=4 and self.returncode is None:self.returncode=0
                return self.returncode
            def terminate(self):self.terminated=True;self.returncode=-15
            def wait(self,**kwargs):return self.returncode
            def kill(self):self.terminated=True;self.returncode=-9
        process=Process();log=self.root/'job.log'
        with log.open('wb') as f:f.truncate(log_bytes)
        with patch.object(self.fleet.subprocess,'Popen',return_value=process), \
             patch.object(self.fleet.time,'sleep'), \
             patch.object(self.core.shutil,'disk_usage',return_value=types.SimpleNamespace(free=free)), \
             patch.object(self.fleet.os,'sched_getaffinity',return_value={0}):
            try:return self.fleet.bounded_command('disposable','true',log,30,{'writable_mib':4096})
            finally:self.last_process=process

    def test_running_job_stops_below_two_gib_reserve(self):
        with self.assertRaisesRegex(RuntimeError,'Physical disk reserve reached'):
            self.watchdog(2*GIB-1)
        self.assertTrue(self.last_process.terminated)

    def test_running_job_is_not_stopped_by_obsolete_twelve_gib_floor(self):
        self.assertEqual(self.watchdog(3*GIB),0)
        self.assertFalse(self.last_process.terminated)

    def test_running_job_log_cap_unchanged(self):
        with self.assertRaisesRegex(RuntimeError,'Per-job log cap reached'):
            self.watchdog(100*GIB,10*MIB+1)

    def test_no_unrelated_functions_or_config_fields_changed(self):
        permitted={'local_ci.py':{'disk_policy','admission','run_job'},
                   'fleet_ci.py':{'guard','bounded_command','parallel_work'},
                   'fleet_detached.py':{'dispatch'}}
        for name,functions in permitted.items():
            def remainder(raw):
                tree=ast.parse(raw)
                tree.body=[n for n in tree.body if not (isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in functions)]
                return ast.dump(tree,include_attributes=False)
            self.assertEqual(remainder(self.baseline[name]),remainder(self.candidate[name]),name)
        old=json.loads(self.baseline['config.json']);new=json.loads(self.candidate['config.json'])
        self.assertEqual({k:v for k,v in old.items() if k not in renderer.CAPACITY},
                         {k:v for k,v in new.items() if k not in renderer.CAPACITY})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    original={name:(args.baseline/name).read_bytes() for name in renderer.BASELINE}
    candidate=renderer.render_runtime(original)
    ActualRuntimeProof.baseline=original;ActualRuntimeProof.candidate=candidate
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ActualRuntimeProof))
    report={'schema':'clawsweeper.capacity-exact-source-disposable-proof.v1',
            'passed':result.wasSuccessful(),'tests_run':result.testsRun,
            'failures':len(result.failures),'errors':len(result.errors),
            'baseline_sha256':{k:renderer.sha(v) for k,v in original.items()},
            'candidate_sha256':{k:renderer.sha(v) for k,v in candidate.items()},
            'real_runtime_functions_exercised':True,'disposable_sqlite_only':True,
            'docker_or_systemd_jobs_launched':False,'live_queue_mutations':False,
            'production_acceptance_claimed':False}
    if args.report:
        with args.report.open('x') as f:
            os.fchmod(f.fileno(),0o600);json.dump(report,f,sort_keys=True,indent=2);f.write('\n')
            f.flush();os.fsync(f.fileno())
    print(json.dumps(report,sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__': sys.exit(main())
