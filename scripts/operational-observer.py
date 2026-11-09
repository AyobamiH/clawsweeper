#!/usr/bin/env python3
"""Read-only ClawSweeper operational admission observer.

Runs one bounded snapshot under an exclusive flock. Never executes operational
workflows or replays their effects. Atomic receipts and idempotent observations.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

from importlib.machinery import SourceFileLoader
inventory = SourceFileLoader('admission_inventory', str(Path(__file__).with_name('operational-admission-inventory.py'))).load_module()

DEFAULT_ROOT=Path.home()/'.local/share/local-ci/clawsweeper-operational-observer'
REPO='AyobamiH/clawsweeper'

def atomic(path, obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.'+path.name+'.')
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(obj,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        dirfd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def github(args, timeout=15):
    p=subprocess.run(['gh','api',*args],capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError('GitHub read failed: '+p.stderr[:180])
    return json.loads(p.stdout)

def observe(root,checkout,fetch=github,now=None):
    root.mkdir(parents=True,exist_ok=True)
    lock=open(root/'owner.lock','a+')
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close();return {'state':'held_by_other_owner','effect_count':0}
    try:
        db=sqlite3.connect(root/'observations.sqlite3',timeout=5)
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS observations (identity TEXT PRIMARY KEY, receipt TEXT NOT NULL, observed_at TEXT NOT NULL)')
            # Read the actual remote head before claiming any exact-head observation.
            head=fetch(['repos/'+REPO+'/commits/main'])['sha']
            local=subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()
            if local!=head:raise RuntimeError('Checkout head is stale; refusing observation')
            snapshot=inventory.inventory(checkout)
            workflow='exact-review-dead-letter-reconcile.yml'
            record=next(w for w in snapshot['workflows'] if w['workflow']==workflow)
            assert record['scheduled'] and not record['admitted_for_execution']
            runs=fetch(['repos/'+REPO+'/actions/workflows/'+workflow+'/runs?per_page=3'])
            rows=[]
            for item in runs.get('workflow_runs',[]):
                rows.append({'id':item['id'],'head_sha':item['head_sha'],'event':item['event'],'status':item['status'],'conclusion':item['conclusion']})
            digest=hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()
            key=hashlib.sha256((head+record['sha256']+digest).encode()).hexdigest()
            old=db.execute('SELECT receipt FROM observations WHERE identity=?',(key,)).fetchone()
            if old:
                return {'state':'already_observed','identity':key,'receipt':old[0],'effect_count':0}
            timestamp=(now or dt.datetime.now(dt.timezone.utc)).isoformat()
            receipt={'schema_version':1,'state':'observed','mode':'read_only','effect_count':0,'observed_at':timestamp,
                     'source_sha':head,'workflow_sha256':record['sha256'],'workflow':workflow,
                     'workflow_admitted':False,'run_count':len(rows),'runs':rows,'identity':key,
                     'limits':['GitHub API metadata only','No operational execution','No credentialed provider access','No recovery or queue replay']}
            destination=root/'receipts'/(key+'.json')
            atomic(destination,receipt)
            db.execute('INSERT INTO observations VALUES (?,?,?)',(key,str(destination),timestamp));db.commit()
            return {'state':'observed','identity':key,'receipt':str(destination),'effect_count':0}
        finally:db.close()
    finally:fcntl.flock(lock,fcntl.LOCK_UN);lock.close()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--checkout',type=Path,required=True)
    ap.add_argument('--state',type=Path,default=DEFAULT_ROOT)
    args=ap.parse_args()
    try:result=observe(args.state,args.checkout)
    except Exception as e:
        print(json.dumps({'state':'error','error':str(e)[:250],'effect_count':0}),file=sys.stderr);sys.exit(1)
    print(json.dumps(result,sort_keys=True))
    if result['state']=='held_by_other_owner':sys.exit(75)

if __name__=='__main__':main()
