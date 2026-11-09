#!/usr/bin/env python3
"""Fail-closed local operational executor, initially restricted to read-only GitHub observation.

No arbitrary commands, GitHub mutations, production credentials or queue replay.
"""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
STATE=Path.home()/'.local/share/local-ci/clawsweeper-operational-executor'
TASK='github-dead-letter-observation-v1'

def connect(path):
    path.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path/'executor.sqlite3',timeout=10,isolation_level=None)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS tasks (task TEXT NOT NULL, slot INTEGER NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, started_at TEXT, completed_at TEXT, receipt TEXT, error TEXT, PRIMARY KEY(task,slot))')
    return db

def execute(checkout,state=STATE,interval=900,now=None,runner=None):
    if interval<60:raise ValueError('Minimum interval is 60 seconds')
    if not checkout.is_dir():raise ValueError('Checkout not found')
    state.mkdir(parents=True,exist_ok=True)
    with open(state/'executor.lock','a+') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'state':'held','effect_count':0}
        try:
            db=connect(state)
            try:
                stamp=time.time() if now is None else now
                slot=int(stamp//interval)
                old=db.execute('SELECT state,receipt,attempts FROM tasks WHERE task=? AND slot=?',(TASK,slot)).fetchone()
                if old and old[0]=='completed' and old[1] and Path(old[1]).is_file():
                    return {'state':'already_completed','slot':slot,'receipt':old[1],'effect_count':0}
                if old and old[2]>=3:
                    return {'state':'retry_limit','slot':slot,'effect_count':0}
                timestamp=dt.datetime.fromtimestamp(stamp,dt.timezone.utc).isoformat()
                db.execute('INSERT INTO tasks(task,slot,state,attempts,started_at) VALUES(?,?,?,1,?) ON CONFLICT(task,slot) DO UPDATE SET state=excluded.state,attempts=tasks.attempts+1,started_at=excluded.started_at',(TASK,slot,'running',timestamp))
                # Crash-interrupted running records are recoverable. The only
                # permitted effect is an idempotent read-only observation.
                command=[sys.executable,str(HERE/'operational-observer.py'),'--checkout',str(checkout),'--state',str(state/'observer')]
                result=(runner or subprocess.run)(command,capture_output=True,text=True,timeout=90)
                if result.returncode!=0:
                    error=(result.stderr or result.stdout)[-350:]
                    db.execute('UPDATE tasks SET state=?,error=? WHERE task=? AND slot=?',('retryable_failure',error,TASK,slot))
                    return {'state':'retryable_failure','slot':slot,'error':error,'effect_count':0}
                outcome=json.loads(result.stdout)
                if outcome['state'] not in ('observed','already_observed') or outcome.get('effect_count')!=0:
                    raise RuntimeError('Observer returned unapproved result')
                receipt=Path(outcome['receipt'])
                evidence=json.loads(receipt.read_text())
                if evidence['effect_count']!=0 or evidence['workflow_admitted'] is not False or evidence['mode']!='read_only':
                    raise RuntimeError('Invalid read-only receipt')
                db.execute('UPDATE tasks SET state=?,completed_at=?,receipt=?,error=NULL WHERE task=? AND slot=?',('completed',timestamp,str(receipt),TASK,slot))
                return {'state':'completed','slot':slot,'receipt':str(receipt),'effect_count':0}
            finally:db.close()
        finally:fcntl.flock(lock,fcntl.LOCK_UN)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--checkout',type=Path,required=True)
    p.add_argument('--state',type=Path,default=STATE)
    p.add_argument('--interval',type=int,default=900)
    a=p.parse_args()
    try:result=execute(a.checkout,a.state,a.interval)
    except Exception as exc:
        print(json.dumps({'state':'error','error':str(exc)[:250],'effect_count':0}),file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result,sort_keys=True))
    if result['state'] not in ('completed','already_completed'):sys.exit(75)
if __name__=='__main__':main()
