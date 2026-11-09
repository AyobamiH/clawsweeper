#!/usr/bin/env python3
"""Read-only, fail-closed inventory of GitHub operational workflow migration candidates.

Never executes workflows, reads secret values, schedules jobs or changes runner settings.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import yaml

MUTATING = re.compile(r'\b(gh\s+(?:api|workflow|run|pr|issue)|curl\b|wrangler\b|git\s+push|pnpm\s+(?:run\s+)?(?:repair|review|apply|dashboard:deploy))\b', re.I)
EXPRESSION = re.compile(r'\$\{\{\s*(?:secrets|vars|github\.token)\b', re.I)

def inventory(root: Path):
    base = root / '.github' / 'workflows'
    if not base.is_dir():
        raise ValueError('Workflow directory missing')
    results = []
    for path in sorted(base.glob('*.yml')):
        source = path.read_text()
        data = yaml.safe_load(source)
        if not isinstance(data, dict) or not isinstance(data.get('jobs'), dict):
            raise ValueError(f'Invalid workflow jobs: {path.name}')
        triggers = data.get('on', data.get(True, {}))
        if isinstance(triggers, str): triggers = {triggers: None}
        if isinstance(triggers, list): triggers = {x: None for x in triggers}
        if not isinstance(triggers, dict): raise ValueError(f'Invalid triggers: {path.name}')
        scheduled = 'schedule' in triggers
        jobs=[]
        for name, job in data['jobs'].items():
            if not isinstance(job, dict):raise ValueError(f'Invalid job: {path.name}/{name}')
            runner=job.get('runs-on')
            if isinstance(runner, dict) or runner is None:
                runner_kind='dynamic_or_missing'
            elif isinstance(runner, (str,list)):
                labels=[runner] if isinstance(runner,str) else runner
                runner_kind='self_hosted' if 'self-hosted' in labels else 'github_hosted' if any(str(x).startswith(('ubuntu-','windows-','macos-')) for x in labels) else 'unknown'
            else: runner_kind='unknown'
            steps=job.get('steps',[])
            if not isinstance(steps,list):raise ValueError(f'Invalid steps: {path.name}/{name}')
            commands='\n'.join(str(s.get('run','')) for s in steps if isinstance(s,dict))
            secret_references=bool(EXPRESSION.search(json.dumps(job)))
            writes=bool(MUTATING.search(commands))
            # No automatic operational admission: review workflow dependencies, tokens,
            # leases, replay semantics, GitHub events, and source before any migration.
            jobs.append({'id':str(name),'runner_kind':runner_kind,'secret_references':secret_references,
                         'possible_external_effects':writes,'needs_human_contract_review':True,'admitted_for_execution':False})
        results.append({'workflow':path.name,'sha256':hashlib.sha256(source.encode()).hexdigest(),
                        'scheduled':scheduled,'triggers':sorted(str(k) for k in triggers),
                        'job_count':len(jobs),'jobs':jobs,'admitted_for_execution':False})
    return {'schema_version':1,'mode':'read_only_no_execution','workflow_count':len(results),
            'scheduled_count':sum(w['scheduled'] for w in results),'admitted_count':0,
            'workflows':results}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    result=inventory(args.repo)
    payload=json.dumps(result,indent=2,sort_keys=True)+'\n'
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(payload)
    else:sys.stdout.write(payload)

if __name__=='__main__':main()
