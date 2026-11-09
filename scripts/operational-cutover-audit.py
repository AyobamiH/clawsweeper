#!/usr/bin/env python3
"""Generate an exact-source, fail-closed migration contract for every operational job.

Never dispatches, disables or mutates a workflow. No credential values are read.
"""
import argparse
import hashlib
import json
from pathlib import Path
import yaml

def audit(root):
    results=[]
    for file in sorted((root/'.github/workflows').glob('*.yml')):
        data=yaml.safe_load(file.read_text())
        triggers=data.get('on',data.get(True,{}))
        if isinstance(triggers,str):triggers={triggers:None}
        if isinstance(triggers,list):triggers={x:None for x in triggers}
        triggers=triggers or {}
        for name,job in (data.get('jobs') or {}).items():
            if not isinstance(job,dict):continue
            body=json.dumps(job,sort_keys=True)
            deps=job.get('needs',[])
            if isinstance(deps,str):deps=[deps]
            steps=job.get('steps') or []
            actions=[s['uses'] for s in steps if isinstance(s,dict) and 'uses' in s]
            markers={
                'github_app_token':any('create-github-app-token' in a or 'create-target-write-token' in a for a in actions),
                'artifacts':any('artifact' in a for a in actions),
                'state_checkout':any('setup-state' in a for a in actions),
                'codex_or_openclaw':any('codex' in a or 'openclaw' in a for a in actions),
                'queue_or_lease':any(x in body.lower() for x in ['queue_lease','lease_revision','fence_key','queue_url']),
                'write_permissions':any('write' in str(v).lower() for v in (job.get('permissions') or {}).values()),
            }
            results.append({'workflow':file.name,'job':str(name),'workflow_sha256':hashlib.sha256(file.read_bytes()).hexdigest(),
              'job_sha256':hashlib.sha256(body.encode()).hexdigest(),'triggers':sorted(str(k) for k in triggers),
              'dependencies':deps,'markers':markers,'execution':'github_actions_only','migration_state':'not_admitted',
              'required_proof':['exact_source','credential_scope','exclusive_lease','idempotent_effects','crash_recovery','external_readback','rollback'],
              'migration_blocker':'No independently verified equivalent local runtime contract'})
    return {'schema_version':1,'jobs':results,'total_jobs':len(results),'admitted_jobs':0,
      'warning':'This report does not authorise workflow cutover, credential access or mutation.'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args()
    result=audit(a.repo)
    text=json.dumps(result,indent=2)+'\n'
    if a.out:a.out.write_text(text)
    else:print(text)
if __name__=='__main__':main()
