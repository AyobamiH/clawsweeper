#!/usr/bin/env python3
"""Cross-host CircleCI dispatch ledger using GitHub GraphQL optimistic CAS.

This ledger reserves the *provider side effect* before any pipeline POST. The
GitHub private state branch is the shared authority; neither host's SQLite DB
alone confers provider ownership. Unknown requests are never replayed.
"""
import argparse,base64,datetime,json,os,pathlib,re,subprocess,sys,uuid

REPO='AyobamiH/clawsweeper-state'
BRANCH='ci/standby-ledger-20261102'
FILE='ci/standby-ledger.json'
TARGET='AyobamiH/clawsweeper'
SHA=re.compile(r'[0-9a-f]{40}\Z')
ACTIVE=('dispatch_outcome_uncertain','awaiting_provider_readback','status_pending')
QUERY='mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid url signature{isValid state wasSignedByGitHub}}}}'

def timestamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def gh(path,method='GET',payload=None):
    args=['gh','api']
    if path=='graphql':args.append('graphql')
    else:args.append('repos/'+path if not path.startswith('repos/') else path)
    if method!='GET':args+=['-X',method]
    if payload is not None:args+=['--input','-']
    p=subprocess.run(args,input=json.dumps(payload) if payload is not None else None,
        text=True,capture_output=True,timeout=28)
    if p.returncode!=0:raise RuntimeError('GitHub authority unavailable or mutation rejected: '+p.stderr[:210])
    try:return json.loads(p.stdout)
    except ValueError as exc:raise RuntimeError('GitHub response invalid') from exc

def validate(state):
    if (not isinstance(state,dict) or state.get('schema_version')!=1
        or state.get('target')!=TARGET or state.get('branch')!=BRANCH
        or not isinstance(state.get('dispatches'),dict) or len(state['dispatches'])>1000):
        raise RuntimeError('Invalid shared ledger identity or shape')
    for sha,rec in state['dispatches'].items():
        if not SHA.fullmatch(sha) or not isinstance(rec,dict) or rec.get('sha')!=sha:
            raise RuntimeError('Invalid dispatch record')
        if rec.get('state') not in ACTIVE+('success','failure','error','held'):
            raise RuntimeError('Unrecognised dispatch lifecycle')
    return state

def read():
    ref=gh(REPO+'/git/ref/heads/'+BRANCH)
    head=ref['object']['sha']
    if not SHA.fullmatch(head):raise RuntimeError('Noncanonical coordination head')
    result=gh(REPO+'/contents/'+FILE+'?ref='+head)
    if result.get('encoding')!='base64' or result.get('type')!='file':
        raise RuntimeError('Coordination file not authenticated')
    raw=base64.b64decode(result['content'])
    if len(raw)>220000:raise RuntimeError('Coordination history exceeds cap')
    state=validate(json.loads(raw))
    return head,state

def commit(head,state,message):
    validate(state)
    if not SHA.fullmatch(head):raise RuntimeError('Invalid expected GitHub head')
    additions=[{'path':FILE,'contents':base64.b64encode((json.dumps(state,indent=2,sort_keys=True)+'\n').encode()).decode()}]
    data={'query':QUERY,'variables':{'input':{
        'branch':{'repositoryNameWithOwner':REPO,'branchName':BRANCH},
        'expectedHeadOid':head,
        'message':{'headline':message[:120]},
        'fileChanges':{'additions':additions}}}}
    result=gh('graphql',payload=data)
    if result.get('errors'):
        raise RuntimeError('Shared ledger CAS refused; reread before any provider side effect')
    obj=result.get('data',{}).get('createCommitOnBranch',{}).get('commit',{})
    if not SHA.fullmatch(obj.get('oid','')) or not obj.get('signature',{}).get('isValid'):
        raise RuntimeError('Shared ledger commit signature unverified')
    return obj['oid']

def claim(owner,sha,reason,heartbeat_evidence,credit_proof):
    if owner not in ('web','Ayobami-Dev') or not SHA.fullmatch(sha):raise ValueError('Unapproved identity')
    if reason not in ('real_resource_hold','primary_heartbeat_expired'):raise ValueError('Unapproved failover reason')
    if not isinstance(credit_proof,dict) or credit_proof.get('plan')!='Free' or credit_proof.get('paid_overage') is not False:
        raise RuntimeError('Free account not proven')
    if not isinstance(credit_proof.get('available_credits'),int) or credit_proof['available_credits']<2000:
        raise RuntimeError('Free credit headroom not proven')
    age=datetime.datetime.now(datetime.timezone.utc).timestamp()-credit_proof.get('checked_at_epoch',0)
    if not 0<=age<=3600 or credit_proof.get('reserved_credits',0)<2000:
        raise RuntimeError('Free credit evidence expired or missing reserve')
    if not isinstance(heartbeat_evidence,dict):raise RuntimeError('Heartbeat admission missing')
    if owner=='Ayobami-Dev':
        if (reason!='primary_heartbeat_expired'
            or heartbeat_evidence.get('kind')!='primary_heartbeat_expired'
            or heartbeat_evidence.get('comment_id')!=6572526731
            or not isinstance(heartbeat_evidence.get('age_seconds'),(int,float))
            or heartbeat_evidence['age_seconds']<900):
            raise RuntimeError('Independent primary-offline evidence missing')
    elif reason!='real_resource_hold' or heartbeat_evidence.get('kind')!='real_host_guard':
        raise RuntimeError('Primary real resource hold missing')
    current=gh('AyobamiH/clawsweeper/git/ref/heads/main')['object']['sha']
    if current!=sha:raise RuntimeError('Source main head moved')
    head,state=read()
    if any(v.get('state') in ACTIVE for v in state['dispatches'].values()):
        raise RuntimeError('Another provider dispatch is owned or uncertain')
    if sha in state['dispatches']:
        raise RuntimeError('Exact-SHA dispatch already recorded, never replay')
    nonce=str(uuid.uuid4())
    record={'sha':sha,'owner':owner,'reason':reason,'nonce':nonce,
        'state':'dispatch_outcome_uncertain','pipeline_id':None,
        'claimed_at':timestamp(),'heartbeat_evidence':heartbeat_evidence,
        'billing_proof':{k:credit_proof.get(k) for k in
            ('plan','paid_overage','available_credits','reserved_credits','checked_at_epoch')}}
    state['dispatches'][sha]=record
    commit(head,state,'ci: reserve CircleCI side effect for '+sha[:12]+' on '+owner)
    verified_head,verified=read()
    if verified['dispatches'].get(sha,{}).get('nonce')!=nonce:
        raise RuntimeError('Reserved provider ownership not read back')
    return record

def update(sha,nonce,state_name,pipeline_id=None,status_id=None,receipt_sha256=None):
    if not SHA.fullmatch(sha) or state_name not in ACTIVE+('success','failure','error','held'):
        raise ValueError('Invalid provider update')
    head,state=read()
    record=state['dispatches'].get(sha)
    if not record or record.get('nonce')!=nonce:raise RuntimeError('Not the owner of recorded provider dispatch')
    old=record['state']
    if old in ('success','failure','error') and old!=state_name:
        raise RuntimeError('Terminal provider outcome immutable')
    if pipeline_id is not None:
        if not isinstance(pipeline_id,str) or str(uuid.UUID(pipeline_id))!=pipeline_id:
            raise ValueError('Invalid provider pipeline UUID')
        if record.get('pipeline_id') and record['pipeline_id']!=pipeline_id:
            raise RuntimeError('Different provider pipeline identity already recorded')
        record['pipeline_id']=pipeline_id
    if state_name in ('success','failure','error'):
        if not record.get('pipeline_id'):
            raise RuntimeError('Cannot close without provider pipeline identity')
        if (not isinstance(status_id,int) or status_id<1 or not isinstance(receipt_sha256,str)
            or re.fullmatch(r'[0-9a-f]{64}',receipt_sha256) is None):
            raise RuntimeError('Verified provider receipt and GitHub status evidence required')
        if record.get('github_status_id') and record['github_status_id']!=status_id:
            raise RuntimeError('Conflicting GitHub status identity')
        record['github_status_id']=status_id
        record['receipt_sha256']=receipt_sha256
    record['state']=state_name;record['updated_at']=timestamp()
    commit(head,state,'ci: CircleCI '+state_name+' '+sha[:12])
    return record

def init():
    head=gh(REPO+'/git/ref/heads/'+BRANCH)['object']['sha']
    state={'schema_version':1,'target':TARGET,'branch':BRANCH,'dispatches':{},
           'created_at':timestamp(),'rule':'No retry after unknown provider POST; exact SHA and CAS ownership required'}
    print(json.dumps({'initialized_head':commit(head,state,'ci: initialise two-host failover CAS ledger')}))

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['init','show']);a=p.parse_args()
    if a.mode=='init':init()
    else:
        head,state=read();print(json.dumps({'head':head,'state':state},indent=2))
if __name__=='__main__':main()
