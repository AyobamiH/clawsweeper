#!/usr/bin/env python3
"""Ayobami-Dev's independently fenced, Free-only ClawSweeper standby.

If the primary heartbeat genuinely expires, inspect the exact current main SHA,
existing GitHub statuses, shared CAS ledger, CircleCI project and Free credits.
Reserve an irreversible provider intent in GitHub *before* making a POST.
Unknown dispatches remain fenced; readback never repeats a pipeline request.
"""
import argparse,datetime,fcntl,hashlib,json,os,pathlib,re,requests,socket,stat,sys,time,urllib.parse,uuid
import standby_coord as coord

ROOT=pathlib.Path(__file__).resolve().parent
POLICY=ROOT/'standby-policy.json'
TOKEN=ROOT/'private'/'circleci-token'
STATUS=ROOT/'evidence'/'standby'/'latest.json'
LOCK=ROOT/'state'/'standby-agent.lock'
HEARTBEAT_MARK='clawsweeper-primary-heartbeat-v1'
BUDGET_MARK='clawsweeper-circleci-free-budget-v1'
CONTEXT='ci/circleci: clawsweeper-full-linux-node24'
PRIMARY_CONTEXT='local-ci/linux-node24'
PROJECT='gh/AyobamiH/clawsweeper'
PROVIDER_BASE='https://circleci.com/api/v2'

class Hold(RuntimeError):pass

def when(s):
    d=datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
    if d.tzinfo is None:raise ValueError('Missing timestamp offset')
    return d.timestamp()

def age(s,now=None):
    n=time.time() if now is None else now
    seconds=n-when(s)
    if not -60<=seconds<=30*86400:raise Hold('Authenticated external timestamp implausible')
    return max(0,seconds)

def atomic(path,obj):
    path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    if path.is_symlink():raise Hold('Symlinked status output prohibited')
    temp=path.with_name(path.name+'.tmp')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f:
        json.dump(obj,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    os.replace(temp,path)

def policy():
    if POLICY.is_symlink():raise Hold('Untrusted policy symlink')
    cfg=json.loads(POLICY.read_text())
    if (cfg.get('schema_version')!=1 or cfg.get('target')!=coord.TARGET
        or cfg.get('standby_host')!='Ayobami-Dev'
        or cfg.get('heartbeat_comment_id')!=6572526731
        or cfg.get('budget_comment_id')!=6572605203
        or cfg.get('heartbeat_timeout_seconds')!=900
        or cfg.get('budget_max_age_seconds')!=3600
        or cfg.get('minimum_free_credits')!=2000
        or cfg.get('mode') not in ('observe','dispatch')):
        raise Hold('Unapproved standby control policy')
    return cfg

def private_secret():
    if not TOKEN.is_file() or TOKEN.is_symlink():raise Hold('Dedicated standby CircleCI token unavailable')
    st=TOKEN.stat()
    if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600:
        raise Hold('Standby token permissions not owner-only')
    value=TOKEN.read_text().strip()
    if not 24<=len(value)<=512:raise Hold('Invalid standby CircleCI API token')
    return value

def issue_json(comment_id,marker):
    remote=coord.gh('AyobamiH/clawsweeper-state/issues/comments/'+str(comment_id))
    body=remote.get('body','')
    if (remote.get('id')!=comment_id or remote.get('user',{}).get('login')!='AyobamiH'
        or not isinstance(body,str) or not body.startswith('<!-- '+marker+' -->\n')):
        raise Hold('Private GitHub evidence identity mismatch')
    data=json.loads(body.split('\n',1)[1])
    if not isinstance(data,dict) or data.get('kind')!=marker or data.get('repository')!=coord.TARGET:
        raise Hold('Private GitHub evidence contents invalid')
    if not remote.get('updated_at'):raise Hold('Provider timestamp missing')
    return remote,data

def primary_evidence(cfg,now=None):
    remote,datum=issue_json(cfg['heartbeat_comment_id'],HEARTBEAT_MARK)
    if (datum.get('host')!='web' or datum.get('fleet_timer_active') is not True
        or not re.fullmatch('[0-9a-f]{64}',str(datum.get('controller_sha256','')))
        or not coord.SHA.fullmatch(str(datum.get('main_sha','')))):
        raise Hold('Primary heartbeat content invalid')
    elapsed=age(remote['updated_at'],now)
    return {'kind':'primary_heartbeat_expired' if elapsed>=cfg['heartbeat_timeout_seconds'] else 'primary_heartbeat_recent',
            'comment_id':remote['id'],'server_updated_at':remote['updated_at'],'age_seconds':round(elapsed,2),
            'last_primary_sha':datum['main_sha']}

def budget_evidence(cfg,now=None):
    remote,doc=issue_json(cfg['budget_comment_id'],BUDGET_MARK)
    remote_age=age(remote['updated_at'],now)
    checked=doc.get('checked_at_epoch',0)
    checked_age=(time.time() if now is None else now)-checked
    if (doc.get('provider')!='CircleCI' or doc.get('plan')!='Free'
        or doc.get('paid_overage') is not False or doc.get('source_host')!='web'
        or not isinstance(checked,(int,float)) or not isinstance(doc.get('available_credits'),int)
        or not isinstance(doc.get('reserved_credits'),int)
        or doc['available_credits']<doc['reserved_credits']
        or doc['reserved_credits']<cfg['minimum_free_credits']
        or not 0<=remote_age<=cfg['budget_max_age_seconds']
        or not -60<=checked_age<=cfg['budget_max_age_seconds']):
        raise Hold('Authenticated Free billing proof expired or insufficient')
    return {k:doc[k] for k in ('provider','plan','paid_overage','available_credits','reserved_credits','checked_at_epoch')}

def statuses(sha):
    rows=coord.gh('AyobamiH/clawsweeper/commits/'+sha+'/statuses?per_page=100')
    if not isinstance(rows,list) or len(rows)>=100:
        raise Hold('GitHub commit status evidence incomplete')
    return rows

def latest_context(rows,context):
    return next((s for s in rows if s.get('context')==context),None)

def safe_project(token):
    result=provider('/project/gh/AyobamiH/clawsweeper',token)
    if result.get('slug')!=PROJECT:raise Hold('CircleCI project mismatch')
    return True

def provider(path,token,method='GET',payload=None):
    if not (path.startswith('/project/gh/AyobamiH/clawsweeper')
            or re.fullmatch(r'/pipeline/[a-f0-9-]{36}(?:/workflow)?',path)
            or re.fullmatch(r'/workflow/[a-f0-9-]{36}/job',path)):
        raise Hold('Unapproved provider API path')
    if '?' in path or '..' in path or ':' in path:raise Hold('Unsafe provider API path')
    try:
        response=requests.request(method,PROVIDER_BASE+path,headers={
            'Circle-Token':token,'Accept':'application/json','Content-Type':'application/json'},
            json=payload,timeout=22)
        response.raise_for_status()
        value=response.json()
        if not isinstance(value,dict):raise Hold('Invalid CircleCI API response')
        return value
    except (requests.RequestException,ValueError) as e:
        raise Hold('CircleCI API transport, status or JSON unavailable: '+type(e).__name__) from None

def existing_provider_workflow(sha,token,accepted_pipeline=None,allow_discovery=False):
    page=provider('/project/gh/AyobamiH/clawsweeper/pipeline',token)
    if page.get('next_page_token') or not isinstance(page.get('items'),list):
        raise Hold('CircleCI pipeline inventory incomplete: fail closed')
    found=[]
    for entry in page['items']:
        if entry.get('vcs',{}).get('revision')!=sha:continue
        pid=entry.get('id')
        if not isinstance(pid,str) or str(uuid.UUID(pid))!=pid:raise Hold('Untrusted pipeline identity')
        workflows=provider('/pipeline/'+pid+'/workflow',token)
        if workflows.get('next_page_token') or not isinstance(workflows.get('items'),list):
            raise Hold('CircleCI workflow inventory incomplete')
        for wf in workflows['items']:
            if wf.get('name')=='circleci-free-fallback':found.append(pid)
    if len(set(found))>1:raise Hold('Multiple same-SHA fallback workflows: reconcile manually')
    if found and not allow_discovery and accepted_pipeline not in found:
        raise Hold('Existing same-SHA CircleCI fallback; never dispatch twice')
    return found[0] if found else None

def recovery_preflight(cfg):
    """Evaluate recovery eligibility independently of provider spending.

    Read-only: no shared ownership mutation or provider POST.
    """
    heartbeat=primary_evidence(cfg)
    sha=coord.gh('AyobamiH/clawsweeper/git/ref/heads/main')['object']['sha']
    if not coord.SHA.fullmatch(sha):raise Hold('Invalid source main SHA')
    commit=coord.gh('AyobamiH/clawsweeper/commits/'+sha)
    if commit.get('sha')!=sha or commit.get('commit',{}).get('verification',{}).get('verified') is not True:
        raise Hold('Unsigned or unverified source SHA')
    row=latest_context(statuses(sha),PRIMARY_CONTEXT)
    if row:
        raise Hold('Primary local CI already reported a status for this exact SHA: '+str(row.get('state')))
    provider_row=latest_context(statuses(sha),CONTEXT)
    if provider_row:raise Hold('CircleCI status already exists for exact source SHA')
    _,ledger=coord.read()
    if sha in ledger['dispatches'] or any(v.get('state') in coord.ACTIVE for v in ledger['dispatches'].values()):
        raise Hold('Shared provider side effect already owned or uncertain')
    if heartbeat['kind']!='primary_heartbeat_expired':
        raise Hold('Healthy primary; no standby action permitted')
    return {'sha':sha,'heartbeat':heartbeat,'recovery_eligible':True}

def readiness(cfg):
    candidate=recovery_preflight(cfg)
    # Spending permission is separate and remains mandatory before a claim.
    billing=budget_evidence(cfg)
    token=private_secret()
    safe_project(token)
    existing_provider_workflow(candidate['sha'],token)
    return {**candidate,'billing':billing,'token':token}

def observe(cfg):
    # Preserve specific holds without exposing credentials or injecting fake outages.
    result={'at':coord.timestamp(),'kind':'standby-observation','host':socket.gethostname(),
            'mode':cfg['mode'],'dispatch_performed':False}
    try:
        hb=primary_evidence(cfg)
        result['heartbeat']={k:hb[k] for k in ('kind','comment_id','server_updated_at','age_seconds')}
    except (RuntimeError,ValueError,KeyError) as exc:
        result['hold']='heartbeat_'+type(exc).__name__
    try:
        b=budget_evidence(cfg)
        result['free_plan']={'plan':b['plan'],'paid_overage':b['paid_overage'],
                             'available_credits':b['available_credits']}
    except (RuntimeError,ValueError,KeyError) as exc:
        result['budget_hold']=type(exc).__name__
    try:
        _,ledger=coord.read()
        result['provider_records']=[{'sha':sha,'state':r['state'],'owner':r.get('owner')}
                                    for sha,r in ledger['dispatches'].items()]
    except Exception as exc:result['ledger_hold']=type(exc).__name__
    try:
        candidate=recovery_preflight(cfg)
        result['recovery']={'eligible':True,'sha':candidate['sha'],
                            'provider_dispatch_authorised':False}
    except (Hold,RuntimeError,ValueError,KeyError) as exc:
        result['recovery']={'eligible':False,'hold':str(exc)[:180],
                            'provider_dispatch_authorised':False}
    atomic(STATUS,result)
    return result

def attempt(cfg):
    candidate=readiness(cfg)
    # Read the primary heartbeat again before reserving a global provider action.
    if primary_evidence(cfg)['kind']!='primary_heartbeat_expired':
        raise Hold('Primary recovered before standby claim')
    token=candidate['token'];sha=candidate['sha']
    claimed=coord.claim('Ayobami-Dev',sha,'primary_heartbeat_expired',candidate['heartbeat'],candidate['billing'])
    nonce=claimed['nonce']
    receipt=ROOT/'evidence'/'standby'/('claim-'+sha+'.json')
    atomic(receipt,{**claimed,'kind':'provider_reservation','never_replay':True})
    # The last permission gates are deliberately after durable reservation.
    try:
        if primary_evidence(cfg)['kind']!='primary_heartbeat_expired':
            coord.update(sha,nonce,'held')
            return {'dispatched':False,'hold':'primary-recovered-after-claim','sha':sha}
        if coord.gh('AyobamiH/clawsweeper/git/ref/heads/main')['object']['sha']!=sha:
            coord.update(sha,nonce,'held');return {'dispatched':False,'hold':'main-superseded','sha':sha}
        if latest_context(statuses(sha),PRIMARY_CONTEXT):
            coord.update(sha,nonce,'held');return {'dispatched':False,'hold':'primary-result-arrived','sha':sha}
        response=provider('/project/gh/AyobamiH/clawsweeper/pipeline',token,'POST',
                          {'branch':'main','parameters':{'fallback_ci':True,'expected_sha':sha}})
        pipeline_id=response.get('id')
        if not isinstance(pipeline_id,str) or str(uuid.UUID(pipeline_id))!=pipeline_id:
            raise Hold('Dispatch response lacks canonical pipeline identity')
        atomic(receipt,{**claimed,'pipeline_id':pipeline_id,'state':'awaiting_provider_readback',
                        'never_replay':True})
        coord.update(sha,nonce,'awaiting_provider_readback',pipeline_id)
        return {'dispatched':True,'sha':sha,'pipeline_id':pipeline_id,'verified':False}
    except Exception as exc:
        # A timed-out POST might have succeeded. Never retry, even across host restarts.
        return {'dispatched':None,'sha':sha,'hold':'dispatch_outcome_uncertain_no_replay',
                'error_class':type(exc).__name__}


def verified_provider_result(sha,pipeline_id,token):
    # Verify both provider API generations and every required Linux suite step.
    if not isinstance(pipeline_id,str) or str(uuid.UUID(pipeline_id))!=pipeline_id:
        raise Hold('Invalid recorded provider pipeline ID')
    pipeline=provider('/pipeline/'+pipeline_id,token)
    if (pipeline.get('id')!=pipeline_id or pipeline.get('project_slug')!=PROJECT
        or pipeline.get('vcs',{}).get('revision')!=sha
        or not isinstance(pipeline.get('number'),int) or pipeline['number']<1):
        raise Hold('Provider pipeline source/project mismatch')
    items=provider('/pipeline/'+pipeline_id+'/workflow',token)
    if items.get('next_page_token') or not isinstance(items.get('items'),list) or len(items['items'])!=1:
        raise Hold('Incomplete or unexpected provider workflow')
    workflow=items['items'][0]
    if (workflow.get('project_slug')!=PROJECT or workflow.get('pipeline_id')!=pipeline_id
        or workflow.get('name')!='circleci-free-fallback'):
        raise Hold('Provider workflow does not match approved fallback')
    jobs=provider('/workflow/'+workflow['id']+'/job',token)
    if jobs.get('next_page_token') or not isinstance(jobs.get('items'),list) or len(jobs['items'])!=1:
        raise Hold('Incomplete or unexpected provider jobs')
    job=jobs['items'][0]
    if (job.get('project_slug')!=PROJECT or job.get('name')!='full-linux-node24'
        or job.get('type')!='build' or not isinstance(job.get('job_number'),int)
        or job['job_number']<1):
        raise Hold('Provider job identity mismatch')
    statuses={'success':'success','failed':'failure','error':'error'}
    if workflow.get('status') not in statuses or job.get('status') not in statuses:
        raise Hold('Provider job/workflow is not terminal')
    outcome=statuses[workflow['status']]
    if statuses[job['status']]!=outcome:raise Hold('Provider workflow/job outcome mismatch')
    try:
        url='https://circleci.com/api/v1.1/project/github/AyobamiH/clawsweeper/'+str(job['job_number'])
        response=requests.get(url,headers={'Circle-Token':token},timeout=20)
        response.raise_for_status();detail=response.json()
    except (requests.RequestException,ValueError) as e:
        raise Hold('Independent CircleCI job readback unavailable: '+type(e).__name__) from None
    if (detail.get('username')!='AyobamiH' or detail.get('reponame')!='clawsweeper'
        or detail.get('branch')!='main' or detail.get('vcs_revision')!=sha
        or detail.get('build_num')!=job['job_number']
        or (detail.get('workflows') or {}).get('workflow_id')!=workflow['id']
        or (detail.get('workflows') or {}).get('job_name')!='full-linux-node24'):
        raise Hold('Independent CircleCI job identity differs')
    if (detail.get('lifecycle')!='finished' or detail.get('outcome') not in ('success','failed','error')
        or statuses[detail['outcome']]!=outcome):
        raise Hold('Independent CircleCI terminal outcome disagrees')
    steps={x.get('name'):[(a.get('status'),a.get('exit_code')) for a in x.get('actions',[])]
           for x in detail.get('steps',[])}
    required=('Enforce exact commit and explicit fallback request',
              'Install pinned pnpm and dependencies',
              'Install full-suite terminal and publication utilities',
              'Full repository validation','Sparse repair checkout acceptance')
    final=next((name for name in ('Verify GitHub Actions semantics with pinned actionlint',
                                  'Verify workflow syntax') if steps.get(name)==[('success',0)]),None)
    if outcome=='success' and (any(steps.get(x)!=[('success',0)] for x in required) or final is None):
        raise Hold('Full CI step contract is not independently green')
    return {'sha':sha,'pipeline_id':pipeline_id,'number':pipeline['number'],
            'workflow_id':workflow['id'],'job_number':job['job_number'],
            'outcome':outcome,'provider_verified':True,'steps':steps,
            'required_steps':list(required)+([final] if final else [])}

def reconcile(cfg,sha,record):
    if record.get('sha')!=sha or record.get('state') not in coord.ACTIVE:
        raise Hold('Not an active provider record')
    token=private_secret();safe_project(token)
    nonce=record['nonce'];pipeline_id=record.get('pipeline_id')
    if not pipeline_id:
        found=existing_provider_workflow(sha,token,allow_discovery=True)
        if not found:return {'sha':sha,'hold':'uncertain_provider_dispatch_no_replay'}
        pipeline=provider('/pipeline/'+found,token)
        if (when(pipeline['created_at'])-when(record['claimed_at'])) < -120:
            raise Hold('Candidate provider pipeline predates reservation')
        coord.update(sha,nonce,'awaiting_provider_readback',found)
        pipeline_id=found
        record={**record,'pipeline_id':found,'state':'awaiting_provider_readback'}
    info=verified_provider_result(sha,pipeline_id,token)
    receipt=ROOT/'evidence'/'standby'/('provider-'+sha+'.json')
    atomic(receipt,info)
    digest=hashlib.sha256(receipt.read_bytes()).hexdigest()
    state=record.get('state')
    if state not in ('awaiting_provider_readback','status_pending'):
        raise Hold('Unrecognised provider reporting phase')
    target='https://circleci.com/gh/AyobamiH/clawsweeper/'+str(info['number'])
    desired={'state':info['outcome'],'context':CONTEXT,
             'description':'CircleCI provider-verified '+info['outcome']+' on exact commit',
             'target_url':target}
    # Read back BEFORE every possible write, including crash recovery.
    # Never replay the CircleCI pipeline POST. A GitHub commit status is
    # append-only, so a bounded duplicate status may occur after an uncertain
    # network response; exact SHA/context/payload are verified below.
    matching=latest_context(statuses(sha),CONTEXT)
    if matching is None:
        try:
            attempt_number=coord.reserve_status_post(sha,nonce,pipeline_id)
        except RuntimeError as exc:
            return {'sha':sha,'hold':'github-status-reconciliation-required',
                    'reason':str(exc)[:180]}
        try:
            coord.gh('AyobamiH/clawsweeper/statuses/'+sha,'POST',desired)
        except Exception as exc:
            return {'sha':sha,'hold':'github-status-post-uncertain-readback-first',
                    'attempt':attempt_number,'reason':type(exc).__name__}
        matching=latest_context(statuses(sha),CONTEXT)
    if matching is None:
        return {'sha':sha,'hold':'github-status-not-confirmed-readback-first'}
    if any(matching.get(k)!=v for k,v in desired.items()) or not isinstance(matching.get('id'),int):
        raise Hold('GitHub provider status mismatch')
    coord.update(sha,nonce,info['outcome'],pipeline_id,status_id=matching['id'],receipt_sha256=digest)
    atomic(receipt,{**info,'github_status_id':matching['id'],'receipt_sha256':digest,
                    'verified_at':coord.timestamp()})
    return {'sha':sha,'outcome':info['outcome'],'github_status_id':matching['id'],
            'pipeline_id':pipeline_id,'independently_verified':True}

def run():
    os.umask(0o077)
    cfg=policy()
    if socket.gethostname()!='Ayobami-Dev':raise Hold('Wrong standby host identity')
    LOCK.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    with LOCK.open('a+') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'skipped':'standby operation already running'}
        result=observe(cfg)
        if cfg['mode']!='dispatch':return result
        try:
            _,ledger=coord.read()
            active=[(sha,rec) for sha,rec in ledger['dispatches'].items()
                    if rec.get('state') in coord.ACTIVE]
            if len(active)>1:raise Hold('Multiple active shared provider owners')
            if active:return {**result,'reconciliation':reconcile(cfg,*active[0])}
            return {**result,'attempt':attempt(cfg)}
        except (Hold,RuntimeError,KeyError,ValueError) as exc:
            result['hold']=str(exc)[:220];return result

if __name__=='__main__':
    try:print(json.dumps(run(),sort_keys=True))
    except Exception as e:
        print(json.dumps({'error':type(e).__name__,'reason':str(e)[:180],'dispatched':False}))
        sys.exit(2)
