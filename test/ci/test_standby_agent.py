"""Offline/online standby decisions: no network side effects and no paid executions."""
import datetime,json,tempfile,time,unittest,uuid
from pathlib import Path
from unittest.mock import patch,MagicMock,call
import standby_agent as a
import standby_coord as c

SHA='a'*40
UUID='11111111-1111-4111-8111-111111111111'
CFG={'schema_version':1,'target':c.TARGET,'standby_host':'Ayobami-Dev','mode':'observe',
     'heartbeat_comment_id':6572526731,'budget_comment_id':6572605203,
     'heartbeat_timeout_seconds':900,'budget_max_age_seconds':3600,'minimum_free_credits':2000}
BUDGET={'provider':'CircleCI','plan':'Free','paid_overage':False,'available_credits':25000,'reserved_credits':2000,'checked_at_epoch':time.time()}
OFFLINE={'kind':'primary_heartbeat_expired','comment_id':6572526731,'age_seconds':1001,'server_updated_at':'2026-11-02T08:00:00Z','last_primary_sha':SHA}

class Admissions(unittest.TestCase):
 def test_recent_heartbeat_does_not_dispatch(self):
  with patch.object(a,'primary_evidence',return_value={**OFFLINE,'kind':'primary_heartbeat_recent','age_seconds':4}),\
       patch.object(a,'budget_evidence',return_value=BUDGET),\
       patch.object(c,'gh',side_effect=lambda path:{'object':{'sha':SHA}} if path.endswith('/git/ref/heads/main') else {'sha':SHA,'commit':{'verification':{'verified':True}}}),\
       patch.object(a,'statuses',return_value=[]),patch.object(c,'read',return_value=('b'*40,{'dispatches':{}})),\
       patch.object(a,'private_secret',side_effect=AssertionError('No credentials needed while primary healthy')):
   with self.assertRaisesRegex(a.Hold,'Healthy primary'):a.readiness(CFG)
 def test_primary_status_precludes_standby(self):
  with patch.object(a,'primary_evidence',return_value=OFFLINE),patch.object(a,'budget_evidence',return_value=BUDGET),\
       patch.object(c,'gh',side_effect=lambda path:{'object':{'sha':SHA}} if path.endswith('/git/ref/heads/main') else {'sha':SHA,'commit':{'verification':{'verified':True}}}),\
       patch.object(a,'statuses',return_value=[{'context':a.PRIMARY_CONTEXT,'state':'pending'}]):
   with self.assertRaisesRegex(a.Hold,'Primary local CI already reported'):a.readiness(CFG)
 def test_observer_does_not_consume_token_or_dispatch(self):
  with patch.object(a,'primary_evidence',return_value=OFFLINE),patch.object(a,'budget_evidence',return_value=BUDGET),\
       patch.object(c,'read',return_value=('a'*40,{'dispatches':{}})),patch.object(a,'atomic') as write,\
       patch.object(a,'provider',side_effect=AssertionError('Observer must never hit CircleCI')):
   out=a.observe(CFG)
   self.assertFalse(out['dispatch_performed']);write.assert_called_once()
 def test_stale_budget_fails_closed(self):
  old=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=2)).isoformat()
  with patch.object(a,'issue_json',return_value=({'updated_at':old},{**BUDGET,'kind':a.BUDGET_MARK,'source_host':'web','repository':c.TARGET})):
   with self.assertRaises(a.Hold):a.budget_evidence(CFG)
 def test_nonfree_budget_fails_closed(self):
  with patch.object(a,'issue_json',return_value=({'updated_at':datetime.datetime.now(datetime.timezone.utc).isoformat()},{**BUDGET,'plan':'Performance','kind':a.BUDGET_MARK,'source_host':'web','repository':c.TARGET})):
   with self.assertRaises(a.Hold):a.budget_evidence(CFG)
 def test_paid_overage_fails_closed(self):
  with patch.object(a,'issue_json',return_value=({'updated_at':datetime.datetime.now(datetime.timezone.utc).isoformat()},{**BUDGET,'paid_overage':True,'kind':a.BUDGET_MARK,'source_host':'web','repository':c.TARGET})):
   with self.assertRaises(a.Hold):a.budget_evidence(CFG)

class FencedDispatch(unittest.TestCase):
 def test_reservation_precedes_provider_post(self):
  events=[]
  candidate={'sha':SHA,'token':'test-token','heartbeat':OFFLINE,'billing':BUDGET}
  def claimant(*args):events.append('claim');return {'nonce':'owner-nonce','sha':SHA}
  def provider(*args,**kwargs):events.append('provider_post');return {'id':UUID}
  with patch.object(a,'readiness',return_value=candidate),patch.object(a,'primary_evidence',return_value=OFFLINE),\
       patch.object(c,'claim',side_effect=claimant),patch.object(c,'update') as update,\
       patch.object(c,'gh',return_value={'object':{'sha':SHA}}),\
       patch.object(a,'statuses',return_value=[]),patch.object(a,'provider',side_effect=provider),\
       patch.object(a,'atomic'):
   response=a.attempt(CFG)
  self.assertEqual(events,['claim','provider_post']);self.assertTrue(response['dispatched'])
  update.assert_called_once_with(SHA,'owner-nonce','awaiting_provider_readback',UUID)
 def test_post_timeout_never_retries(self):
  candidate={'sha':SHA,'token':'test-token','heartbeat':OFFLINE,'billing':BUDGET}
  with patch.object(a,'readiness',return_value=candidate),patch.object(a,'primary_evidence',return_value=OFFLINE),\
       patch.object(c,'claim',return_value={'nonce':'owner-nonce','sha':SHA}),patch.object(c,'update') as update,\
       patch.object(c,'gh',return_value={'object':{'sha':SHA}}),patch.object(a,'statuses',return_value=[]),\
       patch.object(a,'provider',side_effect=TimeoutError) as provider,patch.object(a,'atomic'):
   response=a.attempt(CFG)
  self.assertIsNone(response['dispatched']);self.assertIn('uncertain',response['hold'])
  self.assertEqual(provider.call_count,1);update.assert_not_called()
 def test_primary_recovers_after_claim_without_post(self):
  candidate={'sha':SHA,'token':'test-token','heartbeat':OFFLINE,'billing':BUDGET}
  with patch.object(a,'readiness',return_value=candidate),\
       patch.object(a,'primary_evidence',side_effect=[{**OFFLINE,'kind':'primary_heartbeat_recent'}]),\
       patch.object(c,'claim',return_value={'nonce':'owner-nonce','sha':SHA}) as claim,\
       patch.object(a,'provider') as provider:
   with self.assertRaises(a.Hold):a.attempt(CFG)
  claim.assert_not_called();provider.assert_not_called()
 def test_unknown_provider_side_effect_does_not_replay_on_reconcile(self):
  rec={'sha':SHA,'state':'dispatch_outcome_uncertain','nonce':'owner-nonce','pipeline_id':None,'claimed_at':'2026-11-02T08:00:00Z'}
  with patch.object(a,'private_secret',return_value='test-token'),patch.object(a,'safe_project'),\
       patch.object(a,'existing_provider_workflow',return_value=None),\
       patch.object(a,'provider') as provider:
   result=a.reconcile(CFG,SHA,rec)
  self.assertIn('no_replay',result['hold']);provider.assert_not_called()

class SharedCAS(unittest.TestCase):
 def test_owner_rejects_stale_budget_before_gh(self):
  with patch.object(c,'gh') as gh:
   with self.assertRaisesRegex(RuntimeError,'expired'):
    c.claim('Ayobami-Dev',SHA,'primary_heartbeat_expired',OFFLINE,{**BUDGET,'checked_at_epoch':time.time()-7200})
   gh.assert_not_called()
 def test_standby_cannot_claim_recent_primary_heartbeat(self):
  with patch.object(c,'gh') as gh:
   with self.assertRaisesRegex(RuntimeError,'offline evidence missing'):
    c.claim('Ayobami-Dev',SHA,'primary_heartbeat_expired',{**OFFLINE,'age_seconds':3},BUDGET)
   gh.assert_not_called()
 def test_terminal_transition_requires_status_and_receipt_digest(self):
  fake={'dispatches':{SHA:{'sha':SHA,'nonce':'x','state':'awaiting_provider_readback','pipeline_id':UUID}}}
  with patch.object(c,'read',return_value=('b'*40,fake)),patch.object(c,'commit') as commit:
   with self.assertRaisesRegex(RuntimeError,'receipt and GitHub status'):
    c.update(SHA,'x','success',UUID)
   commit.assert_not_called()

if __name__=='__main__':unittest.main()
