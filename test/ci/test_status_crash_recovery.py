import datetime,unittest
from unittest.mock import patch
import standby_coord as c
import standby_agent as a
SHA='a'*40
PID='11111111-1111-4111-8111-111111111111'
NONCE='owned'
NOW=datetime.datetime(2026,11,5,3,0,tzinfo=datetime.timezone.utc)
def state(attempts=0,prior=None):
 r={'sha':SHA,'nonce':NONCE,'state':'status_pending','pipeline_id':PID,'status_post_attempts':attempts}
 if prior:r['status_post_reserved_at']=prior
 return {'dispatches':{SHA:r}}
class StatusCrashRecovery(unittest.TestCase):
 def test_first_reservation_after_crash_before_post(self):
  s=state()
  with patch.object(c,'read',side_effect=[('b'*40,s),('c'*40,s)]) as read,patch.object(c,'commit',return_value='c'*40) as commit:
   self.assertEqual(c.reserve_status_post(SHA,NONCE,PID,now=NOW),1)
   self.assertEqual(commit.call_count,1)
 def test_cooldown_prevents_blind_retry_after_uncertain_post(self):
  s=state(1,NOW.isoformat())
  with patch.object(c,'read',return_value=('b'*40,s)),patch.object(c,'commit') as commit:
   with self.assertRaisesRegex(RuntimeError,'cooldown'):c.reserve_status_post(SHA,NONCE,PID,now=NOW)
   commit.assert_not_called()
 def test_bounded_retry_after_independent_readback(self):
  s=state(1,(NOW-datetime.timedelta(seconds=121)).isoformat())
  with patch.object(c,'read',side_effect=[('b'*40,s),('c'*40,s)]),patch.object(c,'commit',return_value='c'*40):
   self.assertEqual(c.reserve_status_post(SHA,NONCE,PID,now=NOW),2)
 def test_exhaustion_requires_manual_reconciliation(self):
  with patch.object(c,'read',return_value=('b'*40,state(2))),patch.object(c,'commit') as commit:
   with self.assertRaisesRegex(RuntimeError,'exhausted'):c.reserve_status_post(SHA,NONCE,PID,now=NOW)
   commit.assert_not_called()
 def test_mismatched_owner_cannot_reserve(self):
  with patch.object(c,'read',return_value=('b'*40,state())),patch.object(c,'commit') as commit:
   with self.assertRaisesRegex(RuntimeError,'owner'):c.reserve_status_post(SHA,'other',PID,now=NOW)
   commit.assert_not_called()
 def test_existing_status_never_posts_again(self):
  record=state(1)['dispatches'][SHA]
  info={'sha':SHA,'pipeline_id':PID,'number':12,'outcome':'success','provider_verified':True}
  target='https://circleci.com/gh/AyobamiH/clawsweeper/12'
  existing={'context':a.CONTEXT,'state':'success','description':'CircleCI provider-verified success on exact commit','target_url':target,'id':123}
  with patch.object(a,'private_secret',return_value='dummy'),patch.object(a,'safe_project'),patch.object(a,'verified_provider_result',return_value=info),patch.object(a,'statuses',return_value=[existing]),patch.object(c,'reserve_status_post') as reserve,patch.object(c,'gh') as gh,patch.object(c,'update') as update,patch.object(a,'atomic',side_effect=lambda p,d:(p.parent.mkdir(parents=True,exist_ok=True),p.write_text(__import__('json').dumps(d)))),patch.object(a,'ROOT',__import__('pathlib').Path('/tmp')):
   out=a.reconcile({},SHA,record)
   self.assertTrue(out['independently_verified']);reserve.assert_not_called();gh.assert_not_called()
 def test_no_status_and_uncertain_attempt_holds_without_post(self):
  record=state(1)['dispatches'][SHA]
  info={'sha':SHA,'pipeline_id':PID,'number':12,'outcome':'success','provider_verified':True}
  with patch.object(a,'private_secret',return_value='dummy'),patch.object(a,'safe_project'),patch.object(a,'verified_provider_result',return_value=info),patch.object(a,'statuses',return_value=[]),patch.object(c,'reserve_status_post',side_effect=RuntimeError('cooldown')),patch.object(c,'gh') as gh,patch.object(a,'atomic',side_effect=lambda p,d:(p.parent.mkdir(parents=True,exist_ok=True),p.write_text(__import__('json').dumps(d)))),patch.object(a,'ROOT',__import__('pathlib').Path('/tmp')):
   out=a.reconcile({},SHA,record)
   self.assertEqual(out['hold'],'github-status-reconciliation-required');gh.assert_not_called()
if __name__=='__main__':unittest.main()
