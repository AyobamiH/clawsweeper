import unittest
from unittest.mock import patch
import standby_agent as a
import standby_coord as c
SHA='a'*40
OFFLINE={'kind':'primary_heartbeat_expired','age_seconds':1000,'comment_id':6572526731,'last_primary_sha':SHA}
class RecoverySeparation(unittest.TestCase):
    def test_recovery_preflight_without_billing_or_provider(self):
        with patch.object(a,'primary_evidence',return_value=OFFLINE),\
             patch.object(c,'gh',side_effect=lambda path: {'object':{'sha':SHA}} if path.endswith('git/ref/heads/main') else {'sha':SHA,'commit':{'verification':{'verified':True}}}),\
             patch.object(a,'statuses',return_value=[]),\
             patch.object(c,'read',return_value=('b'*40,{'dispatches':{}})),\
             patch.object(a,'budget_evidence',side_effect=AssertionError('financial gate called')),\
             patch.object(a,'provider',side_effect=AssertionError('provider called')):
            self.assertTrue(a.recovery_preflight({})['recovery_eligible'])
    def test_dispatch_still_fails_closed_without_fresh_budget(self):
        with patch.object(a,'recovery_preflight',return_value={'sha':SHA,'heartbeat':OFFLINE,'recovery_eligible':True}),\
             patch.object(a,'budget_evidence',side_effect=a.Hold('expired')),\
             patch.object(a,'provider',side_effect=AssertionError('provider called')),\
             patch.object(c,'claim',side_effect=AssertionError('claim called')):
            with self.assertRaisesRegex(a.Hold,'expired'):a.readiness({})
if __name__=='__main__':unittest.main()
