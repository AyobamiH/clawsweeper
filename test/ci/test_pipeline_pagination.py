import unittest
from unittest.mock import patch
import standby_agent as a
SHA='a'*40
class Pagination(unittest.TestCase):
 def test_multiple_pages_are_exhausted_before_dispatch(self):
  pages=[{'items':[{'vcs':{'revision':'b'*40}}],'next_page_token':'next'}, {'items':[],'next_page_token':None}]
  calls=[]
  def fake(path,token,method='GET',payload=None,params=None):
   calls.append(params)
   return pages[len(calls)-1]
  with patch.object(a,'provider',side_effect=fake):
   self.assertIsNone(a.existing_provider_workflow(SHA,'dummy'))
  self.assertEqual(calls,[None,{'page-token':'next'}])
 def test_cycle_fails_closed(self):
  with patch.object(a,'provider',return_value={'items':[],'next_page_token':'repeat'}):
   with self.assertRaisesRegex(a.Hold,'cyclic'):a.existing_provider_workflow(SHA,'dummy')
 def test_incomplete_page_fails_closed(self):
  with patch.object(a,'provider',return_value={'items':None}):
   with self.assertRaisesRegex(a.Hold,'incomplete'):a.existing_provider_workflow(SHA,'dummy')
 def test_exact_sha_fallback_detected_on_later_page(self):
  pid='11111111-1111-4111-8111-111111111111'
  def fake(path,token,method='GET',payload=None,params=None):
   if path.endswith('/workflow'):return {'items':[{'name':'circleci-free-fallback'}]}
   if params:return {'items':[{'vcs':{'revision':SHA},'id':pid}],'next_page_token':None}
   return {'items':[],'next_page_token':'next'}
  with patch.object(a,'provider',side_effect=fake):
   with self.assertRaisesRegex(a.Hold,'never dispatch twice'):a.existing_provider_workflow(SHA,'dummy')
if __name__=='__main__':unittest.main()
