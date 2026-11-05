import json,hashlib,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import standby_agent as a
import standby_coord as c
class ReceiptIdentity(unittest.TestCase):
 def test_provider_digest_matches_exact_immutable_bytes(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'provider.verified-provider.json';info={'outcome':'success','pipeline_id':'123'}
   digest=a.preserve_provider_receipt(p,info)
   self.assertEqual(digest,hashlib.sha256(p.read_bytes()).hexdigest())
   self.assertEqual(a.preserve_provider_receipt(p,info),digest)
 def test_interrupted_before_finalisation_retains_provider_identity(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'provider.verified-provider.json'
   digest=a.preserve_provider_receipt(p,{'outcome':'failure'})
   self.assertFalse((Path(td)/'provider.json').exists())
   self.assertEqual(digest,hashlib.sha256(p.read_bytes()).hexdigest())
 def test_mismatch_never_overwrites_original(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'provider.verified-provider.json'
   digest=a.preserve_provider_receipt(p,{'outcome':'failure'})
   with self.assertRaisesRegex(a.Hold,'differs'):
    a.preserve_provider_receipt(p,{'outcome':'success'})
   self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),digest)
 def test_corrupt_provider_receipt_fails_closed(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'provider.verified-provider.json';p.write_text('not json')
   with self.assertRaisesRegex(a.Hold,'unreadable'):a.preserve_provider_receipt(p,{'outcome':'success'})
 def test_ledger_declares_representation(self):
  sha='a'*40;pid='11111111-1111-4111-8111-111111111111'
  state={'dispatches':{sha:{'nonce':'owner','state':'status_pending','pipeline_id':pid}}}
  with patch.object(c,'read',return_value=('b'*40,state)),patch.object(c,'commit',return_value='c'*40):
   out=c.update(sha,'owner','success',pid,status_id=123,receipt_sha256='f'*64)
  self.assertEqual(out['receipt_representation'],'verified-provider.v1')
  self.assertEqual(out['receipt_sha256'],'f'*64)
if __name__=='__main__':unittest.main()
