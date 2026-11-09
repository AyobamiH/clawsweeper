import pathlib
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
SCRIPT=pathlib.Path(__file__).resolve().parents[2]/'scripts/operational-cutover-audit.py'
mod=SourceFileLoader('cutover_audit',str(SCRIPT)).load_module()
class AuditTests(unittest.TestCase):
 def test_all_jobs_fail_closed_and_dependencies_preserved(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);p=root/'.github/workflows';p.mkdir(parents=True)
   (p/'x.yml').write_text('''on:\n  schedule:\n    - cron: '0 * * * *'\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-github-app-token@abc\n  publish:\n    needs: scan\n    permissions:\n      contents: write\n    runs-on: ubuntu-latest\n    steps: []\n''')
   result=mod.audit(root)
   self.assertEqual(result['total_jobs'],2)
   self.assertEqual(result['admitted_jobs'],0)
   self.assertEqual(result['jobs'][1]['dependencies'],['scan'])
   self.assertTrue(result['jobs'][0]['markers']['github_app_token'])
   self.assertTrue(result['jobs'][1]['markers']['write_permissions'])
   self.assertTrue(all(x['migration_state']=='not_admitted' for x in result['jobs']))
if __name__=='__main__':unittest.main()
