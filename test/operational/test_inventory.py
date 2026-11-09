import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT=pathlib.Path(__file__).resolve().parents[2]/'scripts/operational-admission-inventory.py'
spec=importlib.util.spec_from_file_location('operational_inventory',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=pathlib.Path(self.temp.name)
        self.workflows=self.root/'.github/workflows'
        self.workflows.mkdir(parents=True)
    def tearDown(self):self.temp.cleanup()
    def test_scheduled_secreted_mutating_workflow_is_never_admitted(self):
        (self.workflows/'scan.yml').write_text('''name: Scan\non:\n  schedule:\n    - cron: '0 * * * *'\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh api repos/example/repo/issues\n        env:\n          TOKEN: ${{ secrets.SCAN_TOKEN }}\n''')
        data=module.inventory(self.root)
        self.assertEqual(data['scheduled_count'],1)
        job=data['workflows'][0]['jobs'][0]
        self.assertEqual(job['runner_kind'],'github_hosted')
        self.assertTrue(job['secret_references'])
        self.assertTrue(job['possible_external_effects'])
        self.assertFalse(job['admitted_for_execution'])
    def test_dynamic_runner_and_unknown_workflow_fail_closed(self):
        (self.workflows/'dynamic.yml').write_text('''on: workflow_dispatch\njobs:\n  build:\n    runs-on: ${{ matrix.os }}\n    steps: []\n''')
        data=module.inventory(self.root)
        self.assertEqual(data['workflows'][0]['jobs'][0]['runner_kind'],'unknown')
        self.assertEqual(data['admitted_count'],0)
    def test_malformed_workflow_is_rejected(self):
        (self.workflows/'bad.yml').write_text('jobs: []\n')
        with self.assertRaisesRegex(ValueError,'Invalid workflow jobs'):module.inventory(self.root)

if __name__=='__main__':unittest.main()
