"""Track every existing critical workflow capability through the migration."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).parents[2]
WORKFLOWS = ROOT / '.github/workflows'

class WorkflowSources(unittest.TestCase):
    def text(self, name):
        return (WORKFLOWS / name).read_text()

    def test_codeql_keeps_both_actual_scanning_languages_and_upload_authority(self):
        s = self.text('codeql.yml')
        for part in ('- actions', '- javascript-typescript', 'security-events: write',
                     'github/codeql-action/init@v4', 'github/codeql-action/analyze@v4',
                     'clawsweeper-ci-security-${{ github.run_id }}-${{ matrix.language }}',
                     'tools: /opt/clawsweeper-codeql/codeql-linux64.zip',
                     'timeout-minutes: 35'):
            self.assertIn(part,s)
        self.assertNotIn('runs-on: ubuntu-latest',s)

    def test_dispatch_and_activity_callbacks_have_no_hosted_fallback(self):
        for file, slot in [('clawsweeper-dispatch.yml','dispatch'),
                           ('github-activity.yml','notify')]:
            s=self.text(file)
            self.assertIn('pull_request_target:',s)
            self.assertIn('clawsweeper-ci-ops-${{ github.run_id }}-'+slot,s)
            self.assertNotRegex(s,r'runs-on: ubuntu-(latest|24\.04)')

    def test_containment_retains_ephemeral_cloudflare_provision_and_cleanup(self):
        s=self.text('repair-containment-smoke.yml')
        for fragment in ('operation: start','operation: stop',
                         'clawsweeper-ci-ops-${{ github.run_id }}-provision',
                         'clawsweeper-ci-ops-${{ github.run_id }}-cleanup',
                         'runs-on: ${{ needs.provision.outputs[matrix.lane] }}'):
            self.assertIn(fragment,s)
        self.assertNotIn('|| \'ubuntu-latest\'',s)
        self.assertIn('needs.provision.outputs.plan !=',s)

    def test_automerge_keeps_full_hermetic_scenarios_no_host_socket(self):
        s=self.text('automerge-e2e.yml')
        for fragment in ('clawsweeper-ci-isolation-${{ github.run_id }}-e2e',
                         'scripts/e2e/automerge-container.mjs',
                         '--scenario all','docker build','docker save',
                         'actions/upload-artifact'):
            self.assertIn(fragment,s)
        self.assertNotIn('/var/run/docker.sock',s)

    def test_control_defaults_deny_privileged_execution(self):
        controller=(ROOT/'scripts/ci/self_hosted_executor.py').read_text()
        installer=(ROOT/'scripts/ci/install-selfhosted-controller.sh').read_text()
        policy=(ROOT/'scripts/ci/self_hosted_policy.py').read_text()
        self.assertIn("'enabled':False",installer)
        self.assertIn('registration_uncertain',controller)
        self.assertIn('existing_or_uncertain_runner_intent',controller)
        self.assertIn('nested_docker_isolation_not_proven',policy)
        self.assertNotIn('--privileged',controller)
        self.assertNotIn('/var/run/docker.sock',controller)
        self.assertIn('--cap-drop',controller)
        self.assertIn('--security-opt',controller)
        self.assertIn('codeql_image_not_pinned',controller)
        self.assertIn('codeql_image_drift',controller)
        builder=(ROOT/'scripts/ci/build-selfhost-codeql-runner.sh').read_text()
        self.assertIn('393bf92b66596141ec93baf9b483f4a350f3749916c922fed0dd63c67706047d',builder)
        self.assertIn('docker build --network none',builder)

if __name__ == '__main__': unittest.main()
