"""Fail-closed provisioned-runner selection without blocking cleanup.

Read-only source tests, no GitHub, Cloudflare or provider API effects.
"""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[2]
WORKFLOWS=ROOT/".github/workflows"


def job_body(filename,name):
    content=(WORKFLOWS/filename).read_text()
    matches=list(re.finditer(r"(?m)^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$",content))
    own=[i for i,m in enumerate(matches) if m.group(1)==name]
    if len(own)!=1:
        raise AssertionError(f"missing or repeated job {filename}#{name}")
    i=own[0]
    start=matches[i].end()
    end=matches[i+1].start() if i+1<len(matches) else len(content)
    return content[start:end]


class ProvisionedRunnerCleanupContracts(unittest.TestCase):
    def test_proof_requires_exact_provisioned_runner_and_current_attempt(self):
        jobs=(
            ("cloudflare-operator-fixtures.yml","validate","launch","runner"),
            ("cloudflare-repair-provision.yml","plan-proof","provision","plan"),
            ("cloudflare-repair-provision.yml","execute-proof","provision","execute"),
        )
        for file,job,parent,output in jobs:
            with self.subTest(job=job,workflow=file):
                section=job_body(file,job)
                self.assertIn("needs: "+parent,section)
                self.assertIn("needs."+parent+".result == 'success'",section)
                self.assertIn("needs."+parent+".outputs.attempt == format('{0}', github.run_attempt)",section)
                self.assertIn("needs."+parent+".outputs."+output+" != ''",section)
                self.assertIn("clawsweeper-unprovisioned-runner-held",section)
                self.assertNotIn("ubuntu-latest",section)
                self.assertEqual(len(re.findall(r"(?m)^    if:",section)),1)

    def test_cleanup_retains_always_and_dependencies(self):
        fixtures=job_body("cloudflare-operator-fixtures.yml","cleanup")
        self.assertIn("always()",fixtures)
        self.assertRegex(fixtures,r"(?m)^      - launch$")
        self.assertRegex(fixtures,r"(?m)^      - validate$")
        repair=job_body("cloudflare-repair-provision.yml","cleanup")
        self.assertIn("always()",repair)
        for prerequisite in ("deploy","provision","plan-proof","execute-proof"):
            self.assertRegex(repair,r"(?m)^      - "+prerequisite+r"$")

    def test_intake_runner_must_be_owner_selected_not_payload_selected(self):
        section=job_body("repair-issue-implementation-intake.yml","intake")
        self.assertIn("vars.CLAWSWEEPER_ISSUE_IMPLEMENTATION_INTAKE_RUNNER == format('clawsweeper-ci-privileged-{0}-{1}-intake', github.run_id, github.run_attempt)",section)
        self.assertIn("clawsweeper-unprovisioned-runner-held",section)
        # Inspect only the runner selector, not unrelated client payload data
        # used to process a user-authorised issue.
        selector=[line for line in section.splitlines() if line.strip().startswith("runs-on:")]
        self.assertEqual(len(selector),1)
        self.assertNotIn("github.event.client_payload.intake_runner",selector[0])
        self.assertNotIn("ubuntu-latest",selector[0])


if __name__=="__main__":
    unittest.main()
