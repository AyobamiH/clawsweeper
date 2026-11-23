"""Adversarial exact-workflow source binding, including actual synthetic merge.

All GitHub API replies are synthetic. No network, registration or dispatch.
"""
import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/"scripts/ci"))
from estate_controller import fetch_workflow_digest
from estate_policy import Hold, workflow_digest

BASE="a"*40
HEAD="b"*40
MERGE="c"*40
STACKED="e"*40
FLOW=".github/workflows/ci.yml"
ORIGINAL=b"on: [pull_request]\njobs: {safe: {runs-on: [self-hosted]}}\n"


def github_run(event="pull_request", prs=None):
    return {"path": FLOW, "event": event, "head_sha": HEAD,
            "pull_requests": [{"number": 42}] if prs is None else prs}


def api(*, parents=None, merge_content=ORIGINAL, head_content=ORIGINAL,
        main_content=ORIGINAL, base_sha=BASE, base_content=ORIGINAL,
        current_head=HEAD, base_repo="AyobamiH/clawsweeper", pr_state="open",
        different_ref=False):
    observed=[]
    def request(path):
        observed.append(path)
        if path.endswith("/pulls/42"):
            return {"number":42,"state":pr_state,
                    "base":{"sha":base_sha,"repo":{"full_name":base_repo}},
                    "head":{"sha":current_head,"repo":{"full_name":"contributor/fork"}}}
        if path.endswith("/git/ref/pull/42/merge"):
            return {"object": {"sha": "d"*40 if different_ref else MERGE}}
        if "/git/commits/" in path:
            return {"parents": [{"sha": x} for x in (
                [base_sha,HEAD] if parents is None else parents)]}
        if "/contents/" in path:
            ref=path.rsplit("?ref=",1)[1]
            return {"content":base64.b64encode({BASE:main_content,HEAD:head_content,
                                                 MERGE:merge_content,base_sha:base_content}.get(ref,b"tampered")).decode()}
        raise AssertionError(path)
    return request,observed


class SyntheticMergeSourceTests(unittest.TestCase):
    def test_pr_requires_three_matching_workflow_byte_sources_and_exact_parents(self):
        fetch,calls=api()
        self.assertEqual(fetch_workflow_digest(github_run(),BASE,fetch),workflow_digest(ORIGINAL))
        self.assertEqual(sum('/contents/' in path for path in calls),4)
        self.assertTrue(any('/pulls/42' in path for path in calls))
        self.assertTrue(any('/git/ref/pull/42/merge' in path for path in calls))
        self.assertTrue(any('/git/commits/'+MERGE in path for path in calls))

    def test_pr_head_alone_cannot_authorise_different_synthetic_merge_bytes(self):
        fetch,_=api(merge_content=ORIGINAL+b'\nrun: echo malicious\n')
        with self.assertRaisesRegex(Hold,'executed_workflow_differs_from_trusted_main'):
            fetch_workflow_digest(github_run(),BASE,fetch)

    def test_stale_base_parent_or_changed_head_denies_before_source_fetch(self):
        for parents in (["f"*40, HEAD],[BASE, "f"*40],[HEAD, BASE], [BASE], []):
            with self.subTest(parents=parents):
                fetch,calls=api(parents=parents)
                with self.assertRaisesRegex(Hold,'pull_request_merge_parents_changed'):
                    fetch_workflow_digest(github_run(),BASE,fetch)
                self.assertFalse(any('/contents/' in value for value in calls))

    def test_ambiguous_or_missing_pr_metadata_is_not_execution_authority(self):
        for prs in ([],[{"number": 42},{"number": 43}], [{"number":True}],
                    [{"number":0}], [{"number":"42"}], [None]):
            with self.subTest(prs=prs):
                fetch,calls=api()
                with self.assertRaisesRegex(Hold,'pull_request_merge_identity_unverifiable'):
                    fetch_workflow_digest(github_run(prs=prs),BASE,fetch)
                self.assertEqual(calls,[])

    def test_changed_merge_ref_and_incomplete_response_refused(self):
        fetch,_=api(different_ref=True)
        with self.assertRaisesRegex(Hold,'executed_workflow_differs_from_trusted_main'):
            fetch_workflow_digest(github_run(),BASE,fetch)
        fetch,_=api()
        def missing_parent(path):
            if '/git/commits/' in path:return {}
            return fetch(path)
        with self.assertRaisesRegex(Hold,'pull_request_merge_identity_unverifiable'):
            fetch_workflow_digest(github_run(),BASE,missing_parent)

    def test_stacked_pr_base_is_authentic_but_cannot_change_workflow_instructions(self):
        fetch,calls=api(base_sha=STACKED)
        self.assertEqual(fetch_workflow_digest(github_run(),BASE,fetch),workflow_digest(ORIGINAL))
        self.assertTrue(any('/contents/' in path and '?ref='+STACKED in path for path in calls))
        changed,_=api(base_sha=STACKED,base_content=ORIGINAL+b'\nchanged-source')
        with self.assertRaisesRegex(Hold,'executed_workflow_differs_from_trusted_main'):
            fetch_workflow_digest(github_run(),BASE,changed)

    def test_live_pr_base_and_head_identity_must_match_actual_merge(self):
        for bad in (dict(current_head='f'*40), dict(base_repo='attacker/fork'),
                    dict(pr_state='closed'), dict(base_sha='invalid'),
                    dict(base_sha=STACKED,parents=[BASE,HEAD])):
            with self.subTest(bad=bad):
                fetch,calls=api(**bad)
                with self.assertRaisesRegex(Hold,'pull_request_merge_parents_changed'):
                    fetch_workflow_digest(github_run(),BASE,fetch)
                self.assertFalse(any('/contents/' in path for path in calls))

    def test_other_events_retain_exact_main_head_comparison(self):
        fetch,calls=api()
        self.assertEqual(fetch_workflow_digest(github_run(event='push'),BASE,fetch),
                         workflow_digest(ORIGINAL))
        self.assertEqual(sum('/contents/' in path for path in calls),2)
        self.assertFalse(any('/git/ref/pull' in path for path in calls))
        bad,_=api(head_content=ORIGINAL+b' tampered')
        with self.assertRaisesRegex(Hold,'executed_workflow_differs_from_trusted_main'):
            fetch_workflow_digest(github_run(event='push'),BASE,bad)

    def test_pr_target_event_never_borrows_readonly_synthetic_merge_validation(self):
        fetch,calls=api()
        with self.assertRaisesRegex(Hold,'untrusted_workflow_source_event'):
            fetch_workflow_digest(github_run(event='pull_request_target'),BASE,fetch)
        self.assertEqual(calls,[])


if __name__=='__main__': unittest.main()
