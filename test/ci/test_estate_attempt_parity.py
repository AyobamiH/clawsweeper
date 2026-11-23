"""Sensitive source/job/run/attempt admission and bounded matrix identity.

Test inputs are synthetic. No model calls, runner registration or providers.
"""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"scripts/ci"))
from estate_policy import Hold,REPO,admit,classify,load_manifest

MANIFEST=load_manifest()
SHA="a"*40
WORKFLOW=".github/workflows/sweep.yml"
KEY=WORKFLOW+"#review"
NAME="Review shard 2 · openclaw/openclaw#42,43"


def candidate(job_name=NAME):
    run={
        "id":54321,"run_attempt":2,"head_sha":SHA,"head_branch":"main",
        "repository":{"full_name":REPO},"path":WORKFLOW,
        "event":"workflow_dispatch",
        "actor":{"login":"AyobamiH","id":12345}
    }
    job={
        "id":34567,"run_id":54321,"name":job_name,"status":"queued",
        "labels":["self-hosted","Linux","X64","clawsweeper-ci-review-54321-review"]
    }
    return classify(MANIFEST,run,job)


def controls(c):
    item=next(j for j in MANIFEST["jobs"] if j["workflow"]==WORKFLOW and j["id"]=="review")
    return {
        "enabled":True,"repo":REPO,"trusted_main_sha":SHA,
        "enabled_classes":["review"],"review_source_verified":True,
        # Simulates an explicitly approved review run; does not call a model.
        "model_inference_permitted":True,
        "approved_jobs":{KEY:{
            "class":"review","source_sha256":item["source_sha256"],
            "run_ids":[c.run_id],"head_shas":[c.sha],
            "complete_changed_source":True,
            "approved_attempts":[{
                "run_id":c.run_id,"job_id":c.job_id,
                "attempt":c.attempt,"head_sha":c.sha,
                "job_name":c.name
            }]
        }}
    },item["source_sha256"]


class ExactAttemptAndMatrixReview(unittest.TestCase):
    def test_source_bound_dynamic_matrix_name_and_tuple_can_be_classified(self):
        c=candidate()
        config,source=controls(c)
        self.assertEqual(c.job_key,KEY)
        self.assertEqual(c.name,NAME)
        self.assertTrue(admit(c,MANIFEST,config,source_sha256=source))

    def test_sweep_matrix_name_is_not_an_unbounded_string(self):
        invalid=[
            "Review shard 2 · openclaw/openclaw#../../etc",
            "Review shard alpha · openclaw/openclaw#42",
            "Review shard 2 · openclaw/openclaw#",
            "Review shard 2 · openclaw/openclaw#42\nINJECT",
            "Review shard 2 · attacker/other#"+("7"*300),
            "Review shard 2 · openclaw/openclaw#42; echo bad",
            "Review shard 2 · user name/repo#42",
        ]
        for name in invalid:
            with self.subTest(name=name),self.assertRaisesRegex(
                Hold,"workflow_job_not_in_manifest"):
                candidate(name)

    def test_exact_run_job_attempt_head_and_expanded_name_are_indivisible(self):
        original=candidate()
        config,source=controls(original)
        for field,value in [
            ("run_id",54322),("job_id",34568),("attempt",3),
            ("head_sha","b"*40),("job_name","Review shard 3 · openclaw/openclaw#42"),
        ]:
            bad=copy.deepcopy(config)
            bad["approved_jobs"][KEY]["approved_attempts"][0][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(
                Hold,"sensitive_attempt_not_explicitly_pinned"):
                admit(original,MANIFEST,bad,source_sha256=source)

    def test_cross_product_authority_is_not_sufficient(self):
        original=candidate()
        config,source=controls(original)
        approved=config["approved_jobs"][KEY]
        approved["run_ids"].append(99999)
        approved["head_shas"].append("b"*40)
        approved["approved_attempts"]=[]
        with self.assertRaisesRegex(Hold,"sensitive_attempt_not_explicitly_pinned"):
            admit(original,MANIFEST,config,source_sha256=source)

    def test_malformed_duplicate_or_wildcard_attempt_fails_closed(self):
        c=candidate()
        config,source=controls(c)
        original=config["approved_jobs"][KEY]["approved_attempts"][0]
        cases=[
            {}, {"run_id":True,**{k:v for k,v in original.items() if k!="run_id"}},
            {**original,"extra":"*"},{**original,"attempt":0},
            {**original,"job_name":"*"},
        ]
        for invalid in cases:
            bad=copy.deepcopy(config)
            bad["approved_jobs"][KEY]["approved_attempts"]=[invalid]
            reason=("sensitive_attempt_not_explicitly_pinned" if invalid=={}
                    else "invalid_sensitive_attempt_approval")
            # Empty dict has invalid keys too, regardless of missing tuple.
            if invalid=={}:reason="invalid_sensitive_attempt_approval"
            if invalid.get("job_name")=="*":reason="sensitive_attempt_not_explicitly_pinned"
            with self.subTest(invalid=invalid),self.assertRaisesRegex(Hold,reason):
                admit(c,MANIFEST,bad,source_sha256=source)
        bad=copy.deepcopy(config)
        bad["approved_jobs"][KEY]["approved_attempts"]=[original,copy.deepcopy(original)]
        with self.assertRaisesRegex(Hold,"duplicate_sensitive_attempt_approval"):
            admit(c,MANIFEST,bad,source_sha256=source)


if __name__=="__main__":
    unittest.main()
