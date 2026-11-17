"""Exact r8p3 -> v3 signed two-job release compiler; never mutates live fleet."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"scripts/ci"))
import direct_local_v3_manual_controller as integration

INSTALLED=Path("/home/johnh/.local/share/local-ci/fleet_ci.py")
PIN="0a1e52cc1fb1e8f582b8032abaffed1e3d1f49cf08ec39dd63d3fab8208203da"

class V3ManualIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old=INSTALLED.read_bytes()
        if hashlib.sha256(cls.old).hexdigest()!=PIN:
            raise unittest.SkipTest("current installed controller changed; no stale rendering")
        cls.frozen={
            k:(ROOT/"scripts/ci"/k).read_bytes() for k in integration.FILES}
        cls.candidate=integration.compile_v3_manual_controller(
            cls.old,expected_sha256=PIN,
            reviewed_frozen_sources=cls.frozen)
        cls.src=cls.candidate["controller"].decode()

    def function(self,name,extra=None):
        tree=ast.parse(self.src)
        funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef)
               and n.name==name]
        self.assertEqual(len(funcs),1)
        text=ast.get_source_segment(self.src,funcs[0])
        env={"__name__":"__test_candidate__"}
        if extra:env.update(extra)
        exec(compile(text,"<frozen-candidate>",'exec'),env)
        return env[name]

    def test_new_release_is_source_only_and_frozen_dependency_complete(self):
        r=self.candidate
        self.assertEqual(r["state"],"prepared_not_installed")
        self.assertEqual(len(r["frozen_hashes"]),len(integration.FILES))
        self.assertEqual(
            r["proposed_sha256"],hashlib.sha256(r["controller"]).hexdigest())
        for k in integration.FILES:
            self.assertEqual(r["frozen_hashes"][k],hashlib.sha256(
                self.frozen[k]).hexdigest())
        self.assertEqual(self.src.count(
            "_MANUAL_LIB = ROOT / \"clawsweeper-manual-code-v3\""),1)
        self.assertNotIn("import direct_local_manual_worker as w;",self.src)
        self.assertNotIn("import direct_local_manual_run as m;",self.src)
        self.assertIn("verify_split_source_release(",self.src)
        self.assertIn("owner_signed_distinct_manual_queue_admission_not_execution",
                      self.frozen["direct_local_signed_split_manual.py"].decode())

    def test_frozen_imports_deny_unlisted_bytecode_before_python_import(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory(prefix="split-frozen-proof-") as tmp:
            root=Path(tmp)
            for name, data in self.frozen.items():
                child=root/name
                child.write_bytes(data)
                child.chmod(0o600)
            verify=self.function("_verified_local_manual_worker",{
                "_MANUAL_LIB":root,
                "_MANUAL_HASHES":self.candidate["frozen_hashes"],
                "hashlib":hashlib,"os":os,"RuntimeError":RuntimeError})
            self.assertTrue(verify())
            (root/"__pycache__").mkdir()
            with self.assertRaisesRegex(RuntimeError,"extra_or_missing"):
                verify()
            (root/"__pycache__").rmdir()
            one=root/"direct_local_signed_split_manual.py"
            one.write_bytes(one.read_bytes()+b"\\n# tampered\\n")
            with self.assertRaisesRegex(RuntimeError,"module_drift"):
                verify()

    def test_new_authenticator_accepts_only_signed_split_manual_path(self):
        auth=self.src.split("def _dl_authenticated_existing_job(",1)[1]
        auth=auth.split("    if a.mode=='execute-job':",1)[0]
        self.assertIn('if _dl_job[\'ref\'] == \'local-manual\':',auth)
        self.assertIn("_verified_manual_claim(_dl_job)",auth)
        self.assertIn("if _dl_ref == 'main':",auth)
        self.assertIn("direct-local-distinct:%",auth)
        self.assertNotIn("direct-local:%' LIMIT 2049",auth)

    def test_new_claim_validates_two_distinct_ids_not_legacy_aggregate(self):
        jobs=[
            {"workflow_job":".github/workflows/ci.yml#check",
             "job_id":"local-fleet-aaaaaaaaaaaa","suite":"linux-node24-claw-check",
             "policy":"a"*64},
            {"workflow_job":".github/workflows/ci.yml#sparse-repair-builds",
             "job_id":"local-fleet-bbbbbbbbbbbb","suite":"linux-node24-claw-sparse",
             "policy":"b"*64}]
        claim={
            "schema":"clawsweeper.existing-fleet-local-manual-split-claim.v1",
            "ref":"local-manual","job_intents":[x["workflow_job"] for x in jobs],
            "admission":"queued","source_sha":"c"*40,"jobs":jobs,
            "request_sha256":"d"*64}
        class Subprocess:
            @staticmethod
            def run(*a,**kw):
                return SimpleNamespace(returncode=0,stdout=json.dumps(claim).encode())
        func=self.function("_signed_manual_claim_entry",{
            "_verified_local_manual_worker":lambda:True,
            "subprocess":Subprocess,"sys":SimpleNamespace(
                executable="/usr/bin/python3"),
            "_MANUAL_LIB":Path("/frozen"),"ROOT":Path("/fleet"),
            "POLICY":Path("/fleet/policy"),"json":json,
            "SHA":re.compile("[a-f0-9]{40}"),
            "NAME":re.compile("local-fleet-[a-f0-9]{12}"),
            "re":re,"RuntimeError":RuntimeError})
        self.assertEqual(len(func("req","signature")["jobs"]),2)
        claim["jobs"]=[jobs[0],jobs[0]]
        with self.assertRaisesRegex(RuntimeError,"claim_result_untrusted"):
            func("req","signature")
        claim["jobs"]=jobs
        claim["schema"]="clawsweeper.existing-fleet-local-manual-claim.v1"
        with self.assertRaisesRegex(RuntimeError,"claim_result_untrusted"):
            func("req","signature")

    def test_manual_proof_rejects_forged_or_relabelled_job(self):
        job={"repo":"AyobamiH/clawsweeper","ref":"local-manual",
             "sha":"c"*40,"id":"local-fleet-aaaaaaaaaaaa"}
        proof={
            "schema":"clawsweeper.existing-fleet-local-manual-split-claim.v1",
            "verified_owner_origin":True,
            "provider_status_authorised":False,
            "github_actions_admission_authorised":False,
            "job_id":job["id"],"source_sha":job["sha"],"ref":job["ref"],
            "live_develop_verified":True,"exact_clean_source_verified":True,
            "queue_state":"running","request_sha256":"a"*64}
        class Subprocess:
            @staticmethod
            def run(*a,**kw):
                return SimpleNamespace(returncode=0,stdout=json.dumps(proof).encode())
        func=self.function("_manual_proof_subprocess",{
            "_verified_local_manual_worker":lambda:True,
            "_MANUAL_REPO":"AyobamiH/clawsweeper",
            "subprocess":Subprocess,"sys":SimpleNamespace(executable="/usr/bin/python3"),
            "_MANUAL_LIB":Path("/frozen"),"ROOT":Path("/fleet"),
            "json":json,"re":re,"RuntimeError":RuntimeError})
        self.assertEqual(func(job,start=True)["queue_state"],"running")
        proof["queue_state"]="completed"
        with self.assertRaisesRegex(RuntimeError,"not_bound_to_job"):
            func(job,start=True)
        proof["queue_state"]="running"
        proof["provider_status_authorised"]=True
        with self.assertRaisesRegex(RuntimeError,"not_bound_to_job"):
            func(job,start=True)

    def test_rejects_unsigned_source_changes_before_release(self):
        with self.assertRaisesRegex(RuntimeError,"unverified_installed"):
            integration.compile_v3_manual_controller(
                self.old+b"\n# source changed",expected_sha256=PIN,
                reviewed_frozen_sources=self.frozen)
        bad=dict(self.frozen)
        bad.pop("direct_local_signed_split_manual.py")
        with self.assertRaisesRegex(RuntimeError,"unverified_installed"):
            integration.compile_v3_manual_controller(
                self.old,expected_sha256=PIN,
                reviewed_frozen_sources=bad)

if __name__=="__main__":unittest.main()
