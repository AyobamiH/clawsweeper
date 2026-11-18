"""Exact r8p3 -> v3 signed two-job release compiler; never mutates live fleet."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"scripts/ci"))
import direct_local_v3_manual_controller as integration

INSTALLED=Path("/home/johnh/.local/share/local-ci/fleet_ci.py")
ORIGINAL_ROLLBACK=Path(
    "/home/johnh/.local/state/agent-worktrees/evidence/"
    "clawsweeper-distinct-admission-20261116/"
    "v3-signed-integrity-package-bfff23836-20261117/"
    "rollback-r8p3/runtime/fleet_ci.py")
PIN="0a1e52cc1fb1e8f582b8032abaffed1e3d1f49cf08ec39dd63d3fab8208203da"

class V3ManualIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Live r8p3 was intentionally replaced by owner-approved v3.
        # Reuse the byte-verified original rollback fixture, not mutable runtime.
        cls.old=ORIGINAL_ROLLBACK.read_bytes()
        if hashlib.sha256(cls.old).hexdigest()!=PIN:
            raise AssertionError("original r8p3 rollback fixture drifted")
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

    def test_prelock_and_worker_cannot_import_obsolete_r7_verifier(self):
        """Regression for the observed installed v3 AttributeError hold."""
        for name in ("_dl_verifier", "_dl_mod"):
            self.assertIn(name+".read_split_source_release(_dl_bound)", self.src)
            self.assertIn(name+".verify_split_source_release(", self.src)
        self.assertIn(
            "_dl_verifier_entry = _MANUAL_LIB / 'direct_local_receiver_integration.py'",
            self.src)
        self.assertIn(
            "_dl_file = _MANUAL_LIB / 'direct_local_receiver_integration.py'",
            self.src)
        self.assertNotIn("ROOT / 'direct_local_receiver_integration.py'", self.src)
        self.assertNotIn("ROOT / 'direct_local_ingress_reconcile.py'", self.src)
        self.assertIn(
            "_dl_doc['implementation_checkout']", self.src)
        self.assertIn(
            "_dl_doc['implementation_commit']", self.src)
        self.assertIn(
            "hashlib.sha256(_dl_ingress_bytes).digest()", self.src)
        self.assertIn(
            "profile='split')", self.src)
        self.assertNotIn("_dl_bytes[", self.src)
        self.assertGreaterEqual(self.src.count(
            "_verified_local_manual_worker()"), 4)
        # The reviewed adapter provides the split contract; r7 does not.
        sidecar=self.frozen["direct_local_receiver_integration.py"].decode()
        self.assertIn("def read_split_source_release(",sidecar)
        self.assertIn("def verify_split_source_release(",sidecar)
        adapter=(ROOT/"scripts/ci/direct_local_ingress_reconcile.py").read_text()
        self.assertIn('profile: str = "aggregate"',adapter)
        self.assertIn('if profile == "split":',adapter)

    def test_signed_implementation_blob_provides_actual_split_adapter(self):
        """Use the archived exact signed source, not today's mutable checkout."""
        descriptor_path=(ORIGINAL_ROLLBACK.parents[3] /
            "v3-preinstall-frozen-signed-sources-bfff23836-20261117"
            "/SOURCE_RELEASE_CANDIDATE.json")
        doc=json.loads(descriptor_path.read_text())
        root=Path(doc["implementation_checkout"])
        rel="scripts/ci/direct_local_ingress_reconcile.py"
        env={"PATH":"/usr/bin:/bin","HOME":"/nonexistent",
             "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
             "GIT_NO_REPLACE_OBJECTS":"1","GIT_OPTIONAL_LOCKS":"0",
             "GIT_TERMINAL_PROMPT":"0","LC_ALL":"C"}
        cmd=["/usr/bin/git","-c","core.fsmonitor=false","-C",str(root),
             "show","--no-ext-diff",doc["implementation_commit"]+":"+rel]
        blob=subprocess.run(cmd,env=env,capture_output=True,
                            check=True,timeout=8).stdout
        self.assertEqual(blob,(root/rel).read_bytes())
        self.assertIn(b'profile: str = "aggregate"',blob)
        self.assertIn(b'if profile == "split":',blob)
        module=types.ModuleType("signed_immutable_ingress_test")
        module.__file__=str(root/rel)
        exec(compile(blob,module.__file__,"exec"),module.__dict__)
        import inspect
        self.assertIn("profile",inspect.signature(
            module.reconcile_existing_fleet_ingress).parameters)

    def test_unreviewed_prelock_shape_holds_instead_of_falling_back(self):
        source=self.src.replace(
            "                _dl_verifier_entry = _MANUAL_LIB",
            "                _dl_verifier_entry = ROOT",1)
        with self.assertRaisesRegex(RuntimeError,
                                    "unrecognised_legacy_verifier_block"):
            integration._bind_v3_ingress_to_verified_release(source)

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
