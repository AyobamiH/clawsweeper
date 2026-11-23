"""Verifier logic tests: fixture success is NOT real operational acceptance."""
import base64
import importlib.util
import importlib._bootstrap_external as bootstrap_external
import copy
import shutil
import time
import io
import zipfile
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import verify_estate_execution as v

HEAD = "a" * 40
TREE = "b" * 40
CHECK = ".github/workflows/ci.yml#check"
SPARSE = ".github/workflows/ci.yml#sparse-repair-builds"
CI = ".github/workflows/ci.yml"
CODEQL = ".github/workflows/codeql.yml"


def private(path, content):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(content)
    path.chmod(0o600)


def entry(path, ident, name, events, workflow_hash):
    return {"workflow": path, "id": ident, "display_name": name,
            "events": events, "source_sha256": workflow_hash, "needs": [], "risks": []}


class Fixtures:
    def __init__(self, root, *, codeql=False):
        self.root = root
        self.workflow = ((Path(__file__).resolve().parents[2] / CODEQL).read_bytes()
                         if codeql else b"# fixture bytes; not an accepted execution workflow\n")
        path = CODEQL if codeql else CI
        self.run = {"id": 10, "head_sha": HEAD, "path": path, "run_attempt": 1,
                    "event": "workflow_dispatch", "head_branch": "develop",
                    "repository": {"full_name": v.REPO}, "status": "completed",
                    "conclusion": "success"}
        definitions = {}
        if codeql:
            definitions[v.CODEQL] = entry(CODEQL, "analyze", "Analyze", ["workflow_dispatch"], v.digest(self.workflow))
            self.jobs = [self.job(20, name, v.CODEQL_STEPS, "security", language)
                         for language, name in v.verify_codeql_release.LANGUAGES.items()]
            self.jobs[1] = self.job(21, "Analyze (javascript-typescript)", v.CODEQL_STEPS,
                                    "security", "javascript-typescript")
        else:
            definitions[CHECK] = entry(CI, "check", "pnpm check", ["push", "workflow_dispatch", "pull_request"], v.digest(self.workflow))
            definitions[SPARSE] = entry(CI, "sparse-repair-builds", "sparse repair build smoke", ["pull_request"], v.digest(self.workflow))
            self.jobs = [self.job(20, "pnpm check", v.VALIDATION[CHECK][2], "validation", "check")]
        definitions[".github/workflows/sweep.yml#publish"] = entry(
            ".github/workflows/sweep.yml", "publish", "Publish", ["schedule"], "c" * 64)
        self.source = {"head_sha": HEAD, "tree_sha": TREE, "manifest_sha256": "d" * 64,
                       "sources": {path: v.digest(self.workflow), ".github/workflows/sweep.yml": "c" * 64},
                       "jobs": definitions}
        self.sarif_ids = {
            "actions": "11111111-1111-4111-8111-111111111111",
            "javascript-typescript": "22222222-2222-4222-8222-222222222222",
        }
        self.analyses = {}
        if codeql:
            for language, identifier in self.sarif_ids.items():
                job = next(j for j in self.jobs if j["name"] == f"Analyze ({language})")
                self.analyses[9 if language == "actions" else 10] = {
                    "id": 9 if language == "actions" else 10,
                    "sarif_id": identifier,
                    "commit_sha": HEAD,
                    "ref": "refs/heads/develop",
                    "analysis_key": ".github/workflows/codeql.yml:analyze",
                    "category": f"/language:{language}",
                    "created_at": "2026-11-10T20:00:30Z",
                    "error": "",
                    "tool": {"name": "CodeQL", "version": "2.27.4"},
                }
        self.runners = []
        self.run_reads = 0
        self.after_run = None
        self.after_job = None
        self.fail = False
        self.seen = []
        self.root.mkdir(mode=0o700)
        for job in self.jobs:
            self.receipt(job, "security" if codeql else "validation")

    def job(self, ident, name, steps, role, slot):
        return {"id": ident, "run_id": 10, "run_attempt": 1, "head_sha": HEAD,
                "name": name, "status": "completed", "conclusion": "success",
                "runner_name": f"csw-ci-10-{ident}-1", "runner_id": ident + 100,
                "labels": ["self-hosted", "Linux", "X64", f"clawsweeper-ci-{role}-10-{slot}"],
                "started_at": "2026-11-10T20:00:00Z", "completed_at": "2026-11-10T20:01:00Z",
                "steps": [{"number": i + 1, "name": n, "status": "completed", "conclusion": "success"}
                          for i, n in enumerate(steps)]}

    def receipt(self, job, role):
        log = b"fixture runner completed\n"
        folder = self.root / f"run-10-job-{job['id']}-attempt-1"
        folder.mkdir(mode=0o700, exist_ok=True)
        receipt = {"schema": "clawsweeper.selfhosted-jit.v1", "run_id": 10, "job_id": job["id"],
                   "attempt": 1, "head_sha": HEAD, "workflow": self.run["path"], "event": self.run["event"],
                   "runner_name": job["runner_name"], "runner_id": job["runner_id"], "role": role,
                   "label": job["labels"][-1], "state": "passed", "issues": [], "runner_exit": 0,
                   "image_sha256": "sha256:" + "e" * 64, "log_bytes": len(log), "log_sha256": v.digest(log),
                   "github_job": {k: job[k] for k in ("id", "run_id", "status", "conclusion", "runner_name")}}
        private(folder / "receipt.json", v.canonical(receipt))
        private(folder / "runner.log", log)
        return folder

    def codeql_adapter(self):
        return {"head_sha": HEAD, "run_attempt": 1,
                "analyses": {
                    language: {k: self.analyses[id_][k]
                               for k in ("id", "commit_sha", "ref", "created_at")}
                    for language, id_ in (("actions", 9), ("javascript-typescript", 10))},
                "security_alert_3": "open"}

    def job_log(self, ident):
        job = next(j for j in self.jobs if j["id"] == ident)
        language = job["name"][9:-1]
        return (f"2026-11-10T20:00:30Z CODEQL_SARIF_UPLOAD_V1 "
                f"run=10 attempt=1 language={language} "
                f"sarif_id={self.sarif_ids[language]}\n").encode()

    def get(self, path):
        self.seen.append(path)
        if self.fail:
            raise v.Refused("github_readback_unavailable")
        if path == f"{v.API}/commits/{HEAD}":
            return {"sha": HEAD, "commit": {"tree": {"sha": TREE}, "verification": {"verified": True}}}
        if path == f"{v.API}/actions/runs/10":
            self.run_reads += 1
            return copy.deepcopy(self.after_run if self.after_run and self.run_reads > 1 else self.run)
        if path == f"{v.API}/contents/{self.run['path']}?ref={HEAD}":
            return {"encoding": "base64", "content": base64.b64encode(self.workflow).decode()}
        if path == f"{v.API}/actions/runs/10/attempts/1/jobs?per_page=100&page=1":
            return {"total_count": len(self.jobs), "jobs": copy.deepcopy(self.jobs)}
        if path == f"{v.API}/actions/runners?per_page=100&page=1":
            return {"total_count": len(self.runners), "runners": copy.deepcopy(self.runners)}
        if path.startswith(f"{v.API}/actions/jobs/"):
            ident = int(path.rsplit("/", 1)[1])
            return copy.deepcopy(self.after_job or next(j for j in self.jobs if j["id"] == ident))
        if path.startswith(f"{v.API}/code-scanning/analyses/"):
            ident = int(path.rsplit("/", 1)[1])
            return copy.deepcopy(self.analyses[ident])
        if path.startswith(f"{v.API}/code-scanning/sarifs/"):
            identifier = path.rsplit("/", 1)[1]
            return {"processing_status": "complete",
                    "analyses_url": f"https://api.github.com/{v.API}/code-scanning/analyses?sarif_id={identifier}"}
        raise AssertionError("Unexpected fixture GET: " + path)


class ExecutionVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fx = Fixtures(self.root / "receipts")
        self.pin = patch.object(v, "VALIDATION_WORKFLOW_SHA256", v.digest(self.fx.workflow))
        self.pin.start()
        self.addCleanup(self.pin.stop)
        # These fixture-only report tests isolate provider reconciliation.
        # RuntimeProofTests below exercises the real committed-byte boundary
        # in a distinct interpreter and repository; it is not disabled there.
        self.runtime = patch.object(v, "runtime_source_proof", return_value={"fixture": "d" * 64})
        self.runtime_mock = self.runtime.start()
        self.addCleanup(self.runtime.stop)

    def verify(self, **kwargs):
        return v.verify_run(self.fx.source, 10, self.fx.root, self.fx.get,
                            kwargs.get("containers", lambda _: True))

    def report(self):
        with patch.object(v, "source_manifest", return_value=self.fx.source):
            return v.build_report(self.root, HEAD, [10], self.fx.root, get=self.fx.get, containers=lambda _: True)

    def test_exact_ordinary_receipt_steps_cleanup_pass(self):
        result = self.verify()
        self.assertEqual(list(result), [CHECK])
        self.assertTrue(result[CHECK]["owned_runners_absent"])
        self.assertIn("/attempts/1/jobs?", " ".join(self.fx.seen))
        self.assertFalse(any("/runs/10/jobs?" in p for p in self.fx.seen))

    def test_sensitive_jobs_are_not_inflated(self):
        report = self.report()
        self.assertEqual(report["execution_verified_jobs"], 1)
        self.assertEqual(report["held_jobs"], 2)
        self.assertFalse(report["workflow_dag_accepted"])
        self.assertFalse(report["production_release_accepted"])
        self.assertEqual(next(j for j in report["jobs"] if j["class"] == "privileged")["status"], "held")

    def test_unrelated_runner_does_not_block(self):
        self.fx.runners = [{"id": 999, "name": "another-project-runner"}]
        self.assertIn(CHECK, self.verify())

    def test_matching_runner_id_or_name_blocks(self):
        for runner in [{"id": 120, "name": "renamed"}, {"id": 999, "name": "csw-ci-10-20-1"}]:
            with self.subTest(runner=runner), self.assertRaisesRegex(v.Refused, "owned_runner_still_registered"):
                self.fx.runners = [runner]
                self.verify()

    def test_owned_container_residue_blocks(self):
        with self.assertRaisesRegex(v.Refused, "owned_container_cleanup_unverified"):
            self.verify(containers=lambda _: False)

    def test_wrong_head_is_not_transferred(self):
        self.fx.run["head_sha"] = "f" * 40
        with self.assertRaisesRegex(v.Refused, "run_head_mismatch"):
            self.verify()

    def test_wrong_attempt_job_rejected(self):
        self.fx.jobs[0]["run_attempt"] = 2
        with self.assertRaisesRegex(v.Refused, "job_attempt_mismatch"):
            self.verify()

    def test_workflow_source_digest_mismatch(self):
        self.fx.workflow += b"changed"
        with self.assertRaisesRegex(v.Refused, "provider_workflow_digest_mismatch"):
            self.verify()

    def test_changed_adapter_contract_refuses(self):
        with patch.object(v, "VALIDATION_WORKFLOW_SHA256", "0" * 64):
            with self.assertRaisesRegex(v.Refused, "validation_workflow_adapter_review_required"):
                self.verify()

    def test_missing_and_skipped_required_step_rejected(self):
        original = copy.deepcopy(self.fx.jobs[0]["steps"])
        cases = [original[:-1], [{**s, "conclusion": "skipped"} if i == 3 else s
                                for i, s in enumerate(original)]]
        for steps in cases:
            with self.subTest(steps=steps), self.assertRaises(v.Refused):
                self.fx.jobs[0]["steps"] = steps
                self.verify()

    def test_failed_cleanup_step_rejected(self):
        self.fx.jobs[0]["steps"].append({"number": 9, "name": "Post checkout", "status": "completed", "conclusion": "failure"})
        with self.assertRaisesRegex(v.Refused, "step_missing_skipped_or_failed"):
            self.verify()

    def test_duplicate_or_reordered_steps_rejected(self):
        self.fx.jobs[0]["steps"][1]["number"] = 1
        with self.assertRaisesRegex(v.Refused, "required_steps_missing_or_ambiguous"):
            self.verify()

    def test_job_failure_rejected(self):
        self.fx.jobs[0]["conclusion"] = "failure"
        with self.assertRaisesRegex(v.Refused, "job_not_successful"):
            self.verify()

    def test_wrong_labels_and_runner_rejected(self):
        with self.subTest("labels"):
            old = self.fx.jobs[0]["labels"]
            self.fx.jobs[0]["labels"] = ["self-hosted", "Linux", "X64", "wrong"]
            with self.assertRaisesRegex(v.Refused, "runner_label_mismatch"):
                self.verify()
            self.fx.jobs[0]["labels"] = old
        self.fx.jobs[0]["runner_name"] = "generic-runner"
        with self.assertRaisesRegex(v.Refused, "runner_identity_mismatch"):
            self.verify()

    def test_receipt_identity_or_state_cannot_be_forged(self):
        p = self.fx.root / "run-10-job-20-attempt-1/receipt.json"
        original = json.loads(p.read_text())
        for key, value in [("head_sha", "f" * 40), ("attempt", 2), ("attempt", True), ("runner_id", 1),
                           ("role", "ops"), ("state", "registered"), ("issues", ["unverified"]),
                           ("runner_exit", True)]:
            with self.subTest(field=key):
                private(p, v.canonical({**original, key: value}))
                with self.assertRaisesRegex(v.Refused, "runner_receipt_identity_invalid"):
                    self.verify()
        private(p, v.canonical(original))

    def test_tampered_log_rejected(self):
        private(self.fx.root / "run-10-job-20-attempt-1/runner.log", b"different log")
        with self.assertRaisesRegex(v.Refused, "runner_log_digest_mismatch"):
            self.verify()

    def test_missing_receipt_rejected(self):
        (self.fx.root / "run-10-job-20-attempt-1/receipt.json").unlink()
        with self.assertRaisesRegex(v.Refused, "evidence_file_unavailable"):
            self.verify()

    def test_receipt_hardlink_rejected(self):
        p = self.fx.root / "run-10-job-20-attempt-1/receipt.json"
        os.link(p, self.root / "receipt-link")
        with self.assertRaisesRegex(v.Refused, "unsafe_evidence_file"):
            self.verify()

    def test_receipt_symlink_rejected(self):
        p = self.fx.root / "run-10-job-20-attempt-1/receipt.json"
        actual = p.with_name("original.json")
        p.rename(actual)
        p.symlink_to(actual)
        with self.assertRaisesRegex(v.Refused, "evidence_file_unavailable"):
            self.verify()

    def test_public_receipt_root_rejected(self):
        self.fx.root.chmod(0o755)
        with self.assertRaisesRegex(v.Refused, "unsafe_private_directory"):
            self.verify()

    def test_skipped_sparse_is_not_success_nor_blocks_check(self):
        # Match the actual generated workflow manifest: it carries inherited
        # events even though ci.yml has a pull_request-only job-level if.
        self.fx.source["jobs"][SPARSE]["events"] = ["pull_request", "push", "workflow_dispatch"]
        self.fx.jobs.append({"id": 21, "run_id": 10, "run_attempt": 1, "head_sha": HEAD,
                             "name": "sparse repair build smoke", "status": "completed", "conclusion": "skipped",
                             "runner_name": None, "runner_id": None, "steps": []})
        self.assertEqual(list(self.verify()), [CHECK])

    def test_skipped_sparse_cannot_hide_an_executed_step_or_assigned_runner(self):
        self.fx.source["jobs"][SPARSE]["events"] = ["pull_request", "push", "workflow_dispatch"]
        baseline = {"id": 21, "run_id": 10, "run_attempt": 1, "head_sha": HEAD,
                    "name": "sparse repair build smoke", "status": "completed", "conclusion": "skipped",
                    "runner_name": None, "runner_id": None, "steps": []}
        for changes in ({"runner_name": "unexpected"}, {"runner_id": 200},
                        {"steps": [{"number": 1, "name": "Set up job", "conclusion": "success"}]},
                        {"status": "queued"}, {"conclusion": "failure"}):
            with self.subTest(changes=changes):
                self.fx.jobs.append({**baseline, **changes})
                try:
                    with self.assertRaisesRegex(v.Refused, "sparse_expected_skip_mismatch"):
                        self.verify()
                finally:
                    self.fx.jobs.pop()

    def test_pr_without_executed_merge_attestation_is_held(self):
        self.fx.run["event"] = "pull_request"
        with self.assertRaisesRegex(v.Refused, "executed_pr_merge_attestation_required"):
            self.verify()

    def test_rerun_during_readback_rejected(self):
        self.fx.after_run = {**self.fx.run, "run_attempt": 2}
        with self.assertRaisesRegex(v.Refused, "run_changed_during_observation"):
            self.verify()

    def test_job_changes_during_readback_rejected(self):
        self.fx.after_job = {**self.fx.jobs[0], "runner_name": "different"}
        with self.assertRaisesRegex(v.Refused, "job_changed_during_observation"):
            self.verify()

    def test_duplicate_job_ids_rejected(self):
        self.fx.jobs.append(copy.deepcopy(self.fx.jobs[0]))
        with self.assertRaisesRegex(v.Refused, "page_identity_duplicate_or_invalid"):
            self.verify()

    def test_truncated_page_rejected(self):
        with self.assertRaisesRegex(v.Refused, "page_inventory_truncated"):
            v._pages(lambda _: {"total_count": 2, "jobs": [{"id": 1}]}, "endpoint", "jobs")

    def test_changing_page_total_rejected(self):
        def get(path):
            return ({"total_count": 101, "jobs": [{"id": n} for n in range(1, 101)]}
                    if path.endswith("&page=1") else {"total_count": 102, "jobs": [{"id": 101}, {"id": 102}]})
        with self.assertRaisesRegex(v.Refused, "page_inventory_invalid"):
            v._pages(get, "endpoint", "jobs")

    def test_complete_multiple_pages_supported(self):
        def get(path):
            return {"total_count": 101, "jobs": [{"id": n} for n in
                    (range(1, 101) if path.endswith("&page=1") else [101])]}
        self.assertEqual(len(v._pages(get, "endpoint", "jobs")), 101)

    def test_failed_provider_read_does_not_inflate_counts(self):
        get = self.fx.get
        def failed(path):
            if "/actions/runs/" in path:
                raise v.Refused("github_readback_unavailable")
            return get(path)
        with patch.object(v, "source_manifest", return_value=self.fx.source):
            report = v.build_report(self.root, HEAD, [10], self.fx.root, get=failed)
        self.assertEqual(report["execution_verified_jobs"], 0)
        self.assertFalse(report["readback_complete"])

    def test_foreign_and_mutation_endpoints_never_reach_cli(self):
        for endpoint in ["https://evil.invalid", "repos/Other/repo/commits/" + HEAD,
                         v.API + "/actions/workflows/ci.yml/enable", v.API + "/actions/runners/generate-jitconfig"]:
            with self.subTest(endpoint=endpoint), patch.object(v, "_bounded_stdout") as run:
                with self.assertRaisesRegex(v.Refused, "github_endpoint_not_allowed"):
                    v.github_get(endpoint)
                run.assert_not_called()

    def test_github_cli_is_explicit_get(self):
        with patch.object(v, "_bounded_stdout", return_value=b'{}') as run:
            v.github_get(v.API + "/commits/" + HEAD)
            argv = run.call_args.args[0]
            self.assertEqual(argv[:6], ["gh", "api", "--hostname", "github.com", "--method", "GET"])
            self.assertEqual(run.call_args.kwargs["max_bytes"], v.MAX_JSON)
            self.assertEqual(run.call_args.kwargs["timeout_seconds"], 30)

    def test_codeql_delegates_existing_sarif_adapter_and_counts_once(self):
        fx = Fixtures(self.root / "security", codeql=True)
        called = []
        def adapter(get, run_id, sha, pr, receipts):
            called.append((run_id, sha, pr, receipts))
            jobs = get(f"{v.API}/actions/runs/10/jobs?per_page=100")["jobs"]
            self.assertEqual(len(jobs), 2)
            return fx.codeql_adapter()
        with patch.object(v, "source_manifest", return_value=fx.source), patch.object(v.verify_codeql_release, "verify_release", side_effect=adapter):
            report = v.build_report(self.root, HEAD, [10], fx.root, get=fx.get, containers=lambda _: True, log_get=fx.job_log)
        self.assertEqual(len(called), 1)
        self.assertEqual(report["execution_verified_jobs"], 1)
        proof = next(j for j in report["jobs"] if j["job_key"] == v.CODEQL)["execution_proofs"][0]
        self.assertEqual(len(proof["job_ids"]), 2)
        self.assertEqual(proof["security_alert_3"], "open")

    def replacement_fixture(self):
        fx = Fixtures(self.root / "replacement-security", codeql=True)
        job = fx.jobs[0]
        original_name, original_id = job["runner_name"], job["runner_id"]
        leaf = fx.root / f"run-10-job-{job['id']}-attempt-1"
        original = json.loads((leaf / "receipt.json").read_text())
        original["state"] = "runner_started"
        original["runner_exit"] = None
        original_raw = v.canonical(original)
        private(leaf / "receipt.json", original_raw)
        job["runner_name"] += "-replacement-1"
        job["runner_id"] = 500
        replacement = {**original, "runner_name": job["runner_name"], "runner_id": 500,
                       "state": "passed", "runner_exit": 0,
                       "original_receipt_sha256": v.digest(original_raw),
                       "github_job": {**original["github_job"], "runner_name": job["runner_name"]}}
        target = leaf.with_name(leaf.name + "-replacement-1")
        target.mkdir(mode=0o700)
        private(target / "receipt.json", v.canonical(replacement))
        private(target / "runner.log", (leaf / "runner.log").read_bytes())
        adapter = fx.codeql_adapter()
        return fx, original_name, original_id, adapter

    def test_replacement_original_container_residue_rejected(self):
        fx, original_name, _, adapter = self.replacement_fixture()
        with patch.object(v.verify_codeql_release, "verify_release", return_value=adapter):
            with self.assertRaisesRegex(v.Refused, "owned_container_cleanup_unverified"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda name: name != original_name, log_get=fx.job_log)

    def test_replacement_original_registration_residue_rejected(self):
        fx, original_name, original_id, adapter = self.replacement_fixture()
        fx.runners = [{"id": original_id, "name": original_name}]
        with patch.object(v.verify_codeql_release, "verify_release", return_value=adapter):
            with self.assertRaisesRegex(v.Refused, "owned_runner_still_registered"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True, log_get=fx.job_log)

    def test_replacement_checks_original_and_replacement_cleanup(self):
        fx, original_name, _, adapter = self.replacement_fixture()
        observed = []
        def containers(name):
            observed.append(name)
            return True
        with patch.object(v.verify_codeql_release, "verify_release", return_value=adapter):
            result = v.verify_run(fx.source, 10, fx.root, fx.get, containers, log_get=fx.job_log)
        self.assertIn(original_name, observed)
        self.assertIn(original_name + "-replacement-1", observed)
        self.assertEqual(len(result[v.CODEQL]["recovered_originals"]), 1)

    def test_foreign_sarif_source_without_job_upload_identity_refused(self):
        # Red regression: the old CodeQL adapter accepts unrelated uploads
        # sharing source, ref and timestamps because no job SARIF ID is checked.
        fx = Fixtures(self.root / "foreign-sarif", codeql=True)
        adapter = fx.codeql_adapter()
        with patch.object(v.verify_codeql_release, "verify_release", return_value=adapter):
            with self.assertRaisesRegex(v.Refused, "codeql_sarif_identity_unverified"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True,
                             log_get=lambda _: b"run completed with no SARIF upload ID")

    def test_sarif_upload_id_is_proven_by_exact_job_log(self):
        fx = Fixtures(self.root / "sarif-positive", codeql=True)
        with patch.object(v.verify_codeql_release, "verify_release", return_value=fx.codeql_adapter()):
            result = v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True, log_get=fx.job_log)
        proof = result[v.CODEQL]["uploaded_sarif"]
        self.assertEqual(set(proof), {"actions", "javascript-typescript"})
        self.assertEqual(proof["actions"]["sarif_id"], fx.sarif_ids["actions"])
        self.assertTrue(all(x["processed"] for x in proof.values()))

    def test_sarif_upload_wrong_job_run_or_language_refused(self):
        fx = Fixtures(self.root / "sarif-negative", codeql=True)
        for field, value in (("run=10", "run=11"),
                             ("attempt=1", "attempt=2"),
                             ("language=actions", "language=javascript-typescript"),
                             ("sarif_id=" + fx.sarif_ids["actions"],
                              "sarif_id=" + fx.sarif_ids["javascript-typescript"])):
            with self.subTest(field=field):
                def logs(job_id):
                    raw = fx.job_log(job_id)
                    return raw.replace(field.encode(), value.encode()) if job_id == 20 else raw
                with patch.object(v.verify_codeql_release, "verify_release", return_value=fx.codeql_adapter()):
                    with self.assertRaisesRegex(v.Refused, "codeql_sarif_job_provenance_mismatch"):
                        v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True, log_get=logs)

    def test_duplicate_or_missing_job_upload_attestation_refused(self):
        fx = Fixtures(self.root / "sarif-duplicate", codeql=True)
        for logs in (lambda j: fx.job_log(j) * 2, lambda j: b"no valid upload receipt"):
            with patch.object(v.verify_codeql_release, "verify_release", return_value=fx.codeql_adapter()):
                with self.assertRaisesRegex(v.Refused, "codeql_sarif_identity_unverified"):
                    v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True, log_get=logs)

    def test_provider_upload_incomplete_refused(self):
        fx = Fixtures(self.root / "sarif-incomplete", codeql=True)
        def provider(path):
            result = fx.get(path)
            if "/code-scanning/sarifs/" in path:
                return {**result, "processing_status": "pending"}
            return result
        with patch.object(v.verify_codeql_release, "verify_release", return_value=fx.codeql_adapter()):
            with self.assertRaisesRegex(v.Refused, "codeql_sarif_upload_not_processed"):
                v.verify_run(fx.source, 10, fx.root, provider, lambda _: True, log_get=fx.job_log)

    def test_sarif_exact_job_attestation_cannot_be_inferred_from_old_steps(self):
        fx = Fixtures(self.root / "sarif-old-steps", codeql=True)
        fx.jobs[0]["steps"] = fx.jobs[0]["steps"][:-1]
        with patch.object(v.verify_codeql_release, "verify_release", return_value=fx.codeql_adapter()):
            with self.assertRaisesRegex(v.Refused, "required_steps_missing_or_ambiguous"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True, log_get=fx.job_log)

    def test_untrusted_api_endpoint_not_allowed(self):
        for path in (v.API + "/actions/jobs/20/logs", v.API + "/code-scanning/sarifs/../bad"):
            with self.assertRaisesRegex(v.Refused, "github_endpoint_not_allowed"):
                v.github_get(path)

    def test_changed_codeql_workflow_cannot_approve_itself_via_manifest(self):
        fx = Fixtures(self.root / "self-approval", codeql=True)
        fx.workflow += b"\n# changed instructions must receive adapter review\n"
        fx.source["sources"][CODEQL] = v.digest(fx.workflow)
        fx.source["jobs"][v.CODEQL]["source_sha256"] = v.digest(fx.workflow)
        with self.assertRaisesRegex(v.Refused, "codeql_workflow_adapter_review_required"):
            v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True, log_get=fx.job_log)

    def test_runtime_change_during_observation_refuses_report(self):
        self.runtime_mock.side_effect = [{"fixture": "a" * 64}, {"fixture": "b" * 64}]
        with self.assertRaisesRegex(v.Refused, "runtime_source_changed_during_observation"):
            self.report()

    def test_codeql_adapter_refusal_keeps_job_held(self):
        fx = Fixtures(self.root / "security", codeql=True)
        with patch.object(v.verify_codeql_release, "verify_release", side_effect=v.verify_codeql_release.EvidenceRefused("missing_sarif")):
            with self.assertRaisesRegex(v.Refused, "codeql_adapter_refused"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True, log_get=fx.job_log)

    def test_durable_report_is_create_only_and_idempotent(self):
        out = self.root / "observation"
        with patch.object(v, "source_manifest", return_value=self.fx.source):
            a = v.observe(self.root, HEAD, [10], self.fx.root, out, get=self.fx.get, containers=lambda _: True)
            b = v.observe(self.root, HEAD, [10], self.fx.root, out, get=self.fx.get, containers=lambda _: True)
        self.assertEqual(a["report"], b["report"])
        self.assertEqual(v.digest((out / a["report"]).read_bytes()), a["report_sha256"])
        self.assertEqual((out / a["report"]).stat().st_nlink, 1)
        self.assertEqual((out / a["report"]).stat().st_mode & 0o777, 0o600)
        self.assertFalse(b["production_release_accepted"])

    def test_failed_refresh_invalidates_old_latest(self):
        out = self.root / "observation"
        with patch.object(v, "source_manifest", return_value=self.fx.source):
            v.observe(self.root, HEAD, [10], self.fx.root, out, get=self.fx.get, containers=lambda _: True)
            self.fx.fail = True
            result = v.observe(self.root, HEAD, [10], self.fx.root, out, get=self.fx.get, containers=lambda _: True)
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(json.loads((out / "latest.json").read_text())["state"], "unverified")
        self.assertEqual(len([p for p in out.glob("*.json") if p.name != "latest.json"]), 1)

    def test_interruption_leaves_observing_not_stale_success(self):
        out = self.root / "observation"
        with patch.object(v, "build_report", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                v.observe(self.root, HEAD, [10], self.fx.root, out)
        self.assertEqual(json.loads((out / "latest.json").read_text())["state"], "observing")

    def test_output_symlink_or_hardlinked_latest_rejected(self):
        actual = self.root / "real"
        actual.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(v.Refused):
            v.observe(self.root, HEAD, [], self.fx.root, alias)
        private(actual / "latest.json", b"{}")
        os.link(actual / "latest.json", self.root / "linked-latest")
        with self.assertRaisesRegex(v.Refused, "unsafe_existing_report"):
            v.observe(self.root, HEAD, [], self.fx.root, actual)


class ImmutableSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        self.git("init", "-q")
        workflow = b"name: fixture\non: push\njobs:\n  check:\n    runs-on: self-hosted\n    steps: []\n"
        p = self.root / CI
        p.parent.mkdir(parents=True)
        p.write_bytes(workflow)
        self.manifest = {"schema": "clawsweeper.workflow-estate.v2",
                         "sources": [{"path": CI, "sha256": v.digest(workflow)}],
                         "jobs": [entry(CI, "check", "pnpm check", ["push"], v.digest(workflow))],
                         "summary": {"workflows": 1, "jobs": 1, "github_hosted": 0, "dynamic_hosted_fallback": 0}}
        (self.root / "config").mkdir()
        self.save()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], env=self.env, stderr=subprocess.DEVNULL).decode().strip()

    def save(self):
        (self.root / "config/ci-workflow-estate.json").write_bytes(v.canonical(self.manifest))
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD")

    def test_exact_commit_ignores_unstaged_worktree_bytes(self):
        (self.root / CI).write_bytes(b"dirty worktree is not evidence")
        source = v.source_manifest(self.root, self.sha)
        self.assertEqual(source["head_sha"], self.sha)
        self.assertEqual(len(source["jobs"]), 1)

    def test_manifest_digest_tampering_rejected(self):
        self.manifest["sources"][0]["sha256"] = "0" * 64
        self.save()
        with self.assertRaisesRegex(v.Refused, "workflow_source_digest_mismatch"):
            v.source_manifest(self.root, self.sha)

    def test_uninventoried_workflow_rejected(self):
        (self.root / ".github/workflows/hidden.yml").write_text("name: hidden\n")
        self.save()
        with self.assertRaisesRegex(v.Refused, "workflow_inventory_incomplete"):
            v.source_manifest(self.root, self.sha)

    def test_duplicate_manifest_job_rejected(self):
        self.manifest["jobs"].append(copy.deepcopy(self.manifest["jobs"][0]))
        self.manifest["summary"]["jobs"] = 2
        self.save()
        with self.assertRaisesRegex(v.Refused, "duplicate_manifest_job"):
            v.source_manifest(self.root, self.sha)

    def test_missing_dag_dependency_rejected(self):
        self.manifest["jobs"][0]["needs"] = ["missing"]
        self.save()
        with self.assertRaisesRegex(v.Refused, "manifest_dag_incomplete"):
            v.source_manifest(self.root, self.sha)


class BoundedReadTests(unittest.TestCase):
    """Real child processes, not a fake completed byte buffer."""

    def command(self, source):
        return [sys.executable, "-B", "-c", source]

    def test_exact_output_limit_is_permitted(self):
        data = v._bounded_stdout(self.command("import sys;sys.stdout.write('x'*1024)"),
                                 max_bytes=1024, timeout_seconds=3)
        self.assertEqual(data, b"x" * 1024)

    def test_stream_overflow_stops_before_full_buffer(self):
        with self.assertRaisesRegex(v.Refused, "provider_stdout_limit"):
            v._bounded_stdout(self.command("import sys;sys.stdout.write('x'*1000000)"),
                              max_bytes=1024, timeout_seconds=3)

    def test_nonzero_exit_refused(self):
        with self.assertRaisesRegex(v.Refused, "provider_stdout_exit_nonzero"):
            v._bounded_stdout(self.command("raise SystemExit(3)"), max_bytes=1024, timeout_seconds=3)

    def test_timeout_kills_owned_process(self):
        started = time.monotonic()
        with self.assertRaisesRegex(v.Refused, "provider_stdout_timeout"):
            v._bounded_stdout(self.command("import time;time.sleep(30)"),
                              max_bytes=1024, timeout_seconds=0.2)
        self.assertLess(time.monotonic() - started, 5)

    def test_exited_leader_cannot_leave_inherited_pipe_child_running(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            script = ("import subprocess,sys;from pathlib import Path;"
                      "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                      f"Path({str(marker)!r}).write_text(str(p.pid))")
            with self.assertRaisesRegex(v.Refused, "provider_stdout_timeout"):
                v._bounded_stdout(self.command(script), max_bytes=1024, timeout_seconds=0.5)
            pid = int(marker.read_text())
            state = Path(f"/proc/{pid}/stat")
            try:
                for _ in range(25):
                    if not state.exists() or state.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                        break
                    time.sleep(0.02)
                else:
                    self.fail("timed-out owned child survived an exited group leader")
            finally:
                # Test fixture cleanup only; never leave the deliberate sleeper.
                if state.exists():
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass

    def test_zip_expansion_refused_before_read(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("log.txt", b"x" * 2048)
        with patch.object(v, "MAX_JSON", 1024), patch.object(v, "_bounded_stdout", return_value=stream.getvalue()):
            with self.assertRaisesRegex(v.Refused, "github_job_log_oversized_or_ambiguous"):
                v.github_job_log(1)


class BoundedProviderPathTests(unittest.TestCase):
    """Exercise actual read-only GitHub/Git entrypoints with oversized output."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def stub(self, command, script):
        exe = self.root / command
        exe.write_text("#!" + sys.executable + "\n" + script + "\n")
        exe.chmod(0o700)
        return {"PATH": str(self.root) + os.pathsep + os.environ.get("PATH", "")}

    def test_github_get_never_buffers_oversized_json(self):
        env = self.stub("gh", "import sys;sys.stdout.write('z'*1000000)")
        with patch.dict(os.environ, env), patch.object(v, "MAX_JSON", 1024):
            with self.assertRaisesRegex(v.Refused, "github_readback_unavailable"):
                v.github_get(v.API + "/commits/" + HEAD)

    def test_git_never_buffers_oversized_source(self):
        env = self.stub("git", "import sys;sys.stdout.write('x'*1000000)")
        with patch.dict(os.environ, env), patch.object(v, "MAX_JSON", 1024):
            with self.assertRaisesRegex(v.Refused, "immutable_source_unavailable"):
                v._git(self.root, "show", "HEAD:config/ci-workflow-estate.json")

    def test_github_timeout_is_bounded_and_refused(self):
        env = self.stub("gh", "import time;time.sleep(30)")
        real = v._bounded_stdout
        def tiny_deadline(args, *, max_bytes, timeout_seconds):
            return real(args, max_bytes=max_bytes, timeout_seconds=0.2)
        with patch.dict(os.environ, env), patch.object(v, "_bounded_stdout", side_effect=tiny_deadline):
            with self.assertRaisesRegex(v.Refused, "github_readback_unavailable"):
                v.github_get(v.API + "/commits/" + HEAD)

    def test_git_timeout_is_bounded_and_refused(self):
        env = self.stub("git", "import time;time.sleep(30)")
        real = v._bounded_stdout
        def tiny_deadline(args, *, max_bytes, timeout_seconds):
            return real(args, max_bytes=max_bytes, timeout_seconds=0.2)
        with patch.dict(os.environ, env), patch.object(v, "_bounded_stdout", side_effect=tiny_deadline):
            with self.assertRaisesRegex(v.Refused, "immutable_source_unavailable"):
                v._git(self.root, "show", "HEAD:config/ci-workflow-estate.json")


class RuntimeProofTests(unittest.TestCase):
    """Real isolated Git source and interpreter, plus the actual JS enumerator."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = Path(__file__).resolve().parents[2]
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                    "PYTHONDONTWRITEBYTECODE": "1"}
        self.paths = ("scripts/ci/verify_estate_execution.py", "scripts/ci/verify_codeql_release.py",
                      "scripts/ci/estate_policy.py", "scripts/ci/self_hosted_executor.py",
                      "scripts/ci/workflow-estate.mjs")
        for name in self.paths:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.repo / name, target)
            target.chmod(0o600)
        (self.root / "node_modules").symlink_to(self.repo / "node_modules", target_is_directory=True)
        workflow = self.root / CI
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: fixture\non: push\njobs:\n  check:\n    runs-on: [self-hosted, Linux, X64]\n    steps: []\n  leaf:\n    runs-on: [self-hosted, Linux, X64]\n    steps: []\n")
        (self.root / "config").mkdir()
        data = subprocess.check_output(["node", "--input-type=module", "-e",
            "import {inspectEstate} from './scripts/ci/workflow-estate.mjs';console.log(JSON.stringify(inspectEstate()));"],
            cwd=self.root, env=self.env, timeout=10)
        (self.root / "config/ci-workflow-estate.json").write_bytes(data)
        self.git("init", "-q")
        self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], env=self.env,
                                       stderr=subprocess.DEVNULL, timeout=10).decode().strip()

    def commit(self):
        self.git("add", "scripts", "config", ".github")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD")

    def probe(self):
        program = ("import json,sys;sys.path.insert(0,'scripts/ci');import verify_estate_execution as v;"
                   "print(json.dumps(v.runtime_source_proof('.',sys.argv[1])))")
        return subprocess.run([sys.executable, "-B", "-c", program, self.sha], cwd=self.root,
                              env=self.env, capture_output=True, text=True, timeout=15)

    def test_exact_committed_dependencies_and_inventory_verified(self):
        result = self.probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 6)

    def test_changed_first_party_dependency_refused(self):
        for name in self.paths:
            with self.subTest(path=name):
                p = self.root / name
                original = p.read_bytes()
                p.write_bytes(original + (b"\n// changed\n" if name.endswith(".mjs") else b"\n# changed\n"))
                try:
                    result = self.probe()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("runtime_source_bytes_drift", result.stderr)
                finally:
                    p.write_bytes(original)

    def test_timestamp_valid_cache_poison_does_not_replace_loaded_policy(self):
        # An unrelated CPython import would accept these cache bytes while the
        # on-disk committed estate_policy.py remains unmodified and authentic.
        policy = self.root / "scripts/ci/estate_policy.py"
        payload = policy.read_bytes()
        poisoned = payload.replace(b'REPO = "AyobamiH/clawsweeper"',
                                   b'REPO = "untrusted/stale-cache"')
        self.assertNotEqual(poisoned, payload)
        stat_result = policy.stat()
        bytecode = bootstrap_external._code_to_timestamp_pyc(
            compile(poisoned, str(policy), "exec"), int(stat_result.st_mtime), len(payload))
        cache = Path(importlib.util.cache_from_source(str(policy)))
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(bytecode)
        direct = subprocess.run([sys.executable, "-B", "-c",
            "import sys;sys.path.insert(0,'scripts/ci');import estate_policy;print(estate_policy.REPO)"],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertEqual(direct.stdout.strip(), "untrusted/stale-cache")
        verified = subprocess.run([sys.executable, "-B", "-c",
            "import sys;sys.path.insert(0,'scripts/ci');import verify_estate_execution as v;"
            "print(v.estate_policy.REPO);print(v.runtime_source_proof('.',sys.argv[1]) is not None)",
            self.sha], cwd=self.root, env=self.env,
            capture_output=True, text=True, timeout=20)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(verified.stdout.splitlines(), ["AyobamiH/clawsweeper", "True"])

    def test_policy_changes_after_source_execution_are_refused(self):
        policy = self.root / "scripts/ci/estate_policy.py"
        original = policy.read_bytes()
        policy.write_bytes(original + b"\n# changed after import\n")
        result = self.probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime_source_bytes_drift", result.stderr)

    def test_changed_executor_ownership_label_contract_refused(self):
        p = self.root / "scripts/ci/self_hosted_executor.py"
        original = p.read_text()
        self.assertIn('LABEL = "io.ayobamih.clawsweeper.selfhosted"', original)
        p.write_text(original.replace('LABEL = "io.ayobamih.clawsweeper.selfhosted"',
                                      'LABEL = "io.ayobamih.clawsweeper.drifted"'))
        self.commit()
        result = self.probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container_label_contract_changed", result.stderr)

    def test_symlinked_runtime_dependency_refused(self):
        p = self.root / "scripts/ci/estate_policy.py"
        other = self.root / "private-copy.py"
        p.rename(other)
        p.symlink_to(other)
        result = self.probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime_module_provenance_mismatch", result.stderr)

    def test_hardlinked_runtime_dependency_refused(self):
        p = self.root / "scripts/ci/estate_policy.py"
        os.link(p, self.root / "hardlink.py")
        result = self.probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime_module_untrusted", result.stderr)

    def test_group_writable_runtime_dependency_refused(self):
        (self.root / "scripts/ci/estate_policy.py").chmod(0o660)
        result = self.probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime_module_untrusted", result.stderr)

    def test_self_consistent_manifest_omitting_leaf_is_rejected(self):
        p = self.root / "config/ci-workflow-estate.json"
        manifest = json.loads(p.read_text())
        manifest["jobs"] = [j for j in manifest["jobs"] if j["id"] != "leaf"]
        manifest["summary"]["jobs"] = 1
        manifest["summary"]["local_label"] = 1
        manifest["execution_boundaries"]["local_label_unverified"] = 1
        p.write_bytes(v.canonical(manifest))
        self.commit()
        result = self.probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("independent_job_inventory_mismatch", result.stderr)

    def test_changed_workflow_cannot_hide_behind_old_manifest(self):
        with (self.root / CI).open("a") as stream:
            stream.write("  hidden:\n    runs-on: self-hosted\n    steps: []\n")
        self.commit()
        result = self.probe()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("independent_job_inventory_mismatch", result.stderr)



if __name__ == "__main__":
    unittest.main()
