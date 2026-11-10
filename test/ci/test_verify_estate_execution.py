"""Verifier logic tests: fixture success is NOT real operational acceptance."""
import base64
import copy
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
        self.workflow = b"# fixture bytes; not an accepted execution workflow\n"
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
        self.fx.jobs.append({"id": 21, "run_id": 10, "run_attempt": 1, "head_sha": HEAD,
                             "name": "sparse repair build smoke", "status": "completed", "conclusion": "skipped"})
        self.assertEqual(list(self.verify()), [CHECK])

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
            with self.subTest(endpoint=endpoint), patch.object(v.subprocess, "run") as run:
                with self.assertRaisesRegex(v.Refused, "github_endpoint_not_allowed"):
                    v.github_get(endpoint)
                run.assert_not_called()

    def test_github_cli_is_explicit_get(self):
        with patch.object(v.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b'{}')) as run:
            v.github_get(v.API + "/commits/" + HEAD)
            argv = run.call_args.args[0]
            self.assertEqual(argv[:6], ["gh", "api", "--hostname", "github.com", "--method", "GET"])

    def test_codeql_delegates_existing_sarif_adapter_and_counts_once(self):
        fx = Fixtures(self.root / "security", codeql=True)
        called = []
        def adapter(get, run_id, sha, pr, receipts):
            called.append((run_id, sha, pr, receipts))
            jobs = get(f"{v.API}/actions/runs/10/jobs?per_page=100")["jobs"]
            self.assertEqual(len(jobs), 2)
            return {"head_sha": HEAD, "run_attempt": 1, "analyses": {"actions": {"id": 9}, "javascript-typescript": {"id": 10}},
                    "security_alert_3": "open"}
        with patch.object(v, "source_manifest", return_value=fx.source), patch.object(v.verify_codeql_release, "verify_release", side_effect=adapter):
            report = v.build_report(self.root, HEAD, [10], fx.root, get=fx.get, containers=lambda _: True)
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
        adapter = {"head_sha": HEAD, "run_attempt": 1, "analyses": {}, "security_alert_3": "open"}
        return fx, original_name, original_id, adapter

    def test_replacement_original_container_residue_rejected(self):
        fx, original_name, _, adapter = self.replacement_fixture()
        with patch.object(v.verify_codeql_release, "verify_release", return_value=adapter):
            with self.assertRaisesRegex(v.Refused, "owned_container_cleanup_unverified"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda name: name != original_name)

    def test_replacement_original_registration_residue_rejected(self):
        fx, original_name, original_id, adapter = self.replacement_fixture()
        fx.runners = [{"id": original_id, "name": original_name}]
        with patch.object(v.verify_codeql_release, "verify_release", return_value=adapter):
            with self.assertRaisesRegex(v.Refused, "owned_runner_still_registered"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True)

    def test_replacement_checks_original_and_replacement_cleanup(self):
        fx, original_name, _, adapter = self.replacement_fixture()
        observed = []
        def containers(name):
            observed.append(name)
            return True
        with patch.object(v.verify_codeql_release, "verify_release", return_value=adapter):
            result = v.verify_run(fx.source, 10, fx.root, fx.get, containers)
        self.assertIn(original_name, observed)
        self.assertIn(original_name + "-replacement-1", observed)
        self.assertEqual(len(result[v.CODEQL]["recovered_originals"]), 1)

    def test_codeql_adapter_refusal_keeps_job_held(self):
        fx = Fixtures(self.root / "security", codeql=True)
        with patch.object(v.verify_codeql_release, "verify_release", side_effect=v.verify_codeql_release.EvidenceRefused("missing_sarif")):
            with self.assertRaisesRegex(v.Refused, "codeql_adapter_refused"):
                v.verify_run(fx.source, 10, fx.root, fx.get, lambda _: True)

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


if __name__ == "__main__":
    unittest.main()
