"""Adversarial offline acceptance for the strict read-only estate observer."""
import datetime as dt
import fcntl
import hashlib
import json
import os
import shutil
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import observe_estate_health as observer


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="clawsweeper-estate-observe-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "repo"
        self.checkout.mkdir()
        (self.checkout / "config").mkdir()
        (self.checkout / ".github/workflows").mkdir(parents=True)
        workflow = self.checkout / ".github/workflows/example.yml"
        workflow.write_text("name: sample\non: workflow_dispatch\njobs:\n  example:\n    runs-on: [self-hosted, Linux]\n    steps: []\n")
        # Exercise the actual source inventory generator in the fixture; its
        # manifest must not be self-approved by just editing its own counters.
        project = Path(__file__).resolve().parents[2]
        source = self.checkout / "scripts/ci/workflow-estate.mjs"
        source.parent.mkdir(parents=True)
        shutil.copyfile(project / "scripts/ci/workflow-estate.mjs", source)
        (self.checkout / "node_modules").symlink_to(project / "node_modules", target_is_directory=True)
        # The full CI fleet can heavily contend for CPU and filesystem IO.
        # Do not silently skip this real enumerator or alter its assertions:
        # bound its fixture setup at 90 seconds and preserve any timeout as a failure.
        subprocess.run(["node", "scripts/ci/workflow-estate.mjs", "--write"],
                       cwd=self.checkout, stdout=subprocess.DEVNULL, check=True, timeout=90)
        subprocess.run(["git", "-C", str(self.checkout), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.checkout), "add", "config", ".github", "scripts"], check=True)
        subprocess.run(["git", "-C", str(self.checkout),
                        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
        self.sha = git(self.checkout, "rev-parse", "HEAD")
        self.state = self.root / "state"
        self.slot = dt.datetime(2026, 11, 10, 19, 45, tzinfo=dt.timezone.utc)
        self.values = {"queued": [], "pending": [], "in_progress": []}
        self.fail_at = None

    def read(self, path):
        if path == self.fail_at:
            raise observer.Hold("github_get_failed")
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "b" * 40}}
        if path.endswith("/git/ref/heads/develop"):
            return {"object": {"sha": self.sha}}
        if "/actions/runs?" in path:
            status = path.split("status=")[1].split("&")[0]
            return {"total_count": len(self.values[status]),
                    "workflow_runs": self.values[status]}
        if "/actions/runners?" in path:
            return {"total_count": 0, "runners": []}
        raise AssertionError("unexpected GitHub request:" + path)

    def observe(self):
        return observer.observe(self.checkout, self.state, self.read, self.slot)


class ObserverSecurity(Fixture):
    def test_no_effects_and_exact_source_manifest(self):
        result = self.observe()
        self.assertEqual(result["state"], "observed")
        receipt = json.loads(Path(result["receipt"]).read_text())
        source = receipt["core"]["source"]
        self.assertEqual(source["develop"]["sha"], self.sha)
        self.assertEqual((source["develop"]["workflows"], source["develop"]["jobs"]), (1, 1))
        self.assertEqual(source["main_sha"], "b" * 40)
        self.assertFalse(source["workflow_admitted"])
        self.assertFalse(source["operational_acceptance_claimed"])
        self.assertEqual(source["effect_count"], 0)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(Path(result["receipt"]).stat().st_mode & 0o777, 0o600)

    def test_second_identical_observation_is_idempotent(self):
        first = self.observe()
        second = self.observe()
        self.assertEqual(second["state"], "already_observed")
        self.assertEqual(first["identity"], second["identity"])
        self.assertEqual(len(list((self.state / "receipts").glob("*.json"))), 1)

    def test_crash_between_receipt_and_latest_recovers_without_duplicate(self):
        first = self.observe()
        (self.state / "latest.json").unlink()
        again = self.observe()
        self.assertEqual(again["state"], "already_observed")
        latest = json.loads((self.state / "latest.json").read_text())
        self.assertEqual(latest["receipt_sha256"], first["receipt_sha256"])
        self.assertEqual(len(list((self.state / "receipts").glob("*.json"))), 1)

    def test_live_status_change_same_slot_produces_distinct_receipt(self):
        first = self.observe()
        self.values["queued"] = [{
            "id": 141, "head_sha": self.sha, "path": ".github/workflows/ci.yml",
            "status": "queued", "event": "pull_request"}]
        second = self.observe()
        self.assertEqual(second["state"], "observed")
        self.assertNotEqual(first["identity"], second["identity"])
        self.assertEqual(len(list((self.state / "receipts").glob("*.json"))), 2)

    def test_missing_github_read_fails_closed_and_records_unverified(self):
        self.fail_at = f"repos/{observer.REPOSITORY}/actions/runs?status=queued&per_page=30"
        result = self.observe()
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["reason"], "github_get_failed")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")
        self.assertEqual(json.loads((self.state / "last-attempt.json").read_text())["effect_count"], 0)

    def test_failure_after_success_revokes_latest_health(self):
        old = self.observe()
        self.assertEqual(old["state"], "observed")
        self.fail_at = f"repos/{observer.REPOSITORY}/actions/runs?status=queued&per_page=30"
        latest = self.observe()
        self.assertEqual(latest["state"], "unverified")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")
        # Preserve the original successful receipt as evidence, not a fresh health claim.
        self.assertTrue(Path(old["receipt"]).is_file())
        self.assertEqual(len(list((self.state / "receipts").glob("*.json"))), 1)

    def test_stale_source_does_not_claim_health(self):
        original = self.sha
        self.sha = "c" * 40
        result = self.observe()
        self.assertEqual(result["reason"], "develop_head_changed_or_checkout_stale")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")
        self.sha = original

    def test_workflow_source_drift_fails_closed(self):
        with (self.checkout / ".github/workflows/example.yml").open("a") as f:
            f.write("# altered\n")
        result = self.observe()
        self.assertEqual(result["reason"], "source_tracked_changes_present")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")

    def test_manifest_schema_drift_fails_closed(self):
        p = self.checkout / "config/ci-workflow-estate.json"
        value = json.loads(p.read_text())
        value["summary"]["jobs"] = 999
        p.write_text(json.dumps(value))
        result = self.observe()
        self.assertEqual(result["reason"], "source_tracked_changes_present")

    def test_duplicate_run_ids_fail_closed(self):
        row = {"id": 4, "head_sha": self.sha, "status": "queued",
               "path": ".github/workflows/ci.yml", "event": "pull_request"}
        self.values["queued"] = [row, dict(row)]
        self.assertEqual(self.observe()["reason"], "duplicate_github_run_identity")

    def test_run_snapshot_never_claims_exhaustive_when_more_exist(self):
        row = {"id": 4, "head_sha": self.sha, "status": "queued",
               "path": ".github/workflows/ci.yml", "event": "pull_request"}
        self.values["queued"] = [row]
        original = self.read
        def read(path):
            v = original(path)
            if "status=queued" in path:
                v["total_count"] = 100
            return v
        report = observer.snapshot(self.checkout, read)
        self.assertEqual(report["run_samples"]["queued"]["coverage"], "latest_30_only")

    def test_tampered_existing_receipt_is_never_accepted(self):
        old = self.observe()
        receipt = Path(old["receipt"])
        j = json.loads(receipt.read_text())
        j["core"]["source"]["runner_count"] = 999
        receipt.write_text(json.dumps(j))
        self.assertEqual(self.observe()["reason"], "receipt_identity_conflict")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")

    def test_bad_git_checkout_after_success_revokes_healthy_status(self):
        first = self.observe()
        self.assertEqual(first["state"], "observed")
        (self.checkout / ".git").rename(self.checkout / ".git-backup")
        latest = self.observe()
        self.assertEqual(latest["state"], "unverified")
        self.assertIn("source_manifest_unverifiable", latest["reason"])
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")

    def test_malformed_metadata_after_success_revokes_healthy_status(self):
        first = self.observe()
        self.assertEqual(first["state"], "observed")
        old = self.read
        def malformed(path):
            if path.endswith("/actions/runners?per_page=30"):
                return None
            return old(path)
        latest = observer.observe(self.checkout, self.state, malformed, self.slot)
        self.assertEqual(latest["state"], "unverified")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")

    def test_interrupted_snapshot_never_preserves_prior_success(self):
        self.assertEqual(self.observe()["state"], "observed")
        with patch.object(observer, "snapshot", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.observe()
        for name in ("latest.json", "last-attempt.json"):
            latest = json.loads((self.state / name).read_text())
            self.assertEqual(latest["state"], "unverified")
            self.assertEqual(latest["reason"], "observation_in_progress")

    def test_interrupted_between_invalidation_writes_is_fail_closed(self):
        old = self.observe()
        original = observer._atomic
        calls = []
        def interrupted(path, value):
            calls.append(path.name)
            if len(calls) == 2:
                raise KeyboardInterrupt
            return original(path, value)
        with patch.object(observer, "_atomic", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.observe()
        self.assertEqual(calls, ["latest.json", "last-attempt.json"])
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")
        self.assertTrue(Path(old["receipt"]).exists())

    def test_manifest_missing_leaf_refuses_after_self_consistent_rewrite(self):
        path = self.checkout / ".github/workflows/example.yml"
        path.write_text(path.read_text() + "  extra:\n    runs-on: [self-hosted, Linux]\n    steps: []\n")
        manifest = self.checkout / "config/ci-workflow-estate.json"
        value = json.loads(manifest.read_text())
        value["sources"][0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        value["jobs"][0]["source_sha256"] = value["sources"][0]["sha256"]
        # Self-consistent manifest claims one job although YAML now has two.
        manifest.write_text(json.dumps(value))
        subprocess.run(["git", "-C", str(self.checkout), "add", "config", ".github"], check=True)
        subprocess.run(["git", "-C", str(self.checkout),
                        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture-two"], check=True)
        self.sha = git(self.checkout, "rev-parse", "HEAD")
        result = self.observe()
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["reason"], "independent_workflow_inventory_mismatch")

    def test_manifest_missing_workflow_refuses_after_self_consistent_rewrite(self):
        other = self.checkout / ".github/workflows/hidden.yml"
        other.write_text("name: hidden\non: push\njobs:\n  hidden:\n    runs-on: self-hosted\n    steps: []\n")
        subprocess.run(["git", "-C", str(self.checkout), "add", ".github"], check=True)
        subprocess.run(["git", "-C", str(self.checkout),
                        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "fixture-hidden"], check=True)
        self.sha = git(self.checkout, "rev-parse", "HEAD")
        result = self.observe()
        self.assertEqual(result["reason"], "independent_workflow_inventory_mismatch")

    def test_source_ref_changed_during_observation_refused(self):
        reads = {"develop": 0}
        old = self.read
        def moving(path):
            value = old(path)
            if path.endswith("/git/ref/heads/develop"):
                reads["develop"] += 1
                if reads["develop"] > 1:
                    return {"object": {"sha": "c" * 40}}
            return value
        latest = observer.observe(self.checkout, self.state, moving, self.slot)
        self.assertEqual(latest["reason"], "github_ref_changed_during_observation")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")

    def test_hidden_inventory_helper_edit_refused_despite_clean_git_status(self):
        script = self.checkout / "scripts/ci/workflow-estate.mjs"
        original = script.read_bytes()
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                script.write_bytes(original + b"\n// tampered helper\n")
                subprocess.run(["git", "-C", str(self.checkout), "update-index",
                                flag, "scripts/ci/workflow-estate.mjs"], check=True)
                try:
                    # Git's index hint may conceal these bytes; our direct HEAD
                    # comparison cannot rely on its reported cleanliness.
                    result = self.observe()
                    self.assertEqual(result["state"], "unverified")
                    self.assertEqual(result["reason"], "consumed_source_bytes_drift")
                finally:
                    undo = "--no-assume-unchanged" if flag == "--assume-unchanged" else "--no-skip-worktree"
                    subprocess.run(["git", "-C", str(self.checkout), "update-index",
                                    undo, "scripts/ci/workflow-estate.mjs"], check=True)
                    script.write_bytes(original)

    def test_verified_inventory_never_executes_postcapture_original_replacement(self):
        # A transient attacker swaps both original helper and YAML after exact
        # blob validation, then restores them before the final source recheck.
        original = observer._committed_consumed_sources
        helper = self.checkout / "scripts/ci/workflow-estate.mjs"
        workflow = self.checkout / ".github/workflows/example.yml"
        marker = self.root / "untrusted-helper-executed"
        good_helper, good_workflow = helper.read_bytes(), workflow.read_bytes()
        calls = []
        def after_verified(checkout, sha):
            if not calls:
                sealed = original(checkout, sha)
                helper.write_text(
                    "import{writeFileSync}from'node:fs';"
                    + "writeFileSync(" + json.dumps(str(marker)) + ",'BAD');"
                    + "process.exit(93);")
                workflow.write_text("this is not an accepted YAML job mapping\\n")
                calls.append("swapped_after_verified")
                return sealed
            helper.write_bytes(good_helper)
            workflow.write_bytes(good_workflow)
            calls.append("restored_before_final_recheck")
            return original(checkout, sha)
        try:
            with patch.object(observer, "_committed_consumed_sources",
                              side_effect=after_verified):
                observer._complete_inventory(self.checkout, self.sha)
        finally:
            helper.write_bytes(good_helper)
            workflow.write_bytes(good_workflow)
        self.assertEqual(calls, ["swapped_after_verified", "restored_before_final_recheck"])
        self.assertFalse(marker.exists())

    def test_late_untracked_workflow_remains_a_hold_after_isolated_inventory(self):
        original = observer._committed_consumed_sources
        late = self.checkout / ".github/workflows/late.yml"
        def add_after_verified(checkout, sha):
            sealed = original(checkout, sha)
            late.write_text("name: late\\non: push\\njobs:\\n  surprise:\\n    runs-on: self-hosted\\n    steps: []\\n")
            return sealed
        with patch.object(observer, "_committed_consumed_sources",
                          side_effect=add_after_verified):
            with self.assertRaises(observer.Hold):
                observer._complete_inventory(self.checkout, self.sha)

    def test_source_fifo_replacement_fails_without_hanging(self):
        source = self.checkout / "scripts/ci/workflow-estate.mjs"
        source.unlink()
        os.mkfifo(source, 0o600)
        start = time.monotonic()
        with self.assertRaisesRegex(observer.Hold, "consumed_source_oversized_or_nonregular"):
            observer._safe_source_bytes(source)
        self.assertLess(time.monotonic() - start, 2)

    def test_source_size_bound_cannot_read_oversized_file(self):
        source = self.root / "oversized-source.mjs"
        with source.open("wb") as stream:
            stream.truncate(observer.MAX_SOURCE_BYTES + 1)
        with self.assertRaisesRegex(observer.Hold, "consumed_source_oversized_or_nonregular"):
            observer._safe_source_bytes(source)

    def test_clean_head_switch_after_capture_refused_by_exact_sha_blob(self):
        original = observer._committed_consumed_sources
        moved = False
        def switch(checkout, sha):
            nonlocal moved
            if not moved:
                helper = checkout / "scripts/ci/workflow-estate.mjs"
                helper.write_bytes(helper.read_bytes() + b"\n// changed clean head after capture\n")
                subprocess.run(["git", "-C", str(checkout), "add", "scripts/ci/workflow-estate.mjs"], check=True)
                subprocess.run(["git", "-C", str(checkout),
                                "-c", "commit.gpgsign=false",
                                "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid",
                                "commit", "-qm", "next-head"], check=True)
                moved = True
            return original(checkout, sha)
        with patch.object(observer, "_committed_consumed_sources", side_effect=switch):
            with self.assertRaisesRegex(observer.Hold, "consumed_source_bytes_drift"):
                observer.current_source(self.checkout)
        self.assertTrue(moved)

    def test_clean_head_switch_after_inventory_refused(self):
        original = observer._complete_inventory
        moved = False
        def switch(checkout, sha):
            nonlocal moved
            result = original(checkout, sha)
            if not moved:
                doc = checkout / "observed-head-switch.txt"
                doc.write_text("clean new revision while post-read check is pending\n")
                subprocess.run(["git", "-C", str(checkout), "add", "observed-head-switch.txt"], check=True)
                subprocess.run(["git", "-C", str(checkout),
                                "-c", "commit.gpgsign=false",
                                "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid",
                                "commit", "-qm", "next-head"], check=True)
                moved = True
            return result
        with patch.object(observer, "_complete_inventory", side_effect=switch):
            with self.assertRaisesRegex(observer.Hold, "source_revision_changed_during_validation"):
                observer.current_source(self.checkout)
        self.assertTrue(moved)

    def test_existing_fifo_receipt_is_refused_without_blocking(self):
        first = self.observe()
        path = Path(first["receipt"])
        path.unlink()
        os.mkfifo(path, 0o600)
        start = time.monotonic()
        result = self.observe()
        self.assertLess(time.monotonic() - start, 10)
        self.assertEqual(result["reason"], "unsafe_existing_receipt")

    def test_existing_hardlink_receipt_is_refused(self):
        first = self.observe()
        path = Path(first["receipt"])
        os.link(path, self.root / "external-receipt-link")
        self.assertEqual(self.observe()["reason"], "unsafe_existing_receipt")

    def test_oversized_existing_receipt_is_refused_before_reading_contents(self):
        first = self.observe()
        path = Path(first["receipt"])
        with path.open("wb") as stream:
            stream.truncate(4 * 1024 * 1024 + 1)
        self.assertEqual(self.observe()["reason"], "unsafe_existing_receipt")

    def test_oversized_untracked_workflow_fails_before_node(self):
        extra = self.checkout / ".github/workflows/huge.yml"
        with extra.open("wb") as stream:
            stream.truncate(observer.MAX_SOURCE_BYTES + 1)
        with patch.object(observer, "_bounded_stdout", wraps=observer._bounded_stdout) as bounded:
            report = self.observe()
            calls = [x.args[0] for x in bounded.call_args_list]
        self.assertEqual(report["reason"], "consumed_source_oversized")
        self.assertFalse(any(args and args[0] == "node" for args in calls))

    def test_checkout_modified_during_provider_reads_refuses_new_health(self):
        read = self.read
        changed = False
        def race(path):
            nonlocal changed
            response = read(path)
            if not changed and path.endswith("/actions/runners?per_page=30"):
                with (self.checkout / ".github/workflows/example.yml").open("a") as stream:
                    stream.write("# drift after original source validation\n")
                changed = True
            return response
        report = observer.observe(self.checkout, self.state, race, self.slot)
        self.assertTrue(changed)
        self.assertEqual(report["state"], "unverified")
        self.assertEqual(report["reason"], "checkout_changed_during_observation")
        self.assertEqual(json.loads((self.state / "latest.json").read_text())["state"], "unverified")

    def test_checkout_head_changed_during_readback_refuses_current_claim(self):
        read = self.read
        changed = False
        def race(path):
            nonlocal changed
            response = read(path)
            if not changed and path.endswith("/actions/runners?per_page=30"):
                doc = self.checkout / "source-transition.txt"
                doc.write_text("changed clean revision while GH reads in flight\n")
                subprocess.run(["git", "-C", str(self.checkout), "add", "source-transition.txt"],
                               check=True)
                subprocess.run(["git", "-C", str(self.checkout),
                                "-c", "commit.gpgsign=false",
                                "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid",
                                "commit", "-qm", "changed"], check=True)
                changed = True
            return response
        report = observer.observe(self.checkout, self.state, race, self.slot)
        self.assertTrue(changed)
        self.assertEqual(report["reason"], "checkout_changed_during_observation")

    def test_lock_contention_is_not_a_success(self):
        self.state.mkdir(mode=0o700)
        p = self.state / "owner.lock"
        with p.open("w+") as f:
            os.chmod(p, 0o600)  # source requires owner-private lock, even in fixture

            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                report = self.observe()
                self.assertEqual(report["state"], "held_other_observer")
                self.assertFalse((self.state / "latest.json").exists())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def test_world_readable_state_directory_refused(self):
        self.state.mkdir(mode=0o755)
        # The real full-suite launcher uses umask 0077; mkdir's requested mode
        # is masked by that process umask. Force the deliberate unsafe fixture
        # permission before asserting the observer refuses it.
        self.state.chmod(0o755)
        with self.assertRaisesRegex(observer.Hold, "unsafe_state_permissions"):
            self.observe()

    def test_reader_is_get_only_with_allowlisted_endpoint(self):
        with patch.object(observer, "_bounded_stdout", return_value=b"{}") as bounded:
            observer.github_get(f"repos/{observer.REPOSITORY}/git/ref/heads/main")
            args = bounded.call_args.args[0]
            self.assertEqual(args[:4], ["gh", "api", "--method", "GET"])
            self.assertEqual(bounded.call_args.kwargs["max_bytes"], 4 * 1024 * 1024)
            with self.assertRaisesRegex(observer.Hold, "unapproved_github_endpoint"):
                observer.github_get("repos/AyobamiH/clawsweeper/actions/workflows/ci.yml/dispatches")
            self.assertEqual(bounded.call_count, 1)


class BoundedReadRegression(unittest.TestCase):
    """Process-backed adversarial cases; no synthetic fake completed PIPE."""

    def cmd(self, source):
        return [sys.executable, "-B", "-c", source]

    def test_exact_limit_and_nonzero_exit(self):
        self.assertEqual(
            observer._bounded_stdout(
                self.cmd("import sys;sys.stdout.write('z'*1024)"),
                max_bytes=1024, timeout_seconds=3),
            b"z" * 1024)
        with self.assertRaisesRegex(observer.Hold, "bounded_process_failed"):
            observer._bounded_stdout(
                self.cmd("raise SystemExit(7)"), max_bytes=1024, timeout_seconds=3)

    def test_oversized_response_rejected_before_unbounded_read(self):
        with self.assertRaisesRegex(observer.Hold, "bounded_process_oversize"):
            observer._bounded_stdout(
                self.cmd("import sys;sys.stdout.write('z'*1000000)"),
                max_bytes=1024, timeout_seconds=3)

    def test_slow_response_terminates_owned_process(self):
        start = time.monotonic()
        with self.assertRaisesRegex(observer.Hold, "bounded_process_timeout"):
            observer._bounded_stdout(
                self.cmd("import time;time.sleep(30)"),
                max_bytes=1024, timeout_seconds=0.2)
        self.assertLess(time.monotonic() - start, 4)

    def test_orphan_pipe_descendant_cannot_outlive_failed_read(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "pid"
            source = (
                "import subprocess,sys;from pathlib import Path;"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                f"Path({str(pidfile)!r}).write_text(str(child.pid))"
            )
            with self.assertRaisesRegex(observer.Hold, "bounded_process_timeout"):
                observer._bounded_stdout(self.cmd(source), max_bytes=1024, timeout_seconds=0.5)
            pid = int(pidfile.read_text())
            proc = Path("/proc") / str(pid) / "stat"
            try:
                for _ in range(40):
                    if not proc.exists() or proc.read_text().rsplit(")", 1)[1].split()[0] == "Z":
                        break
                    time.sleep(0.02)
                else:
                    self.fail("bounded observer left descendant executing")
            finally:
                if proc.exists():
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass

    def test_github_read_rejects_oversize_and_timeout(self):
        with patch.object(observer, "_bounded_stdout", side_effect=observer.Hold("bounded_process_oversize")):
            with self.assertRaisesRegex(observer.Hold, "github_read_unavailable"):
                observer.github_get(f"repos/{observer.REPOSITORY}/git/ref/heads/main")
        with patch.object(observer, "_bounded_stdout", side_effect=observer.Hold("bounded_process_timeout")):
            with self.assertRaisesRegex(observer.Hold, "github_read_unavailable"):
                observer.github_get(f"repos/{observer.REPOSITORY}/git/ref/heads/main")



if __name__ == "__main__":
    unittest.main()
