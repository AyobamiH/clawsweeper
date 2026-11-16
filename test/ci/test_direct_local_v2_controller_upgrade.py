"""Offline, fail-closed v1-installed -> distinct-v2 controller upgrade tests."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts" / "ci"
def load(label, path):
    spec = importlib.util.spec_from_file_location(label, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

wiring = load("upgrade_source", SOURCE / "direct_local_fleet_cycle_wiring.py")
fixture = load("upgrade_fixture", ROOT / "test/ci/test_direct_local_fleet_cycle_wiring.py")
REPO = "AyobamiH/clawsweeper"
SHA = "a" * 40
CHECK = ".github/workflows/ci.yml#check"
SPARSE = ".github/workflows/ci.yml#sparse-repair-builds"
SUITES = {CHECK: "linux-node24-claw-check",
          SPARSE: "linux-node24-claw-sparse"}

def rendered():
    v1 = fixture.render()["content"]
    return wiring.compile_distinct_v2_installed_upgrade(
        v1, expected_sha256=hashlib.sha256(v1).hexdigest())

def authenticated():
    source = rendered()["content"].decode()
    main = next(n for n in ast.parse(source).body
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    method = next(n for n in main.body
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_dl_authenticated_existing_job")
    source_lines = source.splitlines(True)
    fn_source = textwrap.dedent("".join(
        source_lines[method.lineno - 1:method.end_lineno]))
    return fn_source

class DistinctUpgradeTests(unittest.TestCase):
    def test_renders_v2_into_existing_owner_controller(self):
        obj = rendered()
        text = obj["content"].decode()
        ast.parse(text)
        self.assertEqual(obj["state"], "source_only_not_installed")
        self.assertEqual(obj["schema"], wiring.V2_SCHEMA)
        self.assertEqual(hashlib.sha256(obj["content"]).hexdigest(),
                         obj["proposed_sha256"])
        for needle in ("read_distinct_release(_dl_bound)",
                       "verify_distinct_release(_dl_doc)",
                       "profile='distinct'",
                       "authenticated_distinct_admission_not_execution",
                       "'direct-local-distinct:%'"):
            self.assertIn(needle, text)
        self.assertNotIn("read_release(_dl_bound)", text)
        self.assertNotIn("authenticated_queue_admission_not_execution", text)
        self.assertNotIn("'direct-local:%' LIMIT 2049", text)
        self.assertEqual(text.count("with core.lock():"), 1)
        self.assertEqual(text.count("def _dl_authenticated_existing_job"), 1)
        self.assertLess(text.index("reconcile_existing_fleet_ingress"),
                        text.index("with core.lock():"))
        for banned in ("workflow_dispatch", "pull_request_target",
                       "runner_register", "hosted_fallback"):
            self.assertNotIn(banned, text)

    def test_exact_source_drift_and_second_upgrade_fail_closed(self):
        v1 = fixture.render()["content"]
        digest = hashlib.sha256(v1).hexdigest()
        for source, expected in ((v1 + b"#changed\n", digest),
                                 (v1, "0" * 64)):
            with self.subTest(case=source[:30]):
                with self.assertRaisesRegex(RuntimeError,
                                            "distinct_upgrade_exact_installed"):
                    wiring.compile_distinct_v2_installed_upgrade(
                        source, expected_sha256=expected)
        v2 = rendered()["content"]
        with self.assertRaisesRegex(RuntimeError,
                                    "distinct_upgrade_unreviewed_v1_fleet_shape"):
            wiring.compile_distinct_v2_installed_upgrade(
                v2, expected_sha256=hashlib.sha256(v2).hexdigest())

    def test_unreviewed_v1_authentication_change_refused(self):
        v1 = fixture.render()["content"]
        changed = v1.replace(b"'direct-local:%' LIMIT 2049",
                             b"'direct-local:%' LIMIT 2050")
        with self.assertRaisesRegex(RuntimeError,
                                    "distinct_upgrade_unreviewed_v1_fleet_shape"):
            wiring.compile_distinct_v2_installed_upgrade(
                changed, expected_sha256=hashlib.sha256(changed).hexdigest())

    def make_context(self, ref="pr/101", event="pull_request"):
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE jobs(id TEXT,repo TEXT,sha TEXT,suite TEXT,
                              ref TEXT,policy TEXT,state TEXT);
            CREATE TABLE observations(key TEXT, value TEXT);
        """)
        names = list(SUITES) if ref != "main" else [CHECK]
        rows = []
        for i, name in enumerate(names):
            row = {"job_id": f"local-fleet-{i + 1:012x}",
                   "workflow_job": name, "suite": SUITES[name],
                   "policy": f"{i + 1:064x}"}
            rows.append(row)
            db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)",
                       (row["job_id"], REPO, SHA, row["suite"], ref,
                        row["policy"], "queued"))
        record = {"source_sha": SHA, "ref": ref, "event": event,
                  "proof_kind": "authenticated_distinct_admission_not_execution",
                  "intent_identity_sha256": "b" * 64,
                  "delivery_sha256": "c" * 64, "jobs": rows}
        db.execute("INSERT INTO observations VALUES(?,?)",
                   ("direct-local-distinct:one", json.dumps(record)))
        namespace = {"db": db, "policy": {"repositories": {
            REPO: {"enrolled_head": SHA}}}, "json": json}
        exec(authenticated(), namespace)
        self.addCleanup(db.close)
        return db, record, rows, namespace["_dl_authenticated_existing_job"]

    def test_two_distinct_pr_jobs_authenticate_without_execution(self):
        _, _, rows, check = self.make_context()
        for row in rows:
            self.assertTrue(check(row["job_id"]))
        self.assertFalse(check("local-fleet-ffffffffffff"))

    def test_one_push_check_job_is_not_two_acceptances(self):
        _, _, rows, check = self.make_context(ref="main", event="push")
        self.assertEqual(len(rows), 1)
        self.assertTrue(check(rows[0]["job_id"]))

    def test_sibling_must_exist_and_have_consistent_state(self):
        db, _, rows, check = self.make_context()
        sibling = rows[1]
        db.execute("DELETE FROM jobs WHERE id=?", (sibling["job_id"],))
        self.assertFalse(check(rows[0]["job_id"]))
        db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)",
                   (sibling["job_id"], REPO, SHA, sibling["suite"],
                    "pr/101", sibling["policy"], "cancelled"))
        self.assertFalse(check(rows[0]["job_id"]))
        db.execute("UPDATE jobs SET state='completed' WHERE id=?",
                   (sibling["job_id"],))
        self.assertTrue(check(rows[0]["job_id"]))

    def test_legacy_aggregate_and_relabelled_sandbox_are_refused(self):
        db, record, rows, check = self.make_context()
        db.execute("UPDATE jobs SET suite='linux-node24' WHERE id=?",
                   (rows[0]["job_id"],))
        self.assertFalse(check(rows[0]["job_id"]))
        db.execute("UPDATE jobs SET suite=? WHERE id=?",
                   (rows[0]["suite"], rows[0]["job_id"]))
        db.execute("UPDATE jobs SET policy=? WHERE id=?",
                   ("f" * 64, rows[0]["job_id"]))
        self.assertFalse(check(rows[0]["job_id"]))

    def test_signed_claim_mutation_and_duplicate_ids_refused(self):
        cases = [
            lambda x: x.update(proof_kind="authenticated_queue_admission_not_execution"),
            lambda x: x.update(source_sha="f" * 40),
            lambda x: x.update(event="push"),
            lambda x: x.update(intent_identity_sha256="bad"),
            lambda x: x["jobs"].pop(),
            lambda x: x["jobs"][1].update(job_id=x["jobs"][0]["job_id"]),
            lambda x: x["jobs"][1].update(policy="0" * 64),
            lambda x: x["jobs"][1].update(workflow_job=CHECK),
        ]
        for i, mutate in enumerate(cases):
            with self.subTest(i=i):
                db, record, rows, check = self.make_context()
                broken = copy.deepcopy(record)
                mutate(broken)
                db.execute("DELETE FROM observations")
                db.execute("INSERT INTO observations VALUES(?,?)",
                           ("direct-local-distinct:one", json.dumps(broken)))
                self.assertFalse(check(rows[0]["job_id"]))

    def test_ambiguous_or_corrupt_observation_fails_closed(self):
        db, record, rows, check = self.make_context()
        db.execute("INSERT INTO observations VALUES(?,?)",
                   ("direct-local-distinct:two", json.dumps(record)))
        self.assertFalse(check(rows[0]["job_id"]))
        db.execute("DELETE FROM observations")
        db.execute("INSERT INTO observations VALUES(?,?)",
                   ("direct-local-distinct:one", "{invalid"))
        self.assertFalse(check(rows[0]["job_id"]))

if __name__ == "__main__":
    unittest.main()
