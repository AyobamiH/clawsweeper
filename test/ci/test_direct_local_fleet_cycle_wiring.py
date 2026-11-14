"""Isolated, no-provider integration gate for an exact frozen fleet cycle."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts" / "ci"
spec = importlib.util.spec_from_file_location(
    "direct_local_fleet_cycle_wiring_test", SOURCE / "direct_local_fleet_cycle_wiring.py")
wiring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wiring)

BASE = b"""import json
def parallel_work(db,policy,max_jobs):
    rows=[dict(r) for r in db.execute(
        "SELECT * FROM jobs WHERE state='queued' AND ready_at<=? "
        "ORDER BY CASE ref WHEN 'main' THEN 0 ELSE 1 END,created_at,id LIMIT 100",
        (time.time(),)).fetchall()]
    if not rows: return
    return rows
def main():
    a=p.parse_args()
    policy=load_policy()
    db=setup()
    if a.mode=='execute-job':
        result=detached.execute(db,policy,a.job_id or '',a.claim_token or '')
        return
    with core.lock():
        if a.mode in ('discover','cycle'):
            discover(db,policy,not a.main_only,a.repo)
        if a.mode in ('work','cycle'):
            detached.dispatch(db,policy,a.max_jobs)
            for _ in range(max(0,min(a.max_jobs,10))):
                row=db.execute("SELECT * FROM jobs WHERE state='queued' AND ready_at<=? ORDER BY CASE ref WHEN 'main' THEN 0 ELSE 1 END,created_at,id LIMIT 1",(time.time(),)).fetchone()
                if not row:break
            parallel_work(db,policy,a.max_jobs)
"""
INGRESS = (SOURCE / "direct_local_ingress_reconcile.py").read_bytes()
VERIFIER = (SOURCE / "direct_local_receiver_integration.py").read_bytes()


def render(source=BASE, digest=None, ingress=INGRESS, verifier=VERIFIER):
    return wiring.compile_prelock_source(
        source, expected_sha256=digest or hashlib.sha256(source).hexdigest(),
        ingress_adapter=ingress, release_verifier=verifier)


class ExactFleetSourceTests(unittest.TestCase):
    def test_hook_is_before_existing_canonical_lock_and_after_setup(self):
        result = render()
        text = result["content"].decode()
        ast.parse(text)
        self.assertLess(text.index("verified_clawsweeper_local_ingress"),
                        text.index("with core.lock():"))
        self.assertGreater(text.index("verified_clawsweeper_local_ingress"),
                           text.index("if a.mode=='execute-job':"))
        self.assertEqual(text.count("with core.lock():"), 1)
        self.assertEqual(text.count("db=setup()"), 1)
        self.assertIn("if a.mode in ('discover', 'cycle', 'work') and HOST == 'web':", text)
        self.assertIn("if _dl_release:", text)
        self.assertIn("exec(compile(_dl_bytes[_dl_entry.name]", text)
        self.assertEqual(result["ingress_sha256"], wiring.sha(INGRESS))
        self.assertEqual(result["verifier_sha256"], wiring.sha(VERIFIER))
        self.assertEqual(result["proposed_sha256"], wiring.sha(result["content"]))
        self.assertNotEqual(result["current_sha256"], result["proposed_sha256"])

    def test_source_drift_refused_without_installation(self):
        with self.assertRaisesRegex(RuntimeError, "fleet_controller_exact_source_mismatch"):
            render(digest="0" * 64)
        with self.assertRaisesRegex(RuntimeError, "fleet_controller_exact_source_mismatch"):
            render(source=BASE + b"# altered", digest=wiring.sha(BASE))

    def test_duplicate_patch_not_silently_allowed(self):
        with self.assertRaisesRegex(RuntimeError, "unrecognised_canonical_fleet_cycle_shape"):
            render(source=render()["content"])

    def test_unrecognised_fleet_cycle_rejected(self):
        for change in (
            BASE.replace(b"with core.lock():", b"with different.lock():"),
            BASE.replace(b"with core.lock():", b"with core.lock():\n        pass\n    with core.lock():"),
            BASE.replace(b"if a.mode in ('work','cycle'):", b"if a.mode == 'work':"),
            BASE.replace(b"    db=setup()\n", b""),
        ):
            with self.subTest(sample=change[:70]):
                with self.assertRaisesRegex(RuntimeError, "unrecognised_canonical_fleet_cycle_shape"):
                    render(change)

    def test_invalid_release_isolated_across_all_fleet_admission_modes(self):
        generated = render()["content"].decode()
        self.assertIn("except Exception as _dl_error:", generated)
        self.assertIn("clawsweeper_direct_local_hold", generated)
        self.assertIn("if _dl_repo != 'AyobamiH/clawsweeper'", generated)
        self.assertIn("discover(db,_dl_exec_policy", generated)
        self.assertIn("detached.dispatch(db,_dl_exec_policy", generated)
        self.assertIn('AND repo!=? ', generated)
        self.assertIn("parallel_work(db,_dl_exec_policy", generated)
        self.assertIn("if _dl_hold else None", generated)
        self.assertIn("clawsweeper_worker_release_path_unverified", generated)
        self.assertIn("clawsweeper_worker_release_verifier_changed", generated)
        self.assertNotIn("error': str(_dl_error)", generated)
        self.assertEqual(generated.count("with core.lock():"), 1)

    def test_release_isolation_shape_drift_is_refused(self):
        current = BASE.replace(b"detached.dispatch(db,policy,a.max_jobs)",
                               b"detached.dispatch(db,policy,5)")
        with self.assertRaisesRegex(RuntimeError,
                                    "unrecognised_local_fleet_repository_isolation_shape"):
            render(source=current)
        current = BASE.replace(b"parallel_work(db,policy,a.max_jobs)",
                               b"parallel_work(db,policy,a.max_jobs,1)")
        with self.assertRaisesRegex(RuntimeError,
                                    "unrecognised_local_fleet_repository_isolation_shape"):
            render(source=current)

    def test_detached_worker_release_guard_drift_refused(self):
        current = BASE.replace(
            b"result=detached.execute(db,policy,a.job_id or '',a.claim_token or '')",
            b"result=detached.execute(db,policy,a.job_id or '')")
        with self.assertRaisesRegex(RuntimeError,
                                    "unrecognised_local_fleet_worker_isolation_shape"):
            render(source=current)

    def test_invalid_release_runtime_holds_only_clawsweeper_and_worker(self):
        import contextlib
        import hashlib as _hashlib
        import io
        import os
        import pathlib
        import time
        import types
        from unittest.mock import patch

        class Result:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

            def fetchall(self):
                return []

        class FakeDB:
            def __init__(self, worker_repo):
                self.queries = []
                self.worker_repo = worker_repo

            def execute(self, sql, args):
                self.queries.append((sql, args))
                if sql.startswith("SELECT repo FROM jobs"):
                    return Result({"repo": self.worker_repo})
                return Result()

        def run(mode, worker_repo, invalid_release):
            db = FakeDB(worker_repo)
            events = []
            policy = {"repositories": {
                "AyobamiH/clawsweeper": {},
                "AyobamiH/opstruth-chatgpt-plugin": {},
            }}
            args = types.SimpleNamespace(
                mode=mode, max_jobs=1, main_only=False, repo=None,
                job_id="local-fleet-123456789abc", claim_token="fixture")
            namespace = {
                "p": types.SimpleNamespace(parse_args=lambda: args),
                "load_policy": lambda: policy,
                "setup": lambda: db,
                "core": types.SimpleNamespace(lock=contextlib.nullcontext),
                "ROOT": pathlib.Path("/nonexistent/fleet-test"),
                "HOST": "web", "os": os, "pathlib": pathlib,
                "hashlib": _hashlib, "time": time,
                "discover": lambda _db, chosen, *_: events.append(
                    ("discover", set(chosen["repositories"]))),
                "detached": types.SimpleNamespace(
                    dispatch=lambda _db, chosen, _count: events.append(
                        ("dispatch", set(chosen["repositories"]))),
                    execute=lambda *_: events.append(("execute", worker_repo))),
            }
            exec(compile(render()["content"], "<isolated-fleet>", "exec"),
                 namespace)
            release = ({"FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE":
                        "/wrong/release.json"} if invalid_release else {})
            with patch.dict(os.environ, release, clear=True):
                with contextlib.redirect_stdout(io.StringIO()) as printed:
                    if mode == "execute-job" and invalid_release and (
                            worker_repo == "AyobamiH/clawsweeper"):
                        with self.assertRaisesRegex(
                                RuntimeError,
                                "clawsweeper_worker_release_path_unverified"):
                            namespace["main"]()
                    else:
                        namespace["main"]()
            return events, db.queries, printed.getvalue(), policy

        events, queries, output, policy = run(
            "cycle", "AyobamiH/clawsweeper", True)
        other = {"AyobamiH/opstruth-chatgpt-plugin"}
        self.assertIn(("discover", other), events)
        self.assertIn(("dispatch", other), events)
        self.assertEqual(len([x for x in queries if "AND repo!=?" in x[0]]), 2)
        self.assertIn("clawsweeper_direct_local_hold", output)
        self.assertNotIn("/wrong/release.json", output)
        self.assertEqual(len(policy["repositories"]), 2)
        for mode in ("work", "discover"):
            events, queries, _, _ = run(
                mode, "AyobamiH/clawsweeper", True)
            self.assertTrue(all(
                "AyobamiH/clawsweeper" not in x[1]
                for x in events if x[0] in ("discover", "dispatch")))
        events, _, _, _ = run("execute-job", "AyobamiH/clawsweeper", True)
        self.assertFalse(any(x[0] == "execute" for x in events))
        events, _, _, _ = run("execute-job",
                              "AyobamiH/opstruth-chatgpt-plugin", True)
        self.assertEqual(events,
                         [("execute", "AyobamiH/opstruth-chatgpt-plugin")])
        events, queries, _, _ = run(
            "cycle", "AyobamiH/clawsweeper", False)
        self.assertIn(("dispatch", set(policy["repositories"])), events)
        self.assertFalse(any("AND repo!=?" in q[0] for q in queries))

    def test_pins_are_per_exact_module_and_receipt_has_no_source(self):
        result = render()
        self.assertNotEqual(result["proposed_sha256"],
                            render(ingress=INGRESS + b"\n# changed")["proposed_sha256"])
        self.assertNotEqual(result["proposed_sha256"],
                            render(verifier=VERIFIER + b"\n# changed")["proposed_sha256"])
        self.assertNotIn("content", wiring.non_secret_receipt(result))

    def test_invalid_module_refuses(self):
        with self.assertRaisesRegex(RuntimeError, "non_python_fleet_or_ingress_source"):
            render(ingress=b"def broken(:")
        with self.assertRaisesRegex(RuntimeError, "unrecognised_canonical_fleet_cycle_shape"):
            render(ingress=b"")

    def test_no_independent_queue_runner_or_hosted_provider_added(self):
        body = render()["content"].split(b"    # Signed ClawSweeper", 1)[1].split(
            b"    with core.lock():", 1)[0]
        for banned in (b"subprocess", b"workflow_dispatch", b"github-hosted",
                       b"ThreadingHTTPServer", b"sqlite3.connect", b"systemctl",
                       b"docker", b"runner_register"):
            self.assertNotIn(banned, body)


if __name__ == "__main__":
    unittest.main()
