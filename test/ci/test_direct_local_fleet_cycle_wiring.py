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
        self.assertIn("discover(db,_dl_discovery_policy", generated)
        self.assertIn("legacy_or_ambiguous_queue_provenance", generated)
        self.assertIn("clawsweeper_worker_missing_authenticated_queue_claim", generated)
        self.assertIn("detached.dispatch(db,_dl_exec_policy", generated)
        self.assertIn('AND repo!=? ', generated)
        self.assertIn("parallel_work(db,_dl_exec_policy", generated)
        self.assertIn("if _dl_hold else None", generated)
        self.assertIn("clawsweeper_worker_release_path_unverified", generated)
        self.assertIn("clawsweeper_worker_release_verifier_changed", generated)
        self.assertIn("clawsweeper_existing_fleet_policy_pin_mismatch", generated)
        self.assertIn("clawsweeper_worker_source_policy_pin_mismatch", generated)
        self.assertIn("_dl_hold = a.mode in ('discover', 'cycle', 'work')", generated)
        self.assertIn("_dl_hold = False", generated)
        self.assertIn("_dl_release is not None", generated)
        # Detached workers must check ClawSweeper identity even with no env var.
        self.assertLess(generated.index("_dl_job = db.execute('SELECT repo FROM jobs"),
                        generated.index("_dl_release = os.environ.get('FLEET_DIRECT_LOCAL",
                                        generated.index("if a.mode=='execute-job':")))
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

        def run(mode, worker_repo, invalid_release, host="web"):
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
                "HOST": host, "os": os, "pathlib": pathlib,
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
                    if mode == "execute-job" and (
                            worker_repo == "AyobamiH/clawsweeper"):
                        # The separate systemd worker may have NO environment
                        # inheritance. Both absent and mismatched releases HOLD.
                        expected = ("clawsweeper_worker_release_path_unverified"
                                    if invalid_release else
                                    "clawsweeper_worker_release_verifier_untrusted")
                        with self.assertRaisesRegex(RuntimeError, expected):
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
        self.assertIn(("dispatch", other), events)
        self.assertTrue(any("AND repo!=?" in q[0] for q in queries))
        # A recovery on the standby host must not admit ClawSweeper either.
        events, queries, _, _ = run(
            "cycle", "AyobamiH/clawsweeper", False, host="Ayobami-Dev")
        self.assertIn(("dispatch", other), events)
        self.assertTrue(any("AND repo!=?" in q[0] for q in queries))

    def test_valid_released_cycle_and_detached_worker_without_inherited_env(self):
        # Effect-free behavioural proof: one existing fleet controller and one
        # detached worker check the fixed owner release in an isolated fixture.
        import contextlib
        import io
        import json
        import os
        import pathlib
        import tempfile
        import time
        import types
        from unittest.mock import patch

        ingress = (b"def reconcile_existing_fleet_ingress(**kwargs):\n"
                   b"    return {'inspected': 0, 'consumed': 0, 'held': 0}\n")
        verifier = (
            b"import json\n"
            b"def read_release(path):\n"
            b"    return json.loads(path.read_text())\n"
            b"def verify_release(doc):\n"
            b"    if doc != {'verified': True, 'commit': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'}:\n"
            b"        raise RuntimeError('wrong_owner_release')\n"
        )
        generated = render(ingress=ingress, verifier=verifier)["content"]
        with tempfile.TemporaryDirectory(prefix="clawsweeper-local-release-") as td:
            root = pathlib.Path(td)
            (root / "secrets").mkdir(mode=0o700)
            bound = root / "secrets" / "clawsweeper-direct-local-release.json"
            bound.write_text(json.dumps({"verified": True, "commit": "a" * 40}))
            bound.chmod(0o600)
            (root / "direct_local_ingress_reconcile.py").write_bytes(ingress)
            (root / "direct_local_receiver_integration.py").write_bytes(verifier)

            class Result:
                def __init__(self, row=None, rows=None):
                    self.row = row
                    self.rows = rows if rows is not None else []
                def fetchone(self):
                    return self.row
                def fetchall(self):
                    return self.rows

            class DB:
                proof_present = True
                legacy_queued = False

                def execute(self, sql, args=()):
                    if sql.startswith("SELECT repo FROM jobs"):
                        return Result({"repo": "AyobamiH/clawsweeper"})
                    if sql.startswith("SELECT id,repo,sha"):
                        return Result({
                            "id": args[0], "repo": "AyobamiH/clawsweeper",
                            "sha": "a" * 40, "suite": "linux-node24",
                            "ref": "pr/1", "state": "claimed",
                        })
                    if sql.startswith("SELECT id FROM jobs"):
                        return Result(rows=([{"id": "local-fleet-123456789abc"}]
                                            if DB.legacy_queued else []))
                    if sql.startswith("SELECT value FROM observations"):
                        claim = {
                            "job_id": "local-fleet-123456789abc",
                            "source_sha": "a" * 40, "suite": "linux-node24",
                            "ref": "pr/1", "event": "pull_request",
                            "proof_kind": "authenticated_queue_admission_not_execution",
                            "delivery_sha256": "b" * 64,
                            "intent_identity_sha256": "c" * 64,
                            "job_intents": [
                                ".github/workflows/ci.yml#check",
                                ".github/workflows/ci.yml#sparse-repair-builds",
                            ],
                        }
                        return Result(rows=([{"value": json.dumps(claim)}]
                                            if DB.proof_present else []))
                    return Result()

            for mode, env in (
                    ("cycle", {"FLEET_DIRECT_LOCAL_CLAWSWEEPER_RELEASE": str(bound)}),
                    ("execute-job", {})):
                seen = []
                repo_names = {"AyobamiH/clawsweeper",
                              "AyobamiH/opstruth-chatgpt-plugin"}
                policy = {"repositories": {key: {} for key in repo_names}}
                policy["repositories"]["AyobamiH/clawsweeper"] = {
                    "enrolled_head": "a" * 40}
                args = types.SimpleNamespace(
                    mode=mode, max_jobs=1, main_only=False, repo=None,
                    job_id="local-fleet-123456789abc", claim_token="fixture")
                namespace = {
                    "p": types.SimpleNamespace(parse_args=lambda: args),
                    "load_policy": lambda: policy,
                    "setup": DB,
                    "core": types.SimpleNamespace(lock=contextlib.nullcontext),
                    "ROOT": root, "HOST": "web", "os": os,
                    "pathlib": pathlib, "hashlib": hashlib, "time": time,
                    "discover": lambda _db, chosen, *_: seen.append(
                        ("discover", set(chosen["repositories"]))),
                    "detached": types.SimpleNamespace(
                        dispatch=lambda _db, chosen, _count: seen.append(
                            ("dispatch", set(chosen["repositories"]))),
                        execute=lambda *_: seen.append(("execute", True))),
                }
                exec(compile(generated, "<verified-local-release>", "exec"),
                     namespace)
                with patch.dict(os.environ, env, clear=True):
                    with contextlib.redirect_stdout(io.StringIO()) as report:
                        namespace["main"]()
                if mode == "cycle":
                    self.assertIn(("discover", {"AyobamiH/opstruth-chatgpt-plugin"}), seen)
                    self.assertIn(("dispatch", repo_names), seen)
                    self.assertIn("clawsweeper_direct_local_prelock",
                                  report.getvalue())
                    self.assertNotIn("clawsweeper_direct_local_hold",
                                     report.getvalue())
                    # A genuinely authenticated queue claim is admitted;
                    # a historical job with the same SHA but no provenance
                    # must not silently enter the detached execution lane.
                    DB.legacy_queued = True
                    DB.proof_present = True
                    seen.clear()
                    with patch.dict(os.environ, env, clear=True):
                        with contextlib.redirect_stdout(io.StringIO()) as verified:
                            namespace["main"]()
                    self.assertIn(("dispatch", repo_names), seen)
                    self.assertNotIn("legacy_or_ambiguous_queue_provenance",
                                     verified.getvalue())
                    DB.proof_present = False
                    seen.clear()
                    with patch.dict(os.environ, env, clear=True):
                        with contextlib.redirect_stdout(io.StringIO()) as unsafe:
                            namespace["main"]()
                    self.assertIn("legacy_or_ambiguous_queue_provenance",
                                  unsafe.getvalue())
                    self.assertIn(
                        ("dispatch", {"AyobamiH/opstruth-chatgpt-plugin"}), seen)
                    DB.legacy_queued = False
                    DB.proof_present = True
                    policy["repositories"]["AyobamiH/clawsweeper"][
                        "enrolled_head"] = "b" * 40
                    seen.clear()
                    with patch.dict(os.environ, env, clear=True):
                        with contextlib.redirect_stdout(io.StringIO()) as rejected:
                            namespace["main"]()
                    self.assertIn("clawsweeper_direct_local_hold",
                                  rejected.getvalue())
                    self.assertIn(
                        ("dispatch", {"AyobamiH/opstruth-chatgpt-plugin"}), seen)
                else:
                    # Simulates systemd-run not propagating manager environment.
                    self.assertIn(("execute", True), seen)
                    DB.proof_present = False
                    with patch.dict(os.environ, {}, clear=True):
                        with self.assertRaisesRegex(
                                RuntimeError,
                                "clawsweeper_worker_missing_authenticated_queue_claim"):
                            namespace["main"]()
                    DB.proof_present = True
                    policy["repositories"]["AyobamiH/clawsweeper"][
                        "enrolled_head"] = "b" * 40
                    with patch.dict(os.environ, {}, clear=True):
                        with self.assertRaisesRegex(
                                RuntimeError,
                                "clawsweeper_worker_source_policy_pin_mismatch"):
                            namespace["main"]()

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


class DistinctDockerCaptureTests(unittest.TestCase):
    """Adversarial, effect-free probe of the exact fleet-runner source patch."""

    WORKER = b"""def run_job(db,policy,row,cpu_affinity=None):
    job = dict(row)
    cfg = policy['repositories'][job['repo']]['suites'][job['suite']]
    name = job['id']
    tools = '/home/johnh/.local/share/local-ci/tools'
    args = ['docker', 'run']
    receipt = {}
    try:
        core.execute(args,timeout=30)
        initial='git init -q; '
    finally:
        pass
    return receipt
def configured_parallelism():
    return 1
"""

    def patch_source(self, source=None, expected=None):
        source = source if source is not None else self.WORKER
        return wiring.compile_distinct_sandbox_evidence_source(
            source,
            expected_sha256=expected or hashlib.sha256(source).hexdigest())

    def sandbox(self):
        name = 'local-fleet-0123456789ab'
        image = 'sha256:' + 'c' * 64
        return {
            'Id': 'b' * 64, 'Name': '/' + name, 'Image': image,
            'State': {'Running': True, 'OOMKilled': False},
            'Config': {'Image': image, 'User': '1001:123',
                       'Labels': {'io.ayobamih.local-ci.fleet': name}},
            'HostConfig': {
                'Privileged': False, 'NetworkMode': 'bridge',
                'Memory': 3072 * 1048576, 'MemorySwap': 3072 * 1048576,
                'NanoCpus': 4000000000, 'PidsLimit': 256,
                'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                'Binds': ['/home/johnh/.local/share/local-ci/tools:/ci-tools:ro'],
            },
        }

    def execute(self, sandbox, *, suite='linux-node24-claw-check',
                engine='docker', repo='AyobamiH/clawsweeper'):
        import copy
        import re
        from types import SimpleNamespace
        source = self.patch_source()['content'].decode()
        effects = {'run': 0, 'receipt': 0}
        def execute(args, timeout):
            effects['run'] += 1
        def atomic(path, receipt):
            effects['receipt'] += 1
        ns = {
            'ENGINE': engine, 'LABEL': 'io.ayobamih.local-ci.fleet',
            'STATE': Path('/tmp'),
            're': re,
            'core': SimpleNamespace(MIB=1048576, execute=execute, atomic=atomic),
            'inspect': lambda name: copy.deepcopy(sandbox),
        }
        exec(compile(source, '<reviewed-fleet-source-fixture>', 'exec'), ns)
        policy = {'image': 'sha256:' + 'c' * 64, 'repositories': {
            repo: {'suites': {suite: {
                'image': 'sha256:' + 'c' * 64,
                'cpus': 4, 'memory_mib': 3072, 'pids': 256,
            }}}}}
        job = {'id': 'local-fleet-0123456789ab', 'repo': repo, 'suite': suite}
        try:
            return ns['run_job'](None, policy, job), effects
        except RuntimeError as exc:
            return str(exc), effects

    def test_actual_docker_id_is_persisted_before_any_job_commands(self):
        receipt, effects = self.execute(self.sandbox())
        self.assertEqual(receipt['sandbox_identity'], 'local-fleet-0123456789ab')
        self.assertEqual(receipt['engine_container_id'], 'b' * 64)
        self.assertEqual(effects, {'run': 1, 'receipt': 1})

    def test_only_two_reviewed_suites_have_new_proof_requirement(self):
        for suite, repo in (
            ('linux-node24', 'AyobamiH/clawsweeper'),
            ('linux-python312', 'AyobamiH/post-once'),
        ):
            receipt, effects = self.execute(None, suite=suite, repo=repo)
            self.assertEqual(receipt, {})
            self.assertEqual(effects, {'run': 1, 'receipt': 0})

    def test_drifted_inspect_fails_before_any_command_receipt(self):
        import copy
        for location, field, value in (
            ((), 'Id', 'fake-job-derived-id'),
            ((), 'Name', '/foreign-container'),
            ((), 'Image', 'sha256:' + 'd' * 64),
            (('State',), 'Running', False),
            (('State',), 'OOMKilled', True),
            (('Config',), 'Image', 'sha256:' + 'd' * 64),
            (('Config',), 'User', '0:0'),
            (('Config', 'Labels'), 'io.ayobamih.local-ci.fleet', 'other'),
            (('HostConfig',), 'Privileged', True),
            (('HostConfig',), 'NetworkMode', 'host'),
            (('HostConfig',), 'Memory', 0),
            (('HostConfig',), 'MemorySwap', 0),
            (('HostConfig',), 'NanoCpus', 0),
            (('HostConfig',), 'PidsLimit', 0),
            (('HostConfig',), 'CapDrop', []),
            (('HostConfig',), 'SecurityOpt', []),
            (('HostConfig',), 'Binds', ['/var/run/docker.sock:/var/run/docker.sock']),
        ):
            with self.subTest(location=location, field=field):
                sample = copy.deepcopy(self.sandbox())
                target = sample
                for segment in location:
                    target = target[segment]
                target[field] = value
                result, effects = self.execute(sample)
                self.assertEqual(result, 'distinct_job_actual_docker_sandbox_unverified')
                self.assertEqual(effects, {'run': 1, 'receipt': 0})

    def test_missing_inspect_and_unsupported_engine_fail_closed(self):
        for sample, engine, expected in (
            (None, 'docker', 'distinct_job_actual_docker_sandbox_unverified'),
            (self.sandbox(), 'podman', 'distinct_job_requires_reviewed_docker_engine'),
        ):
            result, effects = self.execute(sample, engine=engine)
            self.assertEqual(result, expected)
            self.assertEqual(effects, {'run': 1, 'receipt': 0})

    def test_controller_exact_head_and_shape_required(self):
        good = self.patch_source()
        ast.parse(good['content'].decode())
        self.assertEqual(good['proposed_sha256'], wiring.sha(good['content']))
        with self.assertRaisesRegex(RuntimeError, 'fleet_capture_exact_source_mismatch'):
            self.patch_source(expected='0' * 64)
        with self.assertRaisesRegex(RuntimeError, 'unrecognised_fleet_container_creation_shape'):
            self.patch_source(source=good['content'])
        with self.assertRaisesRegex(RuntimeError, 'unrecognised_fleet_container_creation_shape'):
            self.patch_source(source=self.WORKER.replace(
                b'core.execute(args,timeout=30)', b'core.execute(args,timeout=10)'))
        with self.assertRaisesRegex(RuntimeError, 'unrecognised_fleet_container_creation_shape'):
            self.patch_source(source=self.WORKER.replace(
                b'    core.execute(args,timeout=30)\n', b'    pass\n')
                + b'    core.execute(args,timeout=30)\n')
