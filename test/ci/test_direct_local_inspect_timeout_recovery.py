"""Exact installed-controller, disposable Docker transport-timeout regression."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import types
import unittest
from unittest.mock import Mock

SCRIPT=Path(__file__).resolve().parents[2]/"scripts/ci/direct_local_inspect_timeout_recovery.py"
spec=importlib.util.spec_from_file_location("inspect_timeout_renderer",SCRIPT)
renderer=importlib.util.module_from_spec(spec);spec.loader.exec_module(renderer)
BASELINE=Path("/home/johnh/.local/share/local-ci/fleet_ci.py")
NAME="local-fleet-bf40e3b5fe1b"
LABEL="io.ayobamih.local-ci.fleet"

def isolated_function(raw):
    tree=ast.parse(raw)
    selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="inspect"]
    if len(selected)!=1: raise ValueError("missing_exact_runtime_function")
    module=ast.Module(body=selected,type_ignores=[])
    namespace={"NAME":re.compile(r"local-fleet-[0-9a-f]{12}\Z"),
               "LABEL":LABEL,"subprocess":subprocess}
    exec(compile(module,"<actual-rendered-fleet-inspect>","exec"),namespace)
    return namespace

class InspectTimeoutRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=BASELINE.read_bytes()
        cls.candidate=renderer.render(cls.original)
        cls.code=isolated_function(cls.candidate)

    def probe(self, outcomes, measure_size=False):
        probe=Mock(side_effect=outcomes)
        sleep=Mock()
        scope=dict(self.code)
        scope["core"]=types.SimpleNamespace(inspect_container=probe)
        scope["time"]=types.SimpleNamespace(sleep=sleep)
        exec(compile(ast.Module(body=[n for n in ast.parse(self.candidate).body
            if isinstance(n,ast.FunctionDef) and n.name=="inspect"],type_ignores=[]),
            "<isolated-rendered-probe>","exec"),scope)
        return scope["inspect"],probe,sleep

    @staticmethod
    def valid(size=None):
        record={"Config":{"Labels":{LABEL:NAME}}}
        if size is not None:record["SizeRw"]=size
        return record

    def test_exact_source_and_whole_ast_other_than_inspect_remains_unchanged(self):
        self.assertEqual(hashlib.sha256(self.original).hexdigest(),renderer.BASELINE_SHA256)
        self.assertNotEqual(hashlib.sha256(self.candidate).digest(),hashlib.sha256(self.original).digest())
        self.assertIn(b"SizeRw",self.candidate)

    def test_normal_probe_exactly_once(self):
        inspect,probe,sleep=self.probe([self.valid()])
        self.assertEqual(inspect(NAME),self.valid())
        probe.assert_called_once_with(NAME,size=False)
        sleep.assert_not_called()

    def test_one_transient_timeout_recovers_without_restart(self):
        err=subprocess.TimeoutExpired(["docker","container","inspect",NAME],30)
        inspect,probe,sleep=self.probe([err,self.valid()])
        self.assertEqual(inspect(NAME),self.valid())
        self.assertEqual(probe.call_count,2)
        sleep.assert_called_once_with(1)

    def test_two_transient_timeouts_recover_and_size_is_never_skipped(self):
        err=subprocess.TimeoutExpired(["docker","container","inspect","--size",NAME],30)
        inspect,probe,sleep=self.probe([err,err,self.valid(4096)])
        self.assertEqual(inspect(NAME,measure_size=True)["SizeRw"],4096)
        self.assertEqual(probe.call_count,3)
        self.assertTrue(all(c.kwargs["size"] is True for c in probe.call_args_list))
        self.assertEqual([x.args[0] for x in sleep.call_args_list],[1,2])

    def test_third_timeout_fails_closed(self):
        err=subprocess.TimeoutExpired(["docker","container","inspect",NAME],30)
        inspect,probe,sleep=self.probe([err,err,err])
        with self.assertRaises(subprocess.TimeoutExpired):inspect(NAME)
        self.assertEqual(probe.call_count,3)

    def test_non_timeout_transport_error_never_retry(self):
        inspect,probe,sleep=self.probe([RuntimeError("daemon_unavailable")])
        with self.assertRaisesRegex(RuntimeError,"daemon_unavailable"):inspect(NAME)
        self.assertEqual(probe.call_count,1)
        sleep.assert_not_called()

    def test_missing_container_is_not_assumed_success(self):
        inspect,probe,sleep=self.probe([None])
        self.assertIsNone(inspect(NAME))
        probe.assert_called_once_with(NAME,size=False)

    def test_bad_label_still_rejected_after_a_timeout(self):
        err=subprocess.TimeoutExpired(["docker","container","inspect",NAME],30)
        inspect,probe,sleep=self.probe([err,{"Config":{"Labels":{LABEL:"wrong"}}}])
        with self.assertRaisesRegex(RuntimeError,"Container ownership mismatch"):inspect(NAME)
        self.assertEqual(probe.call_count,2)

    def test_invalid_container_name_rejected_before_io(self):
        inspect,probe,sleep=self.probe([])
        with self.assertRaisesRegex(RuntimeError,"Unsafe container name"):inspect("unowned")
        probe.assert_not_called()

    def test_bad_baseline_is_not_patchable(self):
        with self.assertRaisesRegex(ValueError,"installed_controller_sha256_changed"):
            renderer.render(self.original+b"extra")

    def exercise_real_bounded_command(self, size_bytes):
        class Process:
            returncode=None
            polls=0
            terminated=False
            def poll(self):
                self.polls+=1
                if self.polls>=2:self.returncode=0
                return self.returncode
            def terminate(self):
                self.terminated=True;self.returncode=-15
            def wait(self,**kwargs): return self.returncode
            def kill(self): self.terminated=True;self.returncode=-9
        process=Process()
        timeouts=[subprocess.TimeoutExpired(["docker","container","inspect","--size",NAME],30),
                  self.valid(size_bytes)]
        core=types.SimpleNamespace(
            inspect_container=Mock(side_effect=timeouts),
            MIB=1024**2,GIB=1024**3,disk_policy=lambda:(2*1024**3,4*1024**3),
            shutil=types.SimpleNamespace(disk_usage=lambda path:types.SimpleNamespace(free=10*1024**3)))
        clock=iter((0,31,62,63,64,100))
        fake_time=types.SimpleNamespace(monotonic=lambda:next(clock),sleep=Mock())
        fake_processes=types.SimpleNamespace(
            Popen=Mock(return_value=process),DEVNULL=subprocess.DEVNULL,
            STDOUT=subprocess.STDOUT,TimeoutExpired=subprocess.TimeoutExpired)
        scope={"NAME":re.compile(r"local-fleet-[0-9a-f]{12}\Z"),"LABEL":LABEL,
            "core":core,"ENGINE":"docker","time":fake_time,
            "os":types.SimpleNamespace(sched_getaffinity=lambda _: {0}),
            "subprocess":fake_processes}
        source=ast.parse(self.candidate)
        selected=[n for n in source.body if isinstance(n,ast.FunctionDef)
                  and n.name in ("inspect","bounded_command")]
        exec(compile(ast.Module(body=selected,type_ignores=[]),
            "<rendered-execution-watchdog>","exec"),scope)
        with __import__("tempfile").TemporaryDirectory() as temp:
            scope["ROOT"]=Path(temp)
            log=Path(temp)/"ci.log"
            try:
                result=scope["bounded_command"](NAME,"true",log,900,
                    {"_cpu_affinity":(0,),"cpus":1,"writable_mib":4096})
            except Exception as exc:
                result=exc
        return result,process,core.inspect_container,fake_time.sleep

    def test_actual_running_command_survives_transient_size_timeout(self):
        result,process,probe,sleep=self.exercise_real_bounded_command(1024)
        self.assertEqual(result,0)
        self.assertFalse(process.terminated)
        self.assertEqual(probe.call_count,2)
        self.assertTrue(all(c.kwargs["size"] is True for c in probe.call_args_list))

    def test_actual_running_command_still_rejects_over_budget_size(self):
        result,process,probe,sleep=self.exercise_real_bounded_command(4096*1024**2+1)
        self.assertIsInstance(result,RuntimeError)
        self.assertIn("Disposable writable-layer budget reached",str(result))
        self.assertEqual(probe.call_count,2)

    def test_no_docker_exec_run_or_lifecycle_effect_in_patch(self):
        before=ast.parse(self.original);after=ast.parse(self.candidate)
        def funcnames(tree):
            return [n.name for n in tree.body if isinstance(n,ast.FunctionDef)]
        self.assertEqual(funcnames(before),funcnames(after))
        original=ast.get_source_segment(self.original.decode(),next(n for n in before.body if isinstance(n,ast.FunctionDef) and n.name=="inspect"))
        changed=ast.get_source_segment(self.candidate.decode(),next(n for n in after.body if isinstance(n,ast.FunctionDef) and n.name=="inspect"))
        self.assertEqual(changed.count("core.inspect_container"),original.count("core.inspect_container"))
        self.assertNotIn("run_job(",changed)
        self.assertNotIn("docker run",changed)

if __name__=="__main__":unittest.main()
