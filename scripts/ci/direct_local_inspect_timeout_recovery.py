#!/usr/bin/env python3
"""Render one source-bound Docker-inspection recovery correction, never install.

A timed-out Docker container inspect is a read-only, uncertain observation,
not proof that a verified container or its workflow has failed. Only retry this
GET-style operation; non-timeout failures, ownership drift, and size limits
retain their existing fail-closed meaning.
"""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path

BASELINE_SHA256 = "f4c58b8b105792b60ab010464b433c10ebb222e559bff98243aa87aa0afbc1df"

OLD = """    obj=core.inspect_container(name,size=measure_size)
    if obj and obj['Config'].get('Labels',{}).get(LABEL)!=name:
"""
NEW = """    # Docker's metadata endpoint may stall during concurrent host workload.
    # Retry only this read-only probe. Never skip SizeRw when requested and
    # never retry a mutating container operation with an uncertain outcome.
    for _inspect_attempt in range(3):
        try:
            obj=core.inspect_container(name,size=measure_size)
            break
        except subprocess.TimeoutExpired:
            if _inspect_attempt==2:
                raise
            time.sleep(1<<_inspect_attempt)
    if obj and obj['Config'].get('Labels',{}).get(LABEL)!=name:
"""

def render(raw: bytes) -> bytes:
    if hashlib.sha256(raw).hexdigest()!=BASELINE_SHA256:
        raise ValueError("installed_controller_sha256_changed")
    original=raw.decode("utf-8")
    if original.count(OLD)!=1:
        raise ValueError("expected_inspection_call_changed")
    result=original.replace(OLD,NEW,1).encode()
    baseline_tree=ast.parse(raw)
    candidate_tree=ast.parse(result)
    functions=[n for n in candidate_tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="inspect"]
    if len(functions)!=1:
        raise ValueError("expected_inspect_function_missing")
    def no_inspect(tree):
        tree.body=[n for n in tree.body if not isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) or n.name!="inspect"]
        return ast.dump(tree,include_attributes=False)
    if no_inspect(baseline_tree)!=no_inspect(candidate_tree):
        raise ValueError("unrelated_runtime_ast_changed")
    return result

if __name__=="__main__":
    import argparse,json,os,sys
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if a.out.exists() or a.out.is_symlink():
        raise SystemExit("refuse_overwrite_existing_candidate")
    raw=render(a.baseline.read_bytes())
    a.out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with a.out.open("xb") as f:
        os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    print(json.dumps({"candidate_sha256":hashlib.sha256(raw).hexdigest(),
                      "source_sha256":BASELINE_SHA256,"installed":False,
                      "changed_runtime":["fleet_ci.py"],
                      "source_only":True},sort_keys=True))
