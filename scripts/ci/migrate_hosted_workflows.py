#!/usr/bin/env python3
"""Stage explicit GitHub-hosted runner migration with source parity checks."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from estate_policy import job_class

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "engineering" / "hosted-runner-baseline.json"


def plan(source_manifest=BASELINE):
    data = json.loads(Path(source_manifest).read_text())
    if data.get("schema") != "clawsweeper.workflow-estate.v1":
        raise ValueError("unknown_workflow_inventory")
    changes = defaultdict(list)
    for j in data["jobs"]:
        if j["kind"] == "github_hosted":
            if not isinstance(j.get("runs_on"), str) or not re.fullmatch(
                    r"(?:ubuntu|windows|macos)-(?:latest|[0-9][0-9.]*)", j["runs_on"]):
                raise ValueError("unsupported_hosted_runner:" + j["workflow"] + "#" + j["id"])
            changes[j["workflow"]].append(j)
    if sum(map(len, changes.values())) != data["summary"]["github_hosted"]:
        raise ValueError("incomplete_hosted_job_inventory")
    return changes, data


def convert_file(path, jobs, original_digest):
    old = path.read_text()
    if hashlib.sha256(old.encode()).hexdigest() != original_digest:
        raise ValueError("stale_or_modified_source:" + path.name)
    lines = old.splitlines(keepends=True)
    rewritten = []
    for entry in jobs:
        head = re.compile(r"^  " + re.escape(entry["id"]) + r":(?:\s*#.*)?\s*$")
        heads = [i for i, text in enumerate(lines) if head.match(text.rstrip("\r\n"))]
        if len(heads) != 1:
            raise ValueError("job_header_not_unique:" + path.name + "#" + entry["id"])
        start = heads[0] + 1
        end = next((i for i in range(start, len(lines))
                    if re.match(r"^  [a-zA-Z0-9_-]+:", lines[i])), len(lines))
        selectors = [i for i in range(start, end) if re.match(r"^    runs-on:\s+", lines[i])]
        if len(selectors) != 1:
            raise ValueError("runner_selection_not_unique:" + path.name + "#" + entry["id"])
        idx = selectors[0]
        current = lines[idx].strip().removeprefix("runs-on:").strip()
        if current != entry["runs_on"]:
            raise ValueError("runtime_selector_changed:" + path.name + "#" + entry["id"])
        klass = job_class(entry)
        platform = "Windows" if entry["runs_on"].startswith("windows") else \
                   "macOS" if entry["runs_on"].startswith("macos") else "Linux"
        # A native Windows job must never be routed to a Linux/WSL worker.
        expression = chr(36) + "{{ github.run_id }}"
        label = f"clawsweeper-ci-{klass}-{expression}-{entry['id']}"
        rewritten.append((entry["id"], klass, platform, label))
        lines[idx] = f'    runs-on: [self-hosted, {platform}, X64, "{label}"]\n'
    changed = "".join(lines)
    import yaml
    before = yaml.safe_load(old)
    after = yaml.safe_load(changed)
    for j in jobs:
        before["jobs"][j["id"]].pop("runs-on")
        after["jobs"][j["id"]].pop("runs-on")
    if before != after:
        raise ValueError("workflow_behaviour_drift:" + path.name)
    return changed, rewritten


def execute(apply=False):
    sources, inventory = plan()
    trusted = {s["path"]: s["sha256"] for s in inventory["sources"]}
    output = []
    pending = []
    for name, jobs in sorted(sources.items()):
        path = ROOT / name
        content, rewrites = convert_file(path, jobs, trusted[name])
        pending.append((path, content))
        output.extend({"workflow": name, "id": key, "class": klass,
                       "platform": platform, "label": label}
                      for key, klass, platform, label in rewrites)
    if len(output) != inventory["summary"]["github_hosted"]:
        raise ValueError("not_all_hosted_jobs_were_rewritten")
    if apply:
        for target, content in pending:
            target.write_text(content)
    return {"workflows_changed": len(sources), "jobs_moved": len(output),
            "jobs": output, "applied": bool(apply)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    p = parser.parse_args()
    print(json.dumps(execute(p.apply), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
