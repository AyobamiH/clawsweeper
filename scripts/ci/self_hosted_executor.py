#!/usr/bin/env python3
"""Bounded, exclusive ClawSweeper ephemeral GitHub Actions JIT executor.

One queued job per invocation. Defaults to inspect-only; mutations require an
owner-only 0600 controls file. No GH-hosted runner, personal host mounts, host
Docker socket or model inference is exposed to executable workflow code.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from self_hosted_policy import AdmissionHold, REPOSITORY, WORKFLOWS, category_enabled, classify

HOME = Path.home()
ROOT = HOME / ".local/share/local-ci/clawsweeper-selfhosted"
CONTROLS = ROOT / "controls.json"
LOCK = ROOT / "executor.lock"
RECEIPTS = ROOT / "receipts"
IMAGE = "sha256:c1f057b23404d71586056d3333e333099c3301e84cc2583c592907a8b56597d3"
SECURITY_IMAGE_NAME = "clawsweeper-codeql-runner:node24-codeql-2.27.4"
NETWORK_IMAGE = "sha256:f9e6f27cf17460dfb82250c5ac94f5a829956692c2e47615a870a4ec9312b802"
LABEL = "io.ayobamih.clawsweeper.selfhosted"
REPO_SLUG = "repos/" + REPOSITORY
MAX_SECONDS = 42 * 60


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or (path.stat().st_mode & 0o077):
        raise RuntimeError("unsafe_state_permissions")


def atomic(path, record):
    private_dir(path.parent)
    tmp = path.with_name(path.name + f".{os.getpid()}.new")
    content = json.dumps(record, sort_keys=True, indent=2).encode() + b"\n"
    with tmp.open("xb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run_cli(args, data=None, timeout=25):
    try:
        p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("command_timeout") from exc
    if p.returncode:
        raise RuntimeError("external_command_refused")
    return p.stdout


def gh(path, method="GET", body=None):
    args = ["gh", "api", "--method", method, path]
    data = None
    if body is not None:
        args += ["--input", "-"]
        data = json.dumps(body)
    tries = 2 if method == "GET" else 1
    for i in range(tries):
        try:
            payload = run_cli(args, data, timeout=30)
            return json.loads(payload) if payload.strip() else {}
        except (RuntimeError, ValueError):
            if i + 1 == tries:
                raise
            time.sleep(1)


def discover():
    """Only inspect bounded queued/in-progress run inventory, never arbitrary actions."""
    candidates = []
    workflow_paths = {path for path, _ in WORKFLOWS.values()}
    visited = set()
    for status in ("queued", "in_progress"):
        runs = gh(f"{REPO_SLUG}/actions/runs?status={status}&per_page=100").get("workflow_runs", [])
        for item in runs[:100]:
            if item.get("path") not in workflow_paths or item.get("id") in visited:
                continue
            run_id = item["id"]
            if not isinstance(run_id, int) or run_id <= 0:
                continue
            visited.add(run_id)
            if item.get("status") not in ("queued", "in_progress"):
                continue
            jobs = gh(f"{REPO_SLUG}/actions/runs/{run_id}/jobs?per_page=100").get("jobs", [])
            for job in jobs[:100]:
                try:
                    candidates.append(classify(item, job))
                except AdmissionHold:
                    continue
    return sorted(candidates, key=lambda c: (c.run_id, c.job_id))


def load_controls():
    if not CONTROLS.exists():
        return {}
    if CONTROLS.is_symlink() or CONTROLS.stat().st_mode & 0o077:
        raise RuntimeError("controls_not_owner_only")
    x = json.loads(CONTROLS.read_text())
    if not isinstance(x, dict):
        raise RuntimeError("invalid_controls")
    return x


def source_authorised(candidate, controls):
    if candidate.role != "ops":
        return True
    main = gh(f"{REPO_SLUG}/git/ref/heads/main")["object"]["sha"]
    if candidate.event == "pull_request_target" and candidate.trusted_base_sha != main:
        raise AdmissionHold("target_base_sha_changed")
    if main != controls.get("trusted_main_sha"):
        raise AdmissionHold("trusted_workflow_head_changed")
    # A source hash mismatch is an authority change, not a reason to auto-update
    # the owner's accepted baseline or execute the unreviewed revision.
    manifest = controls.get("trusted_workflow_sha256", {})
    expected = manifest.get(candidate.workflow) if isinstance(manifest, dict) else None
    if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise AdmissionHold("trusted_workflow_not_pinned")
    obj = gh(f"{REPO_SLUG}/contents/{candidate.workflow}?ref={main}")
    import base64
    digest = hashlib.sha256(base64.b64decode(obj["content"])).hexdigest()
    if digest != expected:
        raise AdmissionHold("trusted_workflow_drift")
    return True


def approved_job_image(candidate, controls):
    if candidate.role != "security":
        return IMAGE
    pinned = controls.get("security_image_sha256")
    if not isinstance(pinned, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", pinned):
        raise AdmissionHold("codeql_image_not_pinned")
    current = run_cli(["docker", "image", "inspect", SECURITY_IMAGE_NAME,
                       "--format", "{{.Id}}"], timeout=15).strip()
    if current != pinned:
        raise AdmissionHold("codeql_image_drift")
    return pinned


def capacity(candidate, controls):
    # In-flight local CI belongs to another controller; defer, never compete.
    fleet = subprocess.run(["systemctl", "--user", "is-active", "local-ci-fleet.service"],
                           capture_output=True, text=True, timeout=5)
    if fleet.stdout.strip() not in ("inactive", "failed"):
        raise AdmissionHold("shared_fleet_busy")
    available = next(int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")) // 1024
    required = 5500 if candidate.role == "security" else 3200
    if available < required:
        raise AdmissionHold("memory_reserve")
    if shutil.disk_usage(HOME).free < 20 * 1024**3:
        raise AdmissionHold("physical_disk_reserve")
    if run_cli(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=15).strip() == "":
        raise AdmissionHold("container_engine_unavailable")
    image_id = run_cli(["docker", "image", "inspect", "clawsweeper-selfhost-runner:node24-gh245", "--format", "{{.Id}}"], timeout=15).strip()
    if image_id != IMAGE:
        raise AdmissionHold("runner_image_drift")
    approved_job_image(candidate, controls)
    return True


def inspect_owned(name, owner):
    result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True, timeout=15)
    if result.returncode:
        if "no such" in result.stderr.lower():
            return None
        raise RuntimeError("container_inspection_unavailable")
    objs = json.loads(result.stdout)
    if len(objs) != 1 or objs[0].get("Config", {}).get("Labels", {}).get(LABEL) != owner:
        raise RuntimeError("container_ownership_mismatch")
    return objs[0]


def stop_owned(name, owner):
    # Docker --rm containers can still be visible to inspect just after their
    # process exits. A transient inspect failure is not a reason to claim
    # cleanup; give it bounded time and demand independently observed absence.
    stop_requested = False
    for attempt in range(5):
        try:
            obj = inspect_owned(name, owner)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            # An ownership mismatch is a security refusal, not transient API
            # unavailability. Never retry it or accidentally stop that name.
            if isinstance(exc, RuntimeError) and str(exc) != "container_inspection_unavailable":
                raise
            if attempt == 4:
                raise RuntimeError("owned_container_identity_unverified") from exc
            time.sleep(2)
            continue
        if obj is None:
            return
        if not stop_requested:
            run_cli(["docker", "stop", "--time", "8", name], timeout=25)
            stop_requested = True
        time.sleep(2)
    if inspect_owned(name, owner) is not None:
        raise RuntimeError("owned_container_cleanup_incomplete")


def runner_absent_verified(runner_id, name):
    # GitHub automatically deregisters ephemeral JIT runners. A DELETE may
    # return not-found *after success*, but the status is only benign if the
    # complete inventory independently proves the exact runner absent.
    result = gh(f"{REPO_SLUG}/actions/runners?per_page=100")
    runners = result.get("runners")
    total = result.get("total_count")
    if not isinstance(runners, list) or not isinstance(total, int) or total != len(runners):
        raise RuntimeError("runner_inventory_unbounded")
    if any(r.get("id") == runner_id or r.get("name") == name for r in runners):
        raise RuntimeError("runner_deregistration_unverified")
    return True


def prepare_network(name, owner):
    image = run_cli(["docker", "image", "inspect", "poststeward-ops-net:1", "--format", "{{.Id}}"], timeout=15).strip()
    if image != NETWORK_IMAGE:
        raise AdmissionHold("network_image_drift")
    firewall = "\n".join((
        "set -eu", "ip6tables -P OUTPUT DROP",
        "for cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4; do",
        'iptables -A OUTPUT -d "$cidr" -j REJECT', "done",
        "touch /tmp/network-ready", "sleep 2000",
    ))
    run_cli(["docker", "run", "--rm", "--detach", "--name", name, "--label", LABEL+"="+owner,
             "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges",
             "--pids-limit", "50", "--memory", "96m", "--cpus", "0.25", "--dns", "1.1.1.1",
             image, "sh", "-ec", firewall], timeout=30)
    for _ in range(12):
        result = subprocess.run(["docker", "exec", name, "test", "-f", "/tmp/network-ready"], capture_output=True, timeout=10)
        if result.returncode == 0:
            return image
        time.sleep(1)
    raise RuntimeError("network_firewall_not_ready")


def runner_job(candidate, controls):
    key = f"run-{candidate.run_id}-job-{candidate.job_id}-attempt-{candidate.run_attempt}"
    private_dir(RECEIPTS)
    target = RECEIPTS / key
    if target.exists():
        # Once a POST might have succeeded, never blindly repeat it. Operator
        # must reconcile old JIT and GitHub job state before any re-admission.
        raise AdmissionHold("existing_or_uncertain_runner_intent")
    private_dir(target)
    name = f"csw-ci-{candidate.run_id}-{candidate.job_id}-{candidate.run_attempt}"
    worker = name + "-worker"
    net = name + "-net"
    image_id = approved_job_image(candidate, controls)
    receipt = {
        "schema": "clawsweeper.selfhosted-jit.v1", "run_id": candidate.run_id,
        "job_id": candidate.job_id, "attempt": candidate.run_attempt,
        "head_sha": candidate.sha, "workflow": candidate.workflow, "event": candidate.event,
        "role": candidate.role, "label": candidate.label, "runner_name": name,
        "image_sha256": image_id, "state": "registration_uncertain", "created_at": now(),
    }
    atomic(target / "receipt.json", receipt)
    # POST is non-idempotent: no implicit retries on timeout or partial response.
    response = gh(f"{REPO_SLUG}/actions/runners/generate-jitconfig", "POST", {
        "name": name, "runner_group_id": 1,
        "labels": ["self-hosted", "Linux", "X64", candidate.label],
        "work_folder": "_work",
    })
    encoded = response.pop("encoded_jit_config", None)
    registered_id = response.get("runner", {}).get("id")
    if not isinstance(encoded, str) or not isinstance(registered_id, int):
        raise RuntimeError("jit_registration_response_incomplete")
    receipt.update(state="registered", runner_id=registered_id, registered_at=now())
    atomic(target / "receipt.json", receipt)
    process = None
    issues = []
    try:
        prepare_network(net, name)
        log_path = target / "runner.log"
        with log_path.open("xb") as logfile:
            os.fchmod(logfile.fileno(), 0o600)
            cmd = ["docker", "run", "--rm", "--interactive", "--init", "--name", worker,
                   "--label", LABEL+"="+name, "--network", "container:"+net,
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "500",
                   "--memory", "4g" if candidate.role == "security" else "2g", "--cpus", "2", image_id,
                   "bash", "-ec", 'IFS= read -r config; exec ./run.sh --jitconfig "$config"']
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=logfile, stderr=subprocess.STDOUT, text=True)
            process.stdin.write(encoded + "\n")
            process.stdin.close()
            receipt.update(state="runner_started", runner_started_at=now())
            atomic(target / "receipt.json", receipt)
            try:
                process.wait(timeout=MAX_SECONDS)
            except subprocess.TimeoutExpired:
                issues.append("runner_time_limit")
            receipt["runner_exit"] = process.poll()
        receipt["log_sha256"] = hashlib.sha256(log_path.read_bytes()).hexdigest()
        receipt["log_bytes"] = log_path.stat().st_size
        result = {}
        for _ in range(6):
            result = gh(f"{REPO_SLUG}/actions/jobs/{candidate.job_id}")
            if result.get("status") == "completed":
                break
            time.sleep(5)
        receipt["github_job"] = {k: result.get(k) for k in ("id", "run_id", "status", "conclusion", "runner_name", "started_at", "completed_at")}
        if not (result.get("id") == candidate.job_id and result.get("run_id") == candidate.run_id
                and result.get("runner_name") == name and result.get("status") == "completed"):
            issues.append("job_identity_or_terminal_state_unverified")
        if result.get("conclusion") != "success":
            issues.append("github_job_not_successful")
        if process.poll() != 0:
            issues.append("runner_exit_not_zero")
    except Exception as exc:
        issues.append(type(exc).__name__)
    finally:
        # A known runner identity is necessary to deregister; only owned Docker
        # labels may be touched. Cleanup errors always prevent a passing receipt.
        for child in (worker, net):
            try:
                stop_owned(child, name)
            except Exception:
                issues.append("owned_cleanup_unverified")
        if process is not None:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                issues.append("worker_process_reaping_unverified")
        try:
            # A completed one-job JIT runner may already be automatically
            # removed by GitHub. Never equate a failed DELETE with a leak;
            # require independent readback of the complete runner inventory.
            try:
                gh(f"{REPO_SLUG}/actions/runners/{registered_id}", "DELETE")
            except Exception:
                pass
            runner_absent_verified(registered_id, name)
        except Exception:
            issues.append("runner_deregistration_unverified")
        receipt["issues"] = issues
        receipt["state"] = "passed" if not issues else "held"
        receipt["finished_at"] = now()
        atomic(target / "receipt.json", receipt)
    return {"run_id": candidate.run_id, "job_id": candidate.job_id,
            "state": receipt["state"], "issues": issues, "receipt": str(target / "receipt.json")}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inspect", "cycle"))
    args = parser.parse_args()
    private_dir(ROOT)
    if args.mode == "inspect":
        controls = load_controls()
        found = discover()
        output = []
        for c in found:
            try:
                category_enabled(c, controls)
                source_authorised(c, controls)
                decision = "eligible"
            except AdmissionHold as exc:
                decision = str(exc)
            output.append({"run_id": c.run_id, "job_id": c.job_id,
                           "role": c.role, "sha": c.sha, "decision": decision})
        print(json.dumps({"at": now(), "candidates": output[:50]}))
        return
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({"held": "existing_executor_owns_lock"}))
            return
        controls = load_controls()
        if controls.get("enabled") is not True:
            print(json.dumps({"held": "controller_disabled"}))
            return
        for c in discover():
            try:
                category_enabled(c, controls)
                source_authorised(c, controls)
                capacity(c, controls)
                result = runner_job(c, controls)
                print(json.dumps(result))
                return
            except AdmissionHold as exc:
                print(json.dumps({"run_id": c.run_id, "job_id": c.job_id, "held": str(exc)}))
                continue
        print(json.dumps({"at": now(), "status": "no_admitted_work"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "failure", "reason": type(exc).__name__}), file=sys.stderr)
        sys.exit(1)
