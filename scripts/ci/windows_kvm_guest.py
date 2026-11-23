#!/usr/bin/env python3
"""Read-only preflight and strictly offline disposable Windows VM preparation.

This is NOT a GitHub runner registration or a Windows guest JIT controller.
Do not accept a Windows CI job until an independently isolated guest, bounded
egress and full provider-backed one-shot runner lifecycle are proven.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

SCHEMA = "clawsweeper.windows-kvm-guest.v1"
REPO = "AyobamiH/clawsweeper"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_LABEL = re.compile(r"^csw-win-[1-9][0-9]{0,14}-[1-9][0-9]{0,14}$")
ALLOWED_KEYS = frozenset(("schema", "enabled", "repository", "license",
                         "qemu_binary", "qemu_sha256", "qemu_img_binary",
                         "qemu_img_sha256", "image_path", "image_sha256",
                         "firmware_code", "firmware_sha256",
                         "firmware_vars", "firmware_vars_sha256",
                         "egress", "guest_attestation"))
DEFAULT_ROOT = Path.home() / ".local/share/local-ci/windows-guests"
DEFAULT_CONTROLS = DEFAULT_ROOT / "controls.json"


class Held(Exception):
    """Refuse before touching a VM, runner or GitHub registration."""


@dataclass(frozen=True)
class ImageInputs:
    qemu: Path
    qemu_img: Path
    image: Path
    code: Path
    vars: Path
    image_sha: str
    code_sha: str
    vars_sha: str


def _private_regular(path: Path, *, uid: int, allow_root: bool = False) -> None:
    try:
        meta = path.lstat()
    except OSError as exc:
        raise Held("missing_pinned_file") from exc
    if (not stat.S_ISREG(meta.st_mode)
            or meta.st_mode & (0o022 if allow_root else 0o077)):
        raise Held("unsafe_pinned_file_type_or_mode")
    if meta.st_uid not in ((0, uid) if allow_root else (uid,)):
        raise Held("pinned_file_owner_mismatch")


def _trusted_executable(path: str, expected: str, *, uid: int) -> Path:
    if not isinstance(path, str):
        raise Held("hypervisor_not_in_trusted_usr_bin")
    p = Path(path)
    if p.parent != Path("/usr/bin") or ".." in p.parts or p.is_symlink():
        raise Held("hypervisor_not_in_trusted_usr_bin")
    _private_regular(p, uid=uid, allow_root=True)
    if p.stat().st_mode & stat.S_IXUSR == 0 or not os.access(p, os.X_OK):
        raise Held("hypervisor_not_executable")
    _match_hash(p, expected, "hypervisor_binary_digest_mismatch")
    return p


def _match_hash(path: Path, expected: str, error: str) -> None:
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise Held("invalid_sha256_pin")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise Held("pinned_file_unreadable") from exc
    if digest.hexdigest() != expected:
        raise Held(error)


def _verify_self_contained_image(qemu_img: Path, image: Path) -> None:
    """A pinned qcow2 header must not refer to mutable external storage.

    Hashing the apparent qcow2 file alone does not identify its backing disk.
    Reject any external data file, backing chain or unreadable format metadata.
    """
    try:
        probe = subprocess.run(
            [str(qemu_img), "info", "--output=json", str(image)],
            capture_output=True, text=True, check=True, timeout=35,
        )
        report = json.loads(probe.stdout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError,
            ValueError) as exc:
        raise Held("windows_base_image_structure_unverifiable") from exc
    if not isinstance(report, dict) or report.get("format") != "qcow2":
        raise Held("windows_base_image_not_qcow2")
    if any(report.get(k) for k in (
            "backing-filename", "full-backing-filename",
            "backing-filename-format", "data-file", "external-data-file")):
        raise Held("windows_base_image_has_unpinned_dependencies")
    format_specific = report.get("format-specific", {})
    if format_specific is None:
        format_specific = {}
    if not isinstance(format_specific, dict):
        raise Held("windows_base_image_structure_unverifiable")
    flags = format_specific.get("data", {})
    if flags is None:
        flags = {}
    if not isinstance(flags, dict):
        raise Held("windows_base_image_structure_unverifiable")
    if any(flags.get(k) for k in (
            "data-file", "external-data-file", "backing-file", "backing-filename")):
        raise Held("windows_base_image_has_unpinned_dependencies")
    if report.get("encrypted") is True:
        raise Held("encrypted_guest_image_key_unreviewed")


def _private_dir(path: Path, *, uid: int) -> None:
    try:
        meta = path.lstat()
    except OSError as exc:
        raise Held("private_directory_missing") from exc
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != uid
            or meta.st_mode & 0o077):
        raise Held("private_directory_not_owned_or_private")


def _in_root(root: Path, path: Any, *, uid: int) -> Path:
    if not isinstance(path, str):
        raise Held("pinned_path_missing")
    p = Path(path)
    if (not p.is_absolute() or p == root or p.is_symlink()
            or ".." in p.parts or any(ch in path for ch in (",", "\n", "\r"))):
        raise Held("pinned_path_not_owner_root")
    # Resolve parents, but never trust a symlink at any owner-controlled layer.
    try:
        p.relative_to(root)
    except ValueError as exc:
        raise Held("pinned_path_outside_owner_root") from exc
    cursor = p.parent
    while cursor != root:
        if cursor.is_symlink():
            raise Held("pinned_path_parent_symlink")
        cursor = cursor.parent
    if p.is_symlink():
        raise Held("pinned_file_symlink")
    _private_regular(p, uid=uid)
    return p


def _read_controls(path: Path, root: Path) -> dict:
    uid = os.getuid()
    _private_dir(root, uid=uid)
    if path != root / "controls.json":
        raise Held("controls_outside_private_owner_root")
    _private_regular(path, uid=uid)
    if path.stat().st_mode & 0o077:
        raise Held("controls_not_0600")
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise Held("controls_unreadable") from exc
    if not isinstance(record, dict) or set(record) != ALLOWED_KEYS:
        raise Held("controls_schema_or_keys_mismatch")
    if record["schema"] != SCHEMA or record["repository"] != REPO:
        raise Held("controls_repository_identity_mismatch")
    return record


def _kvm() -> None:
    p = Path("/dev/kvm")
    try:
        s = p.lstat()
    except OSError as exc:
        raise Held("kvm_device_absent") from exc
    if not stat.S_ISCHR(s.st_mode) or not os.access(p, os.R_OK | os.W_OK):
        raise Held("kvm_device_not_usable_by_owner")


def validate(root: Path) -> ImageInputs:
    """Complete immutable-input readback BEFORE any mutable VM state."""
    c = _read_controls(root / "controls.json", root)
    if c["enabled"] is not True:
        raise Held("windows_guest_control_disabled")
    if c["license"] != "owner_attested_guest_license":
        raise Held("licensed_windows_guest_not_confirmed")
    if c["egress"] != "offline_only":
        raise Held("unverified_guest_egress_policy")
    if c["guest_attestation"] != "not_yet_proven":
        raise Held("unexpected_guest_attestation_field")
    _kvm()
    uid = os.getuid()
    image_root = root / "images"
    _private_dir(image_root, uid=uid)
    qemu = _trusted_executable(c["qemu_binary"], c["qemu_sha256"], uid=uid)
    qemu_img = _trusted_executable(c["qemu_img_binary"], c["qemu_img_sha256"], uid=uid)
    image = _in_root(image_root, c["image_path"], uid=uid)
    code = _in_root(image_root, c["firmware_code"], uid=uid)
    vars_file = _in_root(image_root, c["firmware_vars"], uid=uid)
    _match_hash(image, c["image_sha256"], "windows_base_image_changed")
    _verify_self_contained_image(qemu_img, image)
    _match_hash(code, c["firmware_sha256"], "windows_uefi_code_changed")
    _match_hash(vars_file, c["firmware_vars_sha256"], "windows_uefi_vars_changed")
    return ImageInputs(qemu, qemu_img, image, code, vars_file,
                       c["image_sha256"], c["firmware_sha256"],
                       c["firmware_vars_sha256"])


def render_vm_command(inputs: ImageInputs, run_dir: Path, name: str) -> list[str]:
    """No host filesystem mappings, Docker socket or guest internet route."""
    if not RUN_LABEL.fullmatch(name):
        raise Held("invalid_run_bound_vm_name")
    if run_dir.is_symlink() or not run_dir.is_absolute():
        raise Held("untrusted_run_directory")
    # Note: -nic none prevents GitHub access. This is only an offline boot
    # proving substrate; GH registration is deliberately NOT implemented.
    return [
        str(inputs.qemu), "-no-user-config", "-nodefaults",
        "-machine", "q35,accel=kvm", "-cpu", "host",
        "-smp", "2", "-m", "6144", "-display", "none",
        "-monitor", "none", "-serial", "none", "-parallel", "none",
        "-no-reboot", "-nic", "none",
        "-name", name,
        "-drive", "if=pflash,format=raw,readonly=on,file=" + str(inputs.code),
        "-drive", "if=pflash,format=raw,file=" + str(run_dir / "uefi-vars.bin"),
        "-drive", "if=none,id=osdisk,format=qcow2,cache=none,file=" + str(run_dir / "ephemeral.qcow2"),
        "-device", "virtio-blk-pci,drive=osdisk",
        "-qmp", "unix:" + str(run_dir / "qmp.sock") + ",server=on,wait=off",
    ]


def inspect(root: Path) -> dict:
    result = {
        "schema": "clawsweeper.windows-kvm-inspection.v1",
        "repository": REPO,
        "guest_isolated": False,
        "github_runner_registered": False,
        "production_admitted": False,
        "network": "disabled",
    }
    try:
        inputs = validate(root)
    except Held as exc:
        result.update(decision="HOLD", reason=str(exc))
    else:
        result.update(decision="READY_FOR_OFFLINE_BOOT_ONLY",
                      reason="ephemeral_guest_and_egress_not_attested",
                      base_image_sha256=inputs.image_sha)
    return result


def _atomic_json(path: Path, value: dict) -> None:
    body = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare_offline(root: Path, *, run_id: int, job_id: int) -> dict:
    """Create an immutable-source overlay. Never start a runner or a VM here.

    A preflight-proven image may be prepared for a separate guarded boot proof.
    Existing intent, including crash residue, always requires reconciliation;
    no cleanup or retry is automatic.
    """
    if type(run_id) is not int or type(job_id) is not int or not (0 < run_id < 10**15 and 0 < job_id < 10**15):
        raise Held("invalid_run_or_job_id")
    name = f"csw-win-{run_id}-{job_id}"
    inputs = validate(root)
    jobs = root / "jobs"
    _private_dir(jobs, uid=os.getuid())
    target = jobs / name
    if target.exists() or target.is_symlink():
        raise Held("existing_or_uncertain_guest_intent")
    target.mkdir(mode=0o700)
    # The directory name itself must survive power loss before any external
    # qemu-img effect; fsyncing only intent.json and its own directory does
    # not durably persist the parent directory entry for target.
    jobs_fd = os.open(jobs, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(jobs_fd)
    finally:
        os.close(jobs_fd)
    record = {
        "schema": "clawsweeper.windows-kvm-intent.v1",
        "state": "preparing_offline_overlay",
        "vm_name": name,
        "run_id": run_id,
        "job_id": job_id,
        "base_image_sha256": inputs.image_sha,
        "guest_isolated": False,
        "github_registration_attempted": False,
    }
    _atomic_json(target / "intent.json", record)
    # Direct subprocess argv; no shell and no operator-supplied format strings.
    # Durable intent exists before first irreversible image operation.
    overlay = target / "ephemeral.qcow2"
    subprocess.run([
        str(inputs.qemu_img), "create", "-f", "qcow2", "-F", "qcow2",
        "-b", str(inputs.image), str(overlay),
    ], check=True, capture_output=True, timeout=90, umask=0o077)
    _private_regular(overlay, uid=os.getuid())
    if overlay.lstat().st_nlink != 1:
        raise Held("guest_overlay_hardlink_not_private")
    overlay.chmod(0o600)
    if overlay.lstat().st_mode & 0o077:
        raise Held("guest_overlay_permissions_unsafe")
    with inputs.vars.open("rb") as source, (target / "uefi-vars.bin").open("xb") as dest:
        os.fchmod(dest.fileno(), 0o600)
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            dest.write(chunk)
        dest.flush()
        os.fsync(dest.fileno())
    _atomic_json(target / "offline-plan.json", {
        **record,
        "state": "offline_overlay_prepared",
        "qemu_argv": render_vm_command(inputs, target, name),
        "runner_registration_possible": False,
        "guest_network_enabled": False,
    })
    return {"decision": "OFFLINE_GUEST_OVERLAY_PREPARED_NOT_JIT_ACCEPTED",
            "intent": str(target / "intent.json"),
            "vm_name": name,
            "github_runner_registered": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["inspect", "prepare-offline"])
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--job-id", type=int)
    args = parser.parse_args()
    try:
        if args.operation == "inspect":
            output = inspect(args.root)
            code = 0
        else:
            output = prepare_offline(args.root, run_id=args.run_id, job_id=args.job_id)
            code = 0
    except (Held, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = {"schema": "clawsweeper.windows-kvm-result.v1",
                  "decision": "HOLD",
                  "reason": str(exc) if isinstance(exc, Held) else type(exc).__name__,
                  "github_runner_registered": False}
        code = 75
    print(json.dumps(output, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
