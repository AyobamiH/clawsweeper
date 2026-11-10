"""Exact policy, isolation and crash-recovery tests for the Windows VM substrate."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

# test/ci owns the canonical Python CI suite path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "ci"))
import windows_kvm_guest as vm


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class WindowsKvmGuestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="clawsweeper-windows-kvm-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "private"
        self.root.mkdir(mode=0o700)
        self.images = self.root / "images"
        self.images.mkdir(mode=0o700)
        self.jobs = self.root / "jobs"
        self.jobs.mkdir(mode=0o700)
        self.image = self.images / "windows-qcow2"
        self.code = self.images / "uefi-code"
        self.vars = self.images / "uefi-vars"
        for file, data in ((self.image, b"FICTIONAL-IMAGE"),
                           (self.code, b"FICTIONAL-UEFI-CODE"),
                           (self.vars, b"FICTIONAL-UEFI-VARS")):
            file.write_bytes(data)
            file.chmod(0o600)
        self.fake_qemu = self.root / "fake-qemu"
        self.fake_img = self.root / "fake-qemu-img"
        self.fake_qemu.write_text("#!/bin/sh\nexit 0\n")
        self.fake_img.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,pathlib,sys\n"
            "if len(sys.argv)>1 and sys.argv[1]=='info':\n"
            " r={'format':'qcow2','virtual-size':4096}\n"
            " if os.getenv('CSW_TEST_BACKING')=='1':r['backing-filename']='/tmp/outside.img'\n"
            " if os.getenv('CSW_TEST_EXTERNAL')=='1':r['format-specific']={'data':{'data-file':'/tmp/outside.bin'}}\n"
            " if os.getenv('CSW_TEST_WRONG_FORMAT')=='1':r['format']='raw'\n"
            " print(json.dumps(r))\n"
            "else:\n"
            " pathlib.Path(sys.argv[-1]).write_bytes(b'FIXTURE-QCOW2-OVERLAY')\n"
        )
        self.fake_qemu.chmod(0o700)
        self.fake_img.chmod(0o700)
        self.controls = self.root / "controls.json"
        self.record = {
            "schema": vm.SCHEMA,
            "enabled": True,
            "repository": vm.REPO,
            "license": "owner_attested_guest_license",
            "qemu_binary": "/usr/bin/qemu-system-x86_64",
            "qemu_sha256": sha(self.fake_qemu),
            "qemu_img_binary": "/usr/bin/qemu-img",
            "qemu_img_sha256": sha(self.fake_img),
            "image_path": str(self.image),
            "image_sha256": sha(self.image),
            "firmware_code": str(self.code),
            "firmware_sha256": sha(self.code),
            "firmware_vars": str(self.vars),
            "firmware_vars_sha256": sha(self.vars),
            "egress": "offline_only",
            "guest_attestation": "not_yet_proven",
        }
        self.save()

    def save(self):
        self.controls.write_text(json.dumps(self.record))
        self.controls.chmod(0o600)

    @contextmanager
    def fixture_hypervisor(self):
        def substitute(path, expected, *, uid):
            if path.endswith("qemu-system-x86_64"):
                assert expected == sha(self.fake_qemu)
                return self.fake_qemu
            if path.endswith("qemu-img"):
                assert expected == sha(self.fake_img)
                return self.fake_img
            raise AssertionError("unapproved fake binary")
        with patch.object(vm, "_kvm"), patch.object(vm, "_trusted_executable", side_effect=substitute):
            yield

    def test_cannot_read_missing_controls_and_never_creates_state(self):
        self.controls.unlink()
        with self.assertRaisesRegex(vm.Held, "missing_pinned_file"):
            vm.validate(self.root)
        response = vm.inspect(self.root)
        self.assertEqual(response["decision"], "HOLD")
        self.assertFalse(response["github_runner_registered"])
        self.assertEqual(list(self.jobs.iterdir()), [])

    def test_default_host_inspection_is_read_only_even_when_missing_image(self):
        self.controls.unlink()
        p = subprocess.run(
            [sys.executable, str(Path(vm.__file__)), "inspect", "--root", str(self.root)],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual(r["decision"], "HOLD")
        self.assertFalse(r["production_admitted"])
        self.assertFalse(r["guest_isolated"])
        self.assertEqual(list(self.jobs.iterdir()), [])

    def test_disabled_controls_hold_before_vm_start(self):
        self.record["enabled"] = False
        self.save()
        self.assertEqual(vm.inspect(self.root)["reason"], "windows_guest_control_disabled")

    def test_rejects_unapproved_windows_guest_licence(self):
        self.record["license"] = "not_provided"
        self.save()
        self.assertEqual(vm.inspect(self.root)["reason"], "licensed_windows_guest_not_confirmed")

    def test_rejects_any_network_mode_other_than_offline(self):
        self.record["egress"] = "public_internet"
        self.save()
        self.assertEqual(vm.inspect(self.root)["reason"], "unverified_guest_egress_policy")

    def test_cannot_forge_guest_attestation_in_controls(self):
        self.record["guest_attestation"] = "trusted"
        self.save()
        self.assertEqual(vm.inspect(self.root)["reason"], "unexpected_guest_attestation_field")

    def test_rejects_unexpected_control_keys_and_repository_identity(self):
        self.record["my_custom_runner_token"] = "n"
        self.save()
        self.assertEqual(vm.inspect(self.root)["reason"], "controls_schema_or_keys_mismatch")
        del self.record["my_custom_runner_token"]
        self.record["repository"] = "other/repository"
        self.save()
        self.assertEqual(vm.inspect(self.root)["reason"], "controls_repository_identity_mismatch")

    def test_rejects_world_readable_control_file(self):
        self.controls.chmod(0o644)
        self.assertIn(vm.inspect(self.root)["reason"],
                      ("unsafe_pinned_file_type_or_mode", "controls_not_0600"))

    def test_rejects_symlinked_control_file(self):
        target = self.root / "other.json"
        target.write_bytes(self.controls.read_bytes())
        target.chmod(0o600)
        self.controls.unlink()
        self.controls.symlink_to(target)
        self.assertIn(vm.inspect(self.root)["reason"],
                      ("unsafe_pinned_file_type_or_mode", "missing_pinned_file"))

    def test_rejects_path_traversal_outside_images(self):
        self.record["image_path"] = str(self.images / ".." / ".." / "private" / "images" / "windows-qcow2")
        self.save()
        with self.fixture_hypervisor():
            self.assertEqual(vm.inspect(self.root)["reason"], "pinned_path_not_owner_root")

    def test_rejects_symlinked_image(self):
        original = self.image
        real = self.images / "original"
        original.rename(real)
        original.symlink_to(real)
        with self.fixture_hypervisor():
            self.assertEqual(vm.inspect(self.root)["reason"], "pinned_path_not_owner_root")

    def test_rejects_publicly_readable_image_or_firmware(self):
        self.image.chmod(0o644)
        with self.fixture_hypervisor():
            self.assertEqual(vm.inspect(self.root)["reason"], "unsafe_pinned_file_type_or_mode")

    def test_rejects_image_hash_drift(self):
        self.image.write_bytes(b"NEW_IMAGE")
        with self.fixture_hypervisor():
            self.assertEqual(vm.inspect(self.root)["reason"], "windows_base_image_changed")

    def test_rejects_mutable_backing_file_dependencies(self):
        with self.fixture_hypervisor(), patch.dict(os.environ, {"CSW_TEST_BACKING": "1"}):
            self.assertEqual(vm.inspect(self.root)["reason"], "windows_base_image_has_unpinned_dependencies")

    def test_rejects_external_data_file_dependency(self):
        with self.fixture_hypervisor(), patch.dict(os.environ, {"CSW_TEST_EXTERNAL": "1"}):
            self.assertEqual(vm.inspect(self.root)["reason"], "windows_base_image_has_unpinned_dependencies")

    def test_rejects_wrong_disk_format(self):
        with self.fixture_hypervisor(), patch.dict(os.environ, {"CSW_TEST_WRONG_FORMAT": "1"}):
            self.assertEqual(vm.inspect(self.root)["reason"], "windows_base_image_not_qcow2")

    def test_rejects_firmware_code_hash_drift(self):
        self.code.write_bytes(b"NEW_UEFI")
        with self.fixture_hypervisor():
            self.assertEqual(vm.inspect(self.root)["reason"], "windows_uefi_code_changed")

    def test_rejects_invalid_hash_pin_and_symlink_executable(self):
        self.record["qemu_sha256"] = "not-a-digest"
        self.save()
        with self.assertRaisesRegex(vm.Held, "invalid_sha256_pin"):
            vm._match_hash(self.fake_img, self.record["qemu_sha256"], "hypervisor_binary_digest_mismatch")
        with self.assertRaisesRegex(vm.Held, "hypervisor_not_in_trusted_usr_bin"):
            vm._trusted_executable("/usr/bin/../tmp/runner", "a" * 64, uid=os.getuid())

    def test_prepared_guest_is_offline_and_has_no_host_mounts(self):
        with self.fixture_hypervisor():
            inputs = vm.validate(self.root)
        run_dir = self.jobs / "csw-win-1200-900"
        args = vm.render_vm_command(inputs, run_dir, "csw-win-1200-900")
        self.assertNotIn("-usb", args)
        self.assertIn("-nic", args)
        self.assertEqual(args[args.index("-nic") + 1], "none")
        self.assertIn("q35,accel=kvm", args)
        self.assertIn("-no-user-config", args)
        self.assertIn("-nodefaults", args)
        self.assertIn("virtio-blk-pci,drive=osdisk", args)
        for unsafe in ("-netdev", "-virtfs", "-fsdev", "-device usb-host",
                       "-chardev", "-drive if=virtio,media=cdrom",
                       "docker.sock", "SSH_AUTH_SOCK", "GITHUB_TOKEN",
                       "jitconfig", "hostfwd", "guestfwd", "tap", "bridge"):
            self.assertNotIn(unsafe, " ".join(args))

    def test_bad_vm_name_and_symlinked_run_dir_refused(self):
        with self.fixture_hypervisor():
            inputs = vm.validate(self.root)
        with self.assertRaisesRegex(vm.Held, "invalid_run_bound_vm_name"):
            vm.render_vm_command(inputs, self.jobs / "x", "../name")
        target = self.jobs / "real"
        target.mkdir(mode=0o700)
        alias = self.jobs / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(vm.Held, "untrusted_run_directory"):
            vm.render_vm_command(inputs, alias, "csw-win-1-2")

    def test_offline_overlay_preparation_creates_single_pinned_intent(self):
        with self.fixture_hypervisor():
            result = vm.prepare_offline(self.root, run_id=1200, job_id=900)
        self.assertEqual(result["decision"], "OFFLINE_GUEST_OVERLAY_PREPARED_NOT_JIT_ACCEPTED")
        work = self.jobs / "csw-win-1200-900"
        self.assertEqual((work / "ephemeral.qcow2").read_bytes(), b"FIXTURE-QCOW2-OVERLAY")
        self.assertEqual((work / "uefi-vars.bin").read_bytes(), self.vars.read_bytes())
        intent = json.loads((work / "intent.json").read_text())
        plan = json.loads((work / "offline-plan.json").read_text())
        self.assertEqual(intent["state"], "preparing_offline_overlay")
        self.assertEqual(plan["state"], "offline_overlay_prepared")
        self.assertFalse(plan["runner_registration_possible"])
        self.assertFalse(plan["guest_network_enabled"])
        self.assertEqual(plan["qemu_argv"][plan["qemu_argv"].index("-nic") + 1], "none")
        for p in work.iterdir():
            self.assertEqual(p.stat().st_mode & 0o077, 0, p.name)

    def test_overlay_never_inherits_unsafe_caller_umask(self):
        previous = os.umask(0o022)
        try:
            with self.fixture_hypervisor():
                vm.prepare_offline(self.root, run_id=33, job_id=44)
        finally:
            os.umask(previous)
        overlay = self.jobs / "csw-win-33-44" / "ephemeral.qcow2"
        self.assertEqual(overlay.stat().st_mode & 0o077, 0)

    def test_duplicate_intent_never_retries_vm_preparation(self):
        with self.fixture_hypervisor():
            vm.prepare_offline(self.root, run_id=3, job_id=4)
            with self.assertRaisesRegex(vm.Held, "existing_or_uncertain_guest_intent"):
                vm.prepare_offline(self.root, run_id=3, job_id=4)

    def test_jobs_directory_entry_fsynced_before_external_overlay_effect(self):
        called = []
        original_fsync = os.fsync
        original_run = subprocess.run

        def observe_fsync(fd):
            try:
                target = os.readlink("/proc/self/fd/" + str(fd))
                called.append(target)
            except OSError:
                pass
            return original_fsync(fd)

        def observe_run(args, **kwargs):
            if isinstance(args, list) and len(args) > 1 and args[1] == "create":
                self.assertIn(str(self.jobs), called, "jobs parent not fsynced before image creation")
            return original_run(args, **kwargs)

        with self.fixture_hypervisor(), patch.object(vm.os, "fsync", side_effect=observe_fsync), patch.object(vm.subprocess, "run", side_effect=observe_run):
            vm.prepare_offline(self.root, run_id=55, job_id=66)
        self.assertIn(str(self.jobs), called)

    def test_failed_image_creation_retains_unreplayable_intent(self):
        self.fake_img.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "if sys.argv[1]=='info': print(json.dumps({'format':'qcow2'}));sys.exit(0)\n"
            "sys.exit(25)\n"
        )
        self.fake_img.chmod(0o700)
        self.record["qemu_img_sha256"] = sha(self.fake_img)
        self.save()
        with self.fixture_hypervisor():
            with self.assertRaises(subprocess.CalledProcessError):
                vm.prepare_offline(self.root, run_id=12, job_id=13)
            self.assertTrue((self.jobs / "csw-win-12-13" / "intent.json").exists())
            with self.assertRaisesRegex(vm.Held, "existing_or_uncertain_guest_intent"):
                vm.prepare_offline(self.root, run_id=12, job_id=13)

    def test_invalid_integer_job_ids_fail_closed(self):
        with self.fixture_hypervisor():
            for run_id, job_id in ((0, 1), (1, -1), (True, 1), (1, 10**20)):
                with self.subTest(job=(run_id, job_id)):
                    with self.assertRaisesRegex(vm.Held, "invalid_run_or_job_id"):
                        vm.prepare_offline(self.root, run_id=run_id, job_id=job_id)

    def test_cli_prepare_default_controls_refuses_without_effect(self):
        self.controls.unlink()
        p = subprocess.run(
            [sys.executable, str(Path(vm.__file__)), "prepare-offline",
             "--root", str(self.root), "--run-id", "123", "--job-id", "456"],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(p.returncode, 75, p.stderr)
        record = json.loads(p.stdout)
        self.assertEqual(record["decision"], "HOLD")
        self.assertFalse(record["github_runner_registered"])
        self.assertEqual(list(self.jobs.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
