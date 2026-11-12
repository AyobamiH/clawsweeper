"""No-provider adversarial export tests: refuse huge sparse logical files BEFORE host writes."""
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import self_hosted_executor as runner


def archive_fixture(*entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as output:
        root = tarfile.TarInfo("e2e-evidence")
        root.type = tarfile.DIRTYPE
        output.addfile(root)
        for name, payload in entries:
            member = tarfile.TarInfo("e2e-evidence/" + name)
            member.mode = 0o777
            if payload is None:
                member.type = tarfile.DIRTYPE
                output.addfile(member)
            else:
                member.size = len(payload)
                output.addfile(member, io.BytesIO(payload))
    return data.getvalue()


class BoundedExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.vault = Path(self.temp.name) / "vault"
        self.vault.mkdir(mode=0o700)

    def export(self, blob):
        return runner._bounded_tar_evidence_export(io.BytesIO(blob), self.vault)

    def test_real_regular_fixture_roundtrip_and_owner_only_modes(self):
        blob = archive_fixture(
            ("run-12345-attempt-1", None),
            ("run-12345-attempt-1/receipt.json", b'{"fixture":"tiny"}'),
            ("run-12345-attempt-1/log.txt", b"run done"))
        value = self.export(blob)
        self.assertEqual(value["file_count"], 2)
        self.assertEqual(value["logical_bytes"], len(b'{"fixture":"tiny"}') + len(b"run done"))
        output = self.vault / "run-12345-attempt-1" / "receipt.json"
        self.assertEqual(output.read_bytes(), b'{"fixture":"tiny"}')
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)

    def test_sparse_512_mib_in_256_mib_tmpfs_refused_before_host_copy(self):
        # Deliberately incomplete tar. No 512-MiB payload is constructed.
        member = tarfile.TarInfo("e2e-evidence/run-12345-attempt-1/sparse.bin")
        member.size = 512 * 1024 * 1024
        payload = member.tobuf() + bytes(1024)
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_export_file_oversized"):
            self.export(payload)
        self.assertEqual(list(self.vault.rglob("*")), [])

    def test_symlink_refused_even_when_target_inside_vault(self):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as output:
            t = tarfile.TarInfo("e2e-evidence/link")
            t.type = tarfile.SYMTYPE
            t.linkname = "run-12345-attempt-1/receipt.json"
            output.addfile(t)
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_export_special_file_refused"):
            self.export(b.getvalue())
        self.assertEqual(list(self.vault.rglob("*")), [])

    def test_parent_escape_refused(self):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode="w") as output:
            t = tarfile.TarInfo("e2e-evidence/../escape")
            t.size = 2
            output.addfile(t, io.BytesIO(b"no"))
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_export_unsafe_path"):
            self.export(b.getvalue())
        self.assertFalse((self.vault.parent / "escape").exists())

    def test_duplicate_entries_refused(self):
        blob = archive_fixture(("same.txt", b"A"), ("same.txt", b"B"))
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_export_duplicate_path"):
            self.export(blob)

    def test_transport_limit_has_hard_read_budget(self):
        data = runner._BoundedTarInput(io.BytesIO(b"AB"))
        data.total = data.limit
        with self.assertRaisesRegex(runner.AdmissionHold, "isolation_export_stream_oversized"):
            data.read(2)

    def test_no_direct_docker_cp_to_host_and_no_socket_mounted(self):
        import inspect
        body = inspect.getsource(runner.export_isolation_volume)
        self.assertIn('holder + ":/e2e-evidence/.", "-"', body)
        self.assertNotIn('str(vault)], timeout=', body)
        self.assertNotIn("docker.sock", body)
        self.assertIn("start_new_session=True", body)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", body)


if __name__ == "__main__":
    unittest.main()
