"""Adversarial real-fcntl checks for cross-owner admission, without provider effects."""
import contextlib
import fcntl
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[2]/'scripts/ci'))
import self_hosted_executor as e
from self_hosted_policy import AdmissionHold

class AtomicFleetLeaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        self.marker=self.home/'OWNED_BY_LOCAL_CI'
        self.marker.write_text('local-ci-v1\n')
        self.lock=self.home/'control.lock'
        self.lock.touch(mode=0o600)
        self.canonical_home=self.home/'canonical-source-suite'
        self.canonical_home.mkdir(mode=0o700)
        self.canonical=self.canonical_home/'full-source.lock'
        self.canonical.touch(mode=0o600)
        marker=patch.object(e,'FLEET_OWNER_MARKER',self.marker)
        key=patch.object(e,'FLEET_CONTROL_LOCK',self.lock)
        canonical=patch.object(e,'CANONICAL_TEST_LOCK',self.canonical)
        marker.start(); key.start(); canonical.start()
        self.addCleanup(marker.stop); self.addCleanup(key.stop)
        self.addCleanup(canonical.stop)
    def test_idle_owner_lock_is_acquired_and_released(self):
        with e.shared_fleet_admission_lock():
            fd=os.open(self.lock,os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
        fd=os.open(self.lock,os.O_RDWR)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(fd)
    def test_other_process_fleet_owner_is_exclusive(self):
        program='''import os,fcntl,sys;fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(fd,fcntl.LOCK_EX);print('READY',flush=True);sys.stdin.readline();os.close(fd)'''
        p=subprocess.Popen([sys.executable,'-u','-c',program,str(self.lock)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(p.stdout.readline().strip(),'READY')
            with self.assertRaisesRegex(AdmissionHold,'shared_fleet_lock_busy'):
                with e.shared_fleet_admission_lock():pass
        finally:
            p.stdin.write('\n');p.stdin.flush();p.communicate(timeout=5)
        self.assertEqual(p.returncode,0)
        with e.shared_fleet_admission_lock():pass
    def test_canonical_source_suite_lock_blocks_jit_even_with_free_fleet(self):
        program="""import fcntl,os,sys;fd=os.open(sys.argv[1],os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX);print('READY',flush=True);sys.stdin.readline()"""
        p=subprocess.Popen([sys.executable,'-u','-c',program,str(self.canonical)],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(p.stdout.readline().strip(),'READY')
            with self.assertRaisesRegex(AdmissionHold,'canonical_test_lock_busy'):
                with e.shared_fleet_admission_lock():pass
        finally:
            p.stdin.write('\n');p.stdin.flush();p.communicate(timeout=5)
        with e.shared_fleet_admission_lock():pass

    def test_jit_holds_both_fleet_and_canonical_inodes_until_cleanup(self):
        with e.shared_fleet_admission_lock():
            for path in (self.lock,self.canonical):
                with self.subTest(path=path):
                    fd=os.open(path,os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally:os.close(fd)
        with e.shared_fleet_admission_lock():pass

    def test_canonical_absent_symlink_hardlink_and_public_mode_fail_closed(self):
        self.canonical.unlink()
        with self.assertRaisesRegex(AdmissionHold,'canonical_test_lock_unavailable'):
            with e.shared_fleet_admission_lock():pass
        self.assertFalse(self.canonical.exists())
        outside=self.home/'outside'; outside.write_text('preserve')
        self.canonical.symlink_to(outside)
        with self.assertRaisesRegex(AdmissionHold,'canonical_test_lock_unavailable'):
            with e.shared_fleet_admission_lock():pass
        self.canonical.unlink();self.canonical.touch(mode=0o600)
        os.link(self.canonical,self.home/'canonical-hardlink')
        with self.assertRaisesRegex(AdmissionHold,'canonical_test_lock_unsafe'):
            with e.shared_fleet_admission_lock():pass
        (self.home/'canonical-hardlink').unlink()
        self.canonical.chmod(0o666)
        with self.assertRaisesRegex(AdmissionHold,'canonical_test_lock_unsafe'):
            with e.shared_fleet_admission_lock():pass
        self.assertEqual(outside.read_text(),'preserve')

    def test_canonical_lock_replaced_mid_admission_is_rejected(self):
        original_open=os.open
        replacement=self.home/'new-canonical'
        replacement.touch(mode=0o600)
        def open_and_replace(path,flags,*args):
            fd=original_open(path,flags,*args)
            if os.fspath(path)==os.fspath(self.canonical):
                os.replace(replacement,self.canonical)
            return fd
        with patch.object(e.os,'open',side_effect=open_and_replace):
            with self.assertRaisesRegex(AdmissionHold,'canonical_test_lock_replaced'):
                with e.shared_fleet_admission_lock():pass

    def test_missing_or_changed_ownership_marker_fails_closed(self):
        for content in ('wrong\n',''):
            with self.subTest(content=content):
                self.marker.write_text(content)
                with self.assertRaisesRegex(AdmissionHold,'shared_fleet_lock_owner_unverified'):
                    with e.shared_fleet_admission_lock():pass
        self.marker.unlink()
        with self.assertRaisesRegex(AdmissionHold,'shared_fleet_lock_owner_unverified'):
            with e.shared_fleet_admission_lock():pass
    def test_rejects_symlinked_or_world_readable_lock(self):
        external=self.home/'outside';external.write_text('preserve')
        self.lock.unlink()
        self.lock.symlink_to(external)
        with self.assertRaisesRegex(AdmissionHold,'shared_fleet_lock_unavailable'):
            with e.shared_fleet_admission_lock():pass
        self.lock.unlink(); self.lock.write_text('');self.lock.chmod(0o644)
        with self.assertRaisesRegex(AdmissionHold,'shared_fleet_lock_unsafe'):
            with e.shared_fleet_admission_lock():pass
        self.assertEqual(external.read_text(),'preserve')
    def test_unsafe_symlinked_owner_marker_refused(self):
        original=self.home/'marker-source';original.write_text('local-ci-v1\n')
        self.marker.unlink();self.marker.symlink_to(original)
        with self.assertRaisesRegex(AdmissionHold,'shared_fleet_lock_owner_unverified'):
            with e.shared_fleet_admission_lock():pass
    def test_missing_fleet_lock_cannot_be_recreated(self):
        self.lock.unlink()
        with self.assertRaisesRegex(AdmissionHold, 'shared_fleet_lock_unavailable'):
            with e.shared_fleet_admission_lock(): pass
        self.assertFalse(self.lock.exists())

    def test_hardlinked_fleet_lock_is_not_an_exclusive_identity(self):
        os.link(self.lock, self.home/'other')
        with self.assertRaisesRegex(AdmissionHold, 'shared_fleet_lock_unsafe'):
            with e.shared_fleet_admission_lock(): pass

    def test_untrusted_parent_permissions_refuse_external_admission(self):
        self.home.chmod(0o770)
        with self.assertRaisesRegex(AdmissionHold, 'shared_fleet_lock_owner_unverified'):
            with e.shared_fleet_admission_lock(): pass

    def test_replaced_lock_inode_is_not_accepted_after_open(self):
        original_open=os.open
        replacement=self.home/'replacement'
        replacement.touch(mode=0o600)
        def open_and_replace(path, flags, *args):
            fd=original_open(path, flags, *args)
            if os.fspath(path)==os.fspath(self.lock):
                os.replace(replacement, self.lock)
            return fd
        with patch.object(e.os,'open',side_effect=open_and_replace):
            with self.assertRaisesRegex(AdmissionHold,'shared_fleet_lock_replaced'):
                with e.shared_fleet_admission_lock(): pass

    def test_actual_cycle_holds_lock_across_capacity_and_runner_cleanup(self):
        seen=[]
        def check(*_):
            fd=os.open(self.lock,os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            seen.append('capacity')
        def fake_runner(*_):
            check()
            seen.append('runner_and_cleanup')
            return {'state':'mocked_no_external_effect'}
        stdout=io.StringIO()
        with (patch.object(e,'ROOT',self.home/'private'),
              patch.object(e,'LOCK',self.home/'jit.lock'),
              patch.object(e,'load_controls',return_value={'enabled':True}),
              patch.object(e,'discover',return_value=[SimpleNamespace()]),
              patch.object(e,'category_enabled'),patch.object(e,'source_authorised'),
              patch.object(e,'capacity',side_effect=check),
              patch.object(e,'runner_job',side_effect=fake_runner),
              patch.object(sys,'argv',['executor','cycle']),
              contextlib.redirect_stdout(stdout)):
            e.main()
        self.assertEqual(seen,['capacity','capacity','runner_and_cleanup'])
        self.assertIn('mocked_no_external_effect',stdout.getvalue())
        with e.shared_fleet_admission_lock():pass

if __name__=='__main__':unittest.main()
