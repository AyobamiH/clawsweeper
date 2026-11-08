"""Admission exclusion shared with the already-installed local CI fleet.

The installed fleet uses local_ci.core.lock() and the same control.lock inode
for its entire dispatch cycle. We hold it throughout a protected JIT cycle:
a detached lease cannot appear between the live-fleet read and actual JIT
execution. No installed fleet code, database or service is modified here.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from estate_policy import Hold

FLEET_ROOT = Path.home() / ".local/share/local-ci"


@contextmanager
def shared_fleet_exclusive(root=FLEET_ROOT):
    root = Path(root)
    marker = root / "OWNED_BY_LOCAL_CI"
    lock = root / "control.lock"
    if root.is_symlink() or not root.is_dir():
        raise Hold("shared_fleet_root_unverifiable")
    root_st = root.stat()
    if root_st.st_uid != os.getuid() or root_st.st_mode & 0o077:
        raise Hold("shared_fleet_owner_unverifiable")
    if marker.is_symlink() or not marker.is_file() or marker.read_bytes() != b"local-ci-v1\n":
        raise Hold("shared_fleet_ownership_marker_mismatch")
    if lock.is_symlink() or not lock.is_file():
        raise Hold("shared_fleet_lock_unavailable")
    try:
        fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise Hold("shared_fleet_lock_unavailable") from exc
    acquired = False
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise Hold("unsafe_shared_fleet_lock")
        pathinfo = lock.stat()
        if (info.st_dev, info.st_ino) != (pathinfo.st_dev, pathinfo.st_ino):
            raise Hold("shared_fleet_lock_replaced")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Hold("shared_fleet_lock_busy") from exc
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextmanager
def legacy_executor_exclusive(lock=None):
    """Exclude the pre-existing ClawSweeper JIT executor during estate admission.

    It already uses an exclusive flock on its private executor.lock for its
    entire cycle. Use the same inode without creating/replacing it. An
    uncertain legacy runner outcome must be independently reconciled before
    any new registration, not inferred from lock acquisition alone.
    """
    lock = Path(lock) if lock is not None else (
        Path.home() / ".local/share/local-ci/clawsweeper-selfhosted/executor.lock"
    )
    if lock.is_symlink() or not lock.is_file():
        raise Hold("legacy_jit_lock_unavailable")
    try:
        fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise Hold("legacy_jit_lock_unavailable") from exc
    acquired = False
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise Hold("unsafe_legacy_jit_lock")
        pathinfo = lock.stat()
        if (info.st_dev, info.st_ino) != (pathinfo.st_dev, pathinfo.st_ino):
            raise Hold("legacy_jit_lock_replaced")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Hold("legacy_jit_controller_busy") from exc
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
