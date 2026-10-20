"""Shared coordination for the localhost-only QLU laboratory."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from devnet import DevnetError


ROOT = Path(__file__).resolve().parents[1]
LOCK_NAME = "qlu-ports-28440.lock"


def _validate_lock(metadata):
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
        raise DevnetError("Unsafe QLU port lock: require a regular, singly linked file owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise DevnetError("Unsafe QLU port lock: permissions must be 0600")


@contextmanager
def private_port_lock(root=ROOT):
    """Serialize supported coordinators sharing this checkout's QLU port range.

    The caller holds this across setup, start, operations, and cleanup. Controller
    methods do not acquire it recursively. Keep the lock file after releasing it:
    unlinking it would allow two processes to lock different inodes. Existing
    node/port ownership checks still protect against unrelated processes and
    coordinators in another checkout.
    """
    directory = Path(root).resolve() / ".local"
    directory_fd = lock_fd = None
    acquired = False
    try:
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            metadata = os.fstat(directory_fd)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise DevnetError("Unsafe QLU laboratory directory: require a directory owned by the current user")
            os.fchmod(directory_fd, 0o700)
            # NONBLOCK prevents a malicious FIFO from hanging before fstat.
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            lock_fd = os.open(LOCK_NAME, flags, 0o600, dir_fd=directory_fd)
            _validate_lock(os.fstat(lock_fd))
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise DevnetError("Another QLU private-network operation is in progress") from error
            acquired = True
            opened = os.fstat(lock_fd)
            _validate_lock(opened)
            named = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise DevnetError("QLU port lock changed during acquisition")
        except OSError as error:
            raise DevnetError("Cannot safely acquire the QLU private-network port lock") from error
        yield
    finally:
        try:
            if lock_fd is not None:
                try:
                    if acquired:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
