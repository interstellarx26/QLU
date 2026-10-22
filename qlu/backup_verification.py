"""Store public, authenticated proof that this exact local vault's backup worked.

The store checks shape and filesystem safety. Only an unlocked WalletSession
can authenticate a receipt. No backup, recovery code, passphrase, or key is stored.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import stat

try:
    from . import protocol, recovery
except ImportError:
    import protocol
    import recovery

MAX_RECEIPT_BYTES = 4096
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
RECEIPT_FIELDS = {"format", "version", "network_id", "genesis_hash", "policy",
                  "vault_sha256", "wallet_commitment", "backup_sha256", "verified_at", "hmac_sha256"}
ERROR_MESSAGE = "The saved backup verification could not be read or saved safely. Verify your backup again."


class VerificationError(ValueError):
    def __init__(self):
        super().__init__(ERROR_MESSAGE)


def _valid(condition):
    if not condition:
        raise VerificationError()


def _digest(value):
    _valid(type(value) is str and HEX256.fullmatch(value) is not None)
    return value


def validate_receipt(blob, digest=None):
    """Validate bounded public metadata only; this does not authenticate its MAC."""
    try:
        value = recovery._parse(blob, MAX_RECEIPT_BYTES)
        _valid(set(value) == RECEIPT_FIELDS and value["format"] == "qlu-backup-verification"
               and type(value["version"]) is int and value["version"] == 1
               and value["network_id"] == protocol.NETWORK
               and value["genesis_hash"] == protocol.GENESIS
               and value["policy"] == recovery.POLICY)
        for name in ("vault_sha256", "wallet_commitment", "backup_sha256", "hmac_sha256"):
            _digest(value[name])
        _valid(type(value["verified_at"]) is int and 0 <= value["verified_at"] <= 2**53 - 1)
        if digest is not None:
            _valid(value["vault_sha256"] == _digest(digest))
        return value
    except Exception:
        raise VerificationError() from None


def _identity(info):
    return info.st_dev, info.st_ino


def _private(info, *, directory=False):
    _valid(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
    _valid(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)


@contextmanager
def _directory(path, *, create):
    parent = directory = None
    try:
        path = Path(path)
        _valid(path.is_absolute() and ".." not in path.parts)
        try:
            parent, name = recovery._open_parent(path)
        except FileNotFoundError:
            if not create:
                yield None
                return
            raise
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        try:
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
        except FileNotFoundError:
            if not create:
                yield None
                return
            raise
        opened = os.fstat(directory)
        _private(opened, directory=True)

        def check():
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _private(current, directory=True)
            _valid(_identity(current) == _identity(opened))

        check()
        yield directory, check
        check()
    finally:
        if directory is not None:
            os.close(directory)
        if parent is not None:
            os.close(parent)


def _read(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        _private(before)
        _valid(1 <= before.st_size <= MAX_RECEIPT_BYTES)
        chunks, remaining = [], MAX_RECEIPT_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _private(after)
        _private(named)
        _valid(_identity(before) == _identity(after) == _identity(named)
               and before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns)
        data = b"".join(chunks)
        _valid(len(data) == before.st_size and len(data) <= MAX_RECEIPT_BYTES)
        return data
    finally:
        os.close(fd)


def load_receipt(directory, digest):
    try:
        name = _digest(digest) + ".json"
        with _directory(directory, create=False) as opened:
            if opened is None:
                return None
            fd, check = opened
            try:
                data = _read(fd, name)
            except FileNotFoundError:
                return None
            check()
            validate_receipt(data, digest)
            return data
    except Exception:
        raise VerificationError() from None


def save_receipt(directory, digest, receipt):
    """Publish a complete receipt atomically; never follow or repair unsafe files."""
    try:
        name = _digest(digest) + ".json"
        validate_receipt(receipt, digest)
        with _directory(directory, create=True) as opened:
            directory_fd, check = opened
            temporary = ".verification-" + secrets.token_hex(16) + ".tmp"
            fd = identity = None
            try:
                # A corrupt but safely owned receipt can be replaced only by a
                # newly verified receipt. Unsafe types/links/permissions cannot.
                try:
                    previous = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    _private(previous)
                except FileNotFoundError:
                    previous = None
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory_fd)
                info = os.fstat(fd)
                _private(info)
                identity = _identity(info)
                view = memoryview(receipt)
                while view:
                    written = os.write(fd, view)
                    _valid(written > 0)
                    view = view[written:]
                os.fsync(fd)
                check()
                current = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
                _private(current)
                _valid(_identity(current) == identity)
                if previous is None:
                    os.link(temporary, name, src_dir_fd=directory_fd,
                            dst_dir_fd=directory_fd, follow_symlinks=False)
                    os.unlink(temporary, dir_fd=directory_fd)
                else:
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    _private(current)
                    _valid(_identity(current) == _identity(previous))
                    os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                os.fsync(directory_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                _private(current)
                _valid(_identity(current) == identity and _read(directory_fd, name) == receipt)
            finally:
                if fd is not None:
                    os.close(fd)
                if identity is not None:
                    try:
                        current = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
                        if _identity(current) == identity:
                            os.unlink(temporary, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
    except Exception:
        raise VerificationError() from None
