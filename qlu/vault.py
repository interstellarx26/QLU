"""Encrypted local storage for the experimental, single-key QLU wallet.

This does not change spending or portable recovery formats. Unlock passwords
are local-only; independent recovery codes retain their existing meaning. Python
cannot guarantee erasure of secret strings or protect a compromised process/OS.
"""
from __future__ import annotations

import hmac
import math
import os
from pathlib import Path
import secrets
import stat
import sys
import threading
import time
import weakref

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Existing protocol helpers use direct imports internally. Resolve them from
# this checkout for both package imports and the command-line wallet.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol
import recovery


MAX_VAULT_BYTES = 8192
KDF = {"name": "Argon2id", "memory_kib": 65536, "iterations": 3, "lanes": 4, "length": 32}
HEADER_FIELDS = {"format", "version", "cipher", "kdf", "salt", "nonce",
                 "network_id", "genesis_hash", "policy"}
AAD_DOMAIN = b"QLU local vault v1 / authenticated header\x00"


class VaultError(ValueError):
    """An operation failed without exposing secret or backend details."""


def _passphrase(value: str) -> bytes:
    if type(value) is not str or len(value) < 15 or value.lstrip().upper().startswith("QLU1-"):
        raise VaultError("Use a separate passphrase of at least 15 characters")
    encoded = value.encode("utf-8")
    if len(encoded) > 1024:
        raise VaultError("Passphrase exceeds the supported size")
    return encoded  # No normalization or whitespace removal.


def _derive(passphrase: bytes, salt: bytes) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(passphrase)


def _wallet_identity(wallet: dict) -> dict:
    wallet = recovery.validate_wallet(wallet)
    if wallet["network_id"] != protocol.NETWORK or wallet["genesis_hash"] != protocol.GENESIS:
        raise VaultError("Unsupported wallet identity")
    return wallet


def _encrypt(wallet: dict, passphrase: bytes) -> bytes:
    wallet = _wallet_identity(wallet)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = {"format": "qlu-local-vault", "version": 1, "cipher": "AES-256-GCM",
              "kdf": dict(KDF), "salt": recovery._b64(salt), "nonce": recovery._b64(nonce),
              "network_id": protocol.NETWORK, "genesis_hash": protocol.GENESIS, "policy": recovery.POLICY}
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(
        nonce, recovery._canonical(wallet), AAD_DOMAIN + recovery._canonical(header))
    blob = recovery._canonical({**header, "ciphertext": recovery._b64(ciphertext)})
    if not 1 <= len(blob) <= MAX_VAULT_BYTES:
        raise VaultError("Invalid vault size")
    return blob


def _decrypt(blob: bytes, passphrase: bytes) -> dict:
    envelope = recovery._parse(blob, MAX_VAULT_BYTES)
    if (envelope.keys() != HEADER_FIELDS | {"ciphertext"}
            or envelope["format"] != "qlu-local-vault"
            or type(envelope["version"]) is not int or envelope["version"] != 1
            or envelope["cipher"] != "AES-256-GCM"
            or envelope["network_id"] != protocol.NETWORK
            or envelope["genesis_hash"] != protocol.GENESIS
            or envelope["policy"] != recovery.POLICY):
        raise VaultError("Unsupported vault envelope")
    kdf = envelope["kdf"]
    # Validate ALL resource parameters and their types before deriving any key.
    if (type(kdf) is not dict or kdf.keys() != KDF.keys()
            or any(type(kdf[name]) is not type(expected) or kdf[name] != expected
                   for name, expected in KDF.items())):
        raise VaultError("Unsupported vault KDF")
    salt = recovery._unb64(envelope["salt"], minimum=16, maximum=16)
    nonce = recovery._unb64(envelope["nonce"], minimum=12, maximum=12)
    ciphertext = recovery._unb64(envelope["ciphertext"], minimum=17, maximum=recovery.MAX_WALLET_BYTES + 16)
    header = {name: envelope[name] for name in HEADER_FIELDS}
    plaintext = AESGCM(_derive(passphrase, salt)).decrypt(
        nonce, ciphertext, AAD_DOMAIN + recovery._canonical(header))
    return _wallet_identity(recovery._parse(plaintext, recovery.MAX_WALLET_BYTES))


def _publish(path: Path, blob: bytes) -> None:
    """Publish a fully written encrypted inode without replacing any destination.

    A failure after publication may leave the complete encrypted vault at path;
    it never deletes the destination or retries with an overwrite. Only this
    invocation's temporary inode can be removed by cleanup.
    """
    directory_fd, name = recovery._open_parent(path)
    temporary = ".qlu-vault-" + secrets.token_hex(16) + ".tmp"
    fd = None
    identity = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
        metadata = os.fstat(fd)
        identity = (metadata.st_dev, metadata.st_ino)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(fd)
        current = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        if ((current.st_dev, current.st_ino) != identity or not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1 or current.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) != 0o600):
            raise VaultError("Unsafe vault temporary file")
        # link() fails if any destination exists, including a dangling symlink.
        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        published = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        current = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
        if ((published.st_dev, published.st_ino) != identity
                or (current.st_dev, current.st_ino) != identity
                or not stat.S_ISREG(published.st_mode) or published.st_nlink != 2
                or published.st_uid != os.geteuid() or stat.S_IMODE(published.st_mode) != 0o600):
            raise VaultError("Vault publication changed during creation")
        os.unlink(temporary, dir_fd=directory_fd)
        identity = None
        published = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != (metadata.st_dev, metadata.st_ino) or published.st_nlink != 1:
            raise VaultError("Vault publication changed during creation")
        os.fsync(directory_fd)
    finally:
        try:
            if fd is not None:
                os.close(fd)
            if identity is not None:
                try:
                    current = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == identity:
                        os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(directory_fd)


def _expire(reference, generation):
    session = reference()
    if session is None:
        return
    with session._mutex:
        if generation != session._generation or session._wallet is None:
            return
        remaining = session._deadline - time.monotonic()
        if remaining > 0:
            session._schedule_locked(remaining, generation)
        else:
            session._lock_locked()


class WalletSession:
    def __init__(self, path, *, idle_seconds=300):
        try:
            if (type(idle_seconds) not in (int, float) or not math.isfinite(idle_seconds)
                    or not 0 < idle_seconds <= 86400 or ".." in Path(path).parts):
                raise ValueError
            self._path = Path(os.path.abspath(os.fspath(path)))
        except Exception:
            raise VaultError("Invalid vault path or idle timeout") from None
        self._idle_seconds = float(idle_seconds)
        self._mutex = threading.RLock()
        self._wallet = None
        self._timer = None
        self._deadline = 0.0
        self._generation = 0

    def __repr__(self):
        return "<WalletSession locked>" if self.locked else "<WalletSession unlocked>"

    def _lock_locked(self):
        self._generation += 1
        if self._timer is not None:
            self._timer.cancel()
        self._timer = None
        self._wallet = None
        self._deadline = 0.0

    def _schedule_locked(self, delay, generation):
        timer = threading.Timer(delay, _expire, (weakref.ref(self), generation))
        timer.daemon = True
        self._timer = timer
        try:
            timer.start()
        except Exception:
            self._lock_locked()
            raise

    def _touch_locked(self):
        if self._timer is not None:
            self._timer.cancel()
        self._generation += 1
        self._deadline = time.monotonic() + self._idle_seconds
        self._schedule_locked(self._idle_seconds, self._generation)

    @property
    def locked(self):
        with self._mutex:
            if self._wallet is not None and time.monotonic() >= self._deadline:
                self._lock_locked()
            return self._wallet is None

    def lock(self):
        with self._mutex:
            self._lock_locked()

    @classmethod
    def _store(cls, path, wallet, encoded_passphrase, idle_seconds):
        session = cls(path, idle_seconds=idle_seconds)
        try:
            _publish(session._path, _encrypt(wallet, encoded_passphrase))
            with session._mutex:
                session._wallet = _wallet_identity(wallet)
                session._touch_locked()
            return session
        except BaseException:
            session.lock()
            raise

    @classmethod
    def create(cls, path, passphrase, *, idle_seconds=300):
        try:
            encoded = _passphrase(passphrase)
            wallet = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
            return cls._store(path, wallet, encoded, idle_seconds)
        except Exception:
            raise VaultError("Vault creation failed") from None

    @classmethod
    def restore(cls, path, backup_blob, code, passphrase, *, idle_seconds=300):
        try:
            encoded = _passphrase(passphrase)
            wallet = recovery.restore_backup(backup_blob, code, protocol.NETWORK, protocol.GENESIS)
            return cls._store(path, wallet, encoded, idle_seconds)
        except Exception:
            raise VaultError("Vault restoration failed") from None

    def unlock(self, passphrase):
        with self._mutex:
            self._lock_locked()  # Failed re-unlock must never retain old authority.
            try:
                encoded = _passphrase(passphrase)
                self._wallet = _decrypt(recovery.read_private(self._path, MAX_VAULT_BYTES), encoded)
                self._touch_locked()
            except BaseException as error:
                self._lock_locked()
                if isinstance(error, Exception):
                    raise VaultError("Vault unlock failed") from None
                raise

    def _operate(self, operation):
        with self._mutex:
            if self.locked:
                raise VaultError("Wallet is locked")
            try:
                result = operation(self._wallet)
                self._touch_locked()
                return result
            except Exception:
                raise VaultError("Wallet operation failed") from None

    @staticmethod
    def _public(wallet):
        keys = protocol.keytool(wallet)
        sizes = {"mldsa_public": 1952, "schnorr_public": 32, "key_commitment": 32}
        if (type(keys) is not dict or keys.keys() != sizes.keys() | {"policy_version"}
                or type(keys["policy_version"]) is not int or keys["policy_version"] != 1):
            raise VaultError("Invalid public key response")
        for name, size in sizes.items():
            if (type(keys[name]) is not str or len(keys[name]) != 2 * size
                    or bytes.fromhex(keys[name]).hex() != keys[name]):
                raise VaultError("Invalid public key response")
        return dict(keys)

    def public_keys(self):
        return self._operate(self._public)

    def address(self):
        return self._operate(lambda wallet: protocol.address_for(self._public(wallet)))

    def sign(self, tx, spent):
        return self._operate(lambda wallet: protocol.sign_transaction(wallet, tx, spent))

    def backup(self):
        return self._operate(recovery.make_backup)

    def verify_backup(self, blob, code):
        def verify(wallet):
            restored = recovery.restore_backup(blob, code, protocol.NETWORK, protocol.GENESIS)
            if not hmac.compare_digest(recovery._canonical(restored), recovery._canonical(wallet)):
                raise VaultError("Backup belongs to a different wallet")
            return True
        return self._operate(verify)
