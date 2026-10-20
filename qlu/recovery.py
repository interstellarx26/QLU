#!/usr/bin/env python3
"""QLU private-network recovery prototype; not a production wallet.

Wallet v1 contains one 32-byte master seed for one hybrid key pair. Derivation
version 1 and policy are mandatory; no HD key discovery is implied. A backup
preserves the complete wallet, including network/genesis and discovery metadata.

Recovery code: 32 independent random bytes || first 8 bytes of
SHA256(b"QLU recovery code v1\\0" || code), RFC 4648 uppercase Base32 without
padding, grouped in eight groups of eight characters, prefixed "QLU1-".
The checksum catches transcription errors; it is not an authentication factor.
The code must be generated, never chosen from a password or PIN.

Backup v1: canonical UTF-8 JSON (sorted keys, no whitespace), AES-256-GCM with
128-bit tag and random 12-byte nonce. HKDF-SHA256 derives a 32-byte key from the
recovery code using a random 32-byte salt and fixed domain-separated info.
The entire header except ciphertext is authenticated as associated data, with
another fixed domain prefix. Parsers reject unknown fields/versions/algorithms,
duplicate keys, oversized payloads, and unsupported wallet policies.

The backup and recovery code must be stored separately. Neither is escrowed;
there is no company reset or authorization bypass. Restoring a compromised key
does not revoke copies of it. Python does not guarantee secret-memory erasure.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

POLICY = "mldsa65-and-bip340-v1"
MAX_WALLET_BYTES = 4096
MAX_BACKUP_BYTES = 8192
MAX_CODE_BYTES = 128
CODE_DOMAIN = b"QLU recovery code v1\x00"
KEY_DOMAIN = b"QLU wallet backup v1 / AES-256-GCM key\x00"
AAD_DOMAIN = b"QLU wallet backup v1 / authenticated header\x00"
WALLET_FIELDS = frozenset({"format", "version", "policy", "derivation_version",
                           "network_id", "genesis_hash", "master_seed", "discovery"})
HEADER_FIELDS = frozenset({"format", "version", "cipher", "kdf", "salt", "nonce",
                           "network_id", "genesis_hash"})


class RecoveryError(ValueError):
    """A recovery operation failed without returning secret material."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError("Duplicate JSON field")
        result[key] = value
    return result


def _no_constant(_: str) -> None:
    raise RecoveryError("Invalid JSON constant")


def _parse(blob: bytes, limit: int) -> dict:
    if not isinstance(blob, bytes) or not 1 <= len(blob) <= limit:
        raise RecoveryError("Invalid payload size")
    try:
        result = json.loads(blob.decode("utf-8"), object_pairs_hook=_pairs,
                            parse_constant=_no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise RecoveryError("Invalid JSON payload") from None
    if type(result) is not dict:
        raise RecoveryError("Payload must be a JSON object")
    return result


def _identity(network_id: str, genesis_hash: str) -> None:
    if type(network_id) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", network_id) is None:
        raise RecoveryError("Invalid network identity")
    if type(genesis_hash) is not str or re.fullmatch(r"[0-9a-f]{64}", genesis_hash) is None:
        raise RecoveryError("Invalid genesis hash")


def validate_wallet(wallet: dict) -> dict:
    """Validate and return a detached copy; never silently migrate a wallet."""
    if type(wallet) is not dict or wallet.keys() != WALLET_FIELDS:
        raise RecoveryError("Unsupported wallet fields")
    if wallet["format"] != "qlu-wallet" or type(wallet["version"]) is not int or wallet["version"] != 1:
        raise RecoveryError("Unsupported wallet format")
    if wallet["policy"] != POLICY or type(wallet["derivation_version"]) is not int or wallet["derivation_version"] != 1:
        raise RecoveryError("Unsupported signing policy or derivation")
    _identity(wallet["network_id"], wallet["genesis_hash"])
    if type(wallet["master_seed"]) is not str or re.fullmatch(r"[0-9a-f]{64}", wallet["master_seed"]) is None:
        raise RecoveryError("Invalid master seed")
    discovery = wallet["discovery"]
    if type(discovery) is not dict or discovery.keys() != {"scheme", "key_index", "scan_from_height"}:
        raise RecoveryError("Unsupported discovery metadata")
    if discovery["scheme"] != "single-key-v1" or type(discovery["key_index"]) is not int or discovery["key_index"] != 0:
        raise RecoveryError("Only single-key discovery is supported")
    if type(discovery["scan_from_height"]) is not int or not 0 <= discovery["scan_from_height"] <= 2**31 - 1:
        raise RecoveryError("Invalid scan height")
    encoded = _canonical(wallet)
    if len(encoded) > MAX_WALLET_BYTES:
        raise RecoveryError("Wallet payload is too large")
    return _parse(encoded, MAX_WALLET_BYTES)


def generate_wallet(network_id: str, genesis_hash: str) -> dict:
    _identity(network_id, genesis_hash)
    return validate_wallet({
        "format": "qlu-wallet", "version": 1, "policy": POLICY,
        "derivation_version": 1, "network_id": network_id,
        "genesis_hash": genesis_hash, "master_seed": secrets.token_bytes(32).hex(),
        "discovery": {"scheme": "single-key-v1", "key_index": 0, "scan_from_height": 0},
    })


def generate_recovery_code() -> str:
    raw = secrets.token_bytes(32)
    checksum = hashlib.sha256(CODE_DOMAIN + raw).digest()[:8]
    encoded = base64.b32encode(raw + checksum).decode("ascii")
    return "QLU1-" + "-".join(encoded[i:i + 8] for i in range(0, len(encoded), 8))


def _decode_code(code: str) -> bytes:
    if type(code) is not str or len(code) > MAX_CODE_BYTES:
        raise RecoveryError("Invalid recovery code")
    code = code.strip().upper()
    if re.fullmatch(r"QLU1-(?:[A-Z2-7]{8}-){7}[A-Z2-7]{8}", code) is None:
        raise RecoveryError("Invalid recovery code format")
    try:
        payload = base64.b32decode(code[5:].replace("-", ""))
    except (ValueError, binascii.Error):
        raise RecoveryError("Invalid recovery code") from None
    raw, checksum = payload[:32], payload[32:]
    if len(payload) != 40 or not hmac.compare_digest(checksum, hashlib.sha256(CODE_DOMAIN + raw).digest()[:8]):
        raise RecoveryError("Recovery code checksum failed")
    return raw


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: Any, *, minimum: int, maximum: int) -> bytes:
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise RecoveryError("Invalid encoded field")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise RecoveryError("Invalid encoded field") from None
    if not minimum <= len(raw) <= maximum or _b64(raw) != value:
        raise RecoveryError("Invalid encoded field length or encoding")
    return raw


def _key(raw_code: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=KEY_DOMAIN).derive(raw_code)


def make_backup(wallet: dict, recovery_code: str | None = None) -> tuple[bytes, str]:
    """Encrypt a complete wallet; return (backup bytes, independent offline code).

    Existing generated codes may be reused for a refreshed backup. Caller-supplied
    codes must originate from generate_recovery_code(); passwords are unsupported.
    """
    wallet = validate_wallet(wallet)
    recovery_code = generate_recovery_code() if recovery_code is None else recovery_code
    raw_code = _decode_code(recovery_code)
    recovery_code = recovery_code.strip().upper()
    salt, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    header = {"format": "qlu-backup", "version": 1, "cipher": "AES-256-GCM",
              "kdf": "HKDF-SHA256", "salt": _b64(salt), "nonce": _b64(nonce),
              "network_id": wallet["network_id"], "genesis_hash": wallet["genesis_hash"]}
    ciphertext = AESGCM(_key(raw_code, salt)).encrypt(nonce, _canonical(wallet), AAD_DOMAIN + _canonical(header))
    return _canonical({**header, "ciphertext": _b64(ciphertext)}), recovery_code


def restore_backup(blob: bytes, recovery_code: str, expected_network: str,
                   expected_genesis: str) -> dict:
    """Restore only after authentication and an exact caller-supplied chain match."""
    _identity(expected_network, expected_genesis)
    envelope = _parse(blob, MAX_BACKUP_BYTES)
    if envelope.keys() != HEADER_FIELDS | {"ciphertext"}:
        raise RecoveryError("Unsupported backup fields")
    if envelope["format"] != "qlu-backup" or type(envelope["version"]) is not int or envelope["version"] != 1:
        raise RecoveryError("Unsupported backup format")
    if envelope["cipher"] != "AES-256-GCM" or envelope["kdf"] != "HKDF-SHA256":
        raise RecoveryError("Unsupported backup encryption")
    _identity(envelope["network_id"], envelope["genesis_hash"])
    if envelope["network_id"] != expected_network or envelope["genesis_hash"] != expected_genesis:
        raise RecoveryError("Backup belongs to a different network")
    salt = _unb64(envelope["salt"], minimum=32, maximum=32)
    nonce = _unb64(envelope["nonce"], minimum=12, maximum=12)
    ciphertext = _unb64(envelope["ciphertext"], minimum=17, maximum=MAX_WALLET_BYTES + 16)
    raw_code = _decode_code(recovery_code)
    header = {key: value for key, value in envelope.items() if key != "ciphertext"}
    try:
        plaintext = AESGCM(_key(raw_code, salt)).decrypt(nonce, ciphertext, AAD_DOMAIN + _canonical(header))
    except InvalidTag:
        raise RecoveryError("Backup authentication failed") from None
    wallet = validate_wallet(_parse(plaintext, MAX_WALLET_BYTES))
    if wallet["network_id"] != expected_network or wallet["genesis_hash"] != expected_genesis:
        raise RecoveryError("Wallet belongs to a different network")
    return wallet


def _open_parent(path: str | Path) -> tuple[int, str]:
    """Open each directory relative to its fd; never follow a symlink component."""
    if ".." in Path(path).parts:
        raise RecoveryError("Parent traversal is not accepted in private file paths")
    path = Path(os.path.abspath(os.fspath(path)))
    if path.name in {"", ".", ".."}:
        raise RecoveryError("Invalid private file path")
    directory_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        info = os.fstat(directory_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RecoveryError("Private file parent must be owned by this user and not writable by others")
        return directory_fd, path.name
    except BaseException:
        os.close(directory_fd)
        raise


def write_private(path: str | Path, data: bytes) -> None:
    """Create a new 0600 file, refusing existing files, links, and unsafe parents."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_BACKUP_BYTES:
        raise RecoveryError("Invalid private file size")
    directory_fd, name = _open_parent(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def read_private(path: str | Path, max_bytes: int = MAX_BACKUP_BYTES) -> bytes:
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BACKUP_BYTES:
        raise RecoveryError("Invalid private file limit")
    directory_fd, name = _open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise RecoveryError("Private file must be a single-link regular file owned by this user with mode 0600")
            if not 1 <= info.st_size <= max_bytes:
                raise RecoveryError("Invalid private file size")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(max_bytes + 1)
            if not 1 <= len(data) <= max_bytes:
                raise RecoveryError("Invalid private file size")
            return data
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def save_wallet(path: str | Path, wallet: dict) -> None:
    write_private(path, _canonical(validate_wallet(wallet)) + b"\n")


def load_wallet(path: str | Path) -> dict:
    return validate_wallet(_parse(read_private(path, MAX_WALLET_BYTES), MAX_WALLET_BYTES))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="QLU private-network wallet recovery prototype")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="Create one prototype wallet in a private file")
    create.add_argument("--network", required=True)
    create.add_argument("--genesis", required=True)
    create.add_argument("--wallet", required=True)
    backup = subparsers.add_parser("backup", help="Write encrypted backup and separate offline code files")
    backup.add_argument("--wallet", required=True)
    backup.add_argument("--backup", required=True)
    backup.add_argument("--code-file", required=True)
    restore = subparsers.add_parser("restore", help="Restore to a new private wallet file")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--code-file", required=True)
    restore.add_argument("--network", required=True)
    restore.add_argument("--genesis", required=True)
    restore.add_argument("--wallet", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            save_wallet(args.wallet, generate_wallet(args.network, args.genesis))
            print("Prototype wallet created. Create and test its backup before use.")
        elif args.command == "backup":
            if Path(os.path.abspath(args.backup)).parent == Path(os.path.abspath(args.code_file)).parent:
                raise RecoveryError("Backup and code files must use separate directories; store them separately offline")
            blob, code = make_backup(load_wallet(args.wallet))
            # Code first: a failure can leave an unused code, never an inaccessible
            # backup whose recovery material was lost. Neither file is overwritten.
            write_private(args.code_file, code.encode("ascii") + b"\n")
            write_private(args.backup, blob + b"\n")
            print("Backup and code saved. Move the code to separate offline storage and test restoration.")
        else:
            code = read_private(args.code_file, MAX_CODE_BYTES).decode("ascii")
            wallet = restore_backup(read_private(args.backup), code, args.network, args.genesis)
            save_wallet(args.wallet, wallet)
            print("Wallet restored. Its existing keys remain valid on any other copy.")
    except (RecoveryError, OSError, UnicodeError):
        # Error details must not echo supplied secrets, file contents, or argv.
        print("Recovery operation failed. Check file permissions, format, network, and recovery materials; existing files are never overwritten.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
