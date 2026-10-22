#!/usr/bin/env python3
"""Package an allowlisted source kit and verify it before native target builds.

Origin creation requires a prepared device_lab session and its Python environment.
Target verification uses only the standard library. No backup decryption or node
operation occurs here. Archive SHA256 must be checked through the origin handoff;
the internal manifest detects changes, but is not an independently trusted signer.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
SOURCE_FILES = (
    "COPYING", "qlu/upstream.json", "qlu/protocol.py", "qlu/recovery.py",
    "qlu/device_recovery.py", "qlu/package_device_kit.py", "qlu/recovery-requirements.txt",
    "qlu/keytool-build/CMakeLists.txt", "qlu/tests/test_device_recovery.py",
    "qlu/tests/test_recovery.py", "docs/QLU_PRIVATE_V1.md", "docs/RECOVERY_RELEASE_GATE.md",
    "docs/MACBOOK_RECOVERY.md", "src/qlu/crypto.cpp", "src/qlu/crypto.h", "src/qlu/keytool.cpp",
    "src/crypto/sha256.cpp", "src/crypto/sha256.h", "src/crypto/hmac_sha256.cpp",
    "src/crypto/hmac_sha256.h", "src/crypto/common.h", "src/compat/endian.h",
    "src/compat/byteswap.h", "src/support/cleanse.cpp", "src/support/cleanse.h",
)
SOURCE_TREES = ("src/secp256k1", "src/univalue/include", "src/univalue/lib",
                "test/functional/test_framework")
SCRIPT_HASHES = {"device_recovery_sha256": "qlu/device_recovery.py",
                 "protocol_sha256": "qlu/protocol.py", "recovery_sha256": "qlu/recovery.py"}
RECOVERY_PROFILE = "recovery-v1"
WALLET_PROFILE = "encrypted-wallet-v1"
WALLET_SOURCE_FILES = (
    "qlu/vault.py", "qlu/backup_verification.py", "qlu/wallet.py", "qlu/wallet_device.py",
    "qlu/tests/test_vault.py", "qlu/tests/test_backup_verification.py", "qlu/tests/test_wallet.py", "qlu/tests/test_wallet_device.py",
    "docs/SECURE_WALLET.md", "docs/MACBOOK_WALLET_TEST.md",
)
WALLET_SCRIPT_HASHES = {"vault_sha256": "qlu/vault.py", "wallet_sha256": "qlu/wallet.py",
                        "wallet_device_sha256": "qlu/wallet_device.py"}
WALLET_ORIGIN_FIELDS = {
    "format", "version", "session_id", "purpose", "network_id", "genesis_hash",
    "challenge_sha256", "backup_sha256", "wallet_commitment", "tooling",
    "origin_vault_sha256", "origin_checks", "created_at",
}
NOTICE = b"""QLU private recovery source kit

Experimental, unaudited; private development coins have no monetary value.
This kit contains selected Bitcoin Core v31.1 sources, including UniValue and
libsecp256k1, plus QLU changes. Original file copyright notices are preserved.
Bitcoin Core and UniValue licensing: COPYING and individual source notices.
libsecp256k1 licensing: src/secp256k1/COPYING.
Exact upstream identity: qlu/upstream.json. Exact packaged files: KIT-MANIFEST.json.
OpenSSL and Python dependencies are installed separately on the target under
their respective licenses. No precompiled native binary is distributed here.

The encrypted disposable test backup and public challenge are in transfer/.
The recovery code is deliberately absent and must travel separately offline.
"""


class KitError(ValueError):
    pass


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _safe_name(name: str) -> str:
    if type(name) is not str:
        raise KitError("Unsafe archive member")
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or path.as_posix() != name
            or any(part in (".", "..", ".git", ".local", "build", "__pycache__") for part in path.parts)):
        raise KitError("Unsafe archive member")
    return name


def _read(root: Path, name: str, maximum: int = MAX_FILE_BYTES) -> bytes:
    """Walk a fixed source path without following symbolic links."""
    _safe_name(name)
    parts = PurePosixPath(name).parts
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= maximum:
                raise KitError("Source must be a bounded single-link regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                blob = stream.read(maximum + 1)
            if len(blob) > maximum:
                raise KitError("Source file exceeded size limit")
            return blob
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=30)
    if result.returncode:
        raise KitError("Unable to inspect the pinned source checkout")
    return result.stdout


def _source_files(profile: str) -> tuple[str, ...]:
    if type(profile) is not str or profile not in (RECOVERY_PROFILE, WALLET_PROFILE):
        raise KitError("Unsupported source-kit profile")
    return SOURCE_FILES + (WALLET_SOURCE_FILES if profile == WALLET_PROFILE else ())


def selected_sources(root: Path = ROOT, *, profile: str = RECOVERY_PROFILE) -> dict[str, bytes]:
    names = set(_source_files(profile))
    tracked = _git(root, "ls-files", "-z", "--", *SOURCE_TREES).decode().split("\0")
    for name in filter(None, tracked):
        if name.startswith("test/functional/test_framework/") and not name.endswith(".py"):
            continue
        names.add(_safe_name(name))
    if not any(name.startswith("src/secp256k1/src/") for name in names):
        raise KitError("Pinned secp256k1 source is missing")
    result = {name: _read(root, name) for name in sorted(names)}
    if sum(map(len, result.values())) > MAX_TOTAL_BYTES:
        raise KitError("Selected source exceeded size limit")
    return result


def _validate_wallet_origin(origin: dict, context: dict, challenge: dict,
                            source_hashes: dict[str, str]) -> None:
    """Check public wallet provenance using only standard-library operations."""
    if (type(origin) is not dict or origin.keys() != WALLET_ORIGIN_FIELDS
            or origin["format"] != "qlu-wallet-device-origin"
            or type(origin["version"]) is not int or origin["version"] != 1):
        raise KitError("Unsupported encrypted-wallet origin metadata")
    for field in ("session_id", "purpose", "network_id", "genesis_hash", "challenge_sha256", "backup_sha256"):
        if type(origin[field]) is not str or origin[field] != context.get(field):
            raise KitError("Encrypted-wallet origin identity does not match the session")
    if (origin["purpose"] not in ("rehearsal", "physical-device")
            or re.fullmatch(r"[0-9a-f]{32}", origin["session_id"]) is None
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", origin["network_id"]) is None):
        raise KitError("Invalid encrypted-wallet origin identity")
    for field in ("genesis_hash", "challenge_sha256", "backup_sha256", "wallet_commitment", "origin_vault_sha256"):
        if type(origin[field]) is not str or re.fullmatch(r"[0-9a-f]{64}", origin[field]) is None:
            raise KitError("Invalid encrypted-wallet origin fingerprint")
    if (type(challenge) is not dict or origin["wallet_commitment"] != challenge.get("wallet_commitment")
            or origin["session_id"] != challenge.get("challenge_id")
            or origin["network_id"] != challenge.get("network_id")
            or origin["genesis_hash"] != challenge.get("genesis_hash")):
        raise KitError("Encrypted-wallet origin does not match its payment challenge")
    tooling = origin["tooling"]
    if type(tooling) is not dict or tooling.keys() != WALLET_SCRIPT_HASHES.keys():
        raise KitError("Unsupported encrypted-wallet source fingerprints")
    for field, path in WALLET_SCRIPT_HASHES.items():
        if (type(tooling[field]) is not str or re.fullmatch(r"[0-9a-f]{64}", tooling[field]) is None
                or tooling[field] != source_hashes.get(path)):
            raise KitError("Encrypted-wallet sources changed after session preparation")
    checks = origin["origin_checks"]
    if (type(checks) is not dict or checks.keys() != {"encrypted_reopen_same_identity", "portable_backup_verified"}
            or any(value is not True for value in checks.values())):
        raise KitError("Encrypted-wallet origin checks are incomplete")
    if type(origin["created_at"]) is not str or not 1 <= len(origin["created_at"]) <= 64:
        raise KitError("Invalid encrypted-wallet origin timestamp")
    try:
        created = datetime.fromisoformat(origin["created_at"])
    except ValueError:
        raise KitError("Invalid encrypted-wallet origin timestamp") from None
    if created.tzinfo is None or created.utcoffset() is None:
        raise KitError("Encrypted-wallet origin timestamp requires a timezone")


def create(identifier: str, root: Path = ROOT, *, profile: str = RECOVERY_PROFILE) -> dict:
    _source_files(profile)
    sys.path.insert(0, str(root / "qlu"))
    import device_lab
    import recovery
    from devnet import secure_directory

    root = root.resolve()
    run, session, challenge = device_lab.read_session(root, device_lab.session_id(identifier))
    files = selected_sources(root, profile=profile)
    for name, path in SCRIPT_HASHES.items():
        if hashlib.sha256(files[path]).hexdigest() != session["origin_tooling"][name]:
            raise KitError("Recovery sources changed after session preparation")
    # These are the only session artifacts permitted into the source archive.
    files["transfer/backup.json"] = recovery.read_private(run / "transfer/backup.json")
    files["transfer/challenge.json"] = recovery.read_private(run / "transfer/challenge.json")
    files["NOTICE"] = NOTICE
    if profile == WALLET_PROFILE:
        origin_blob = recovery.read_private(run / "wallet-origin.json")
        origin = json.loads(origin_blob, object_pairs_hook=_pairs)
        _validate_wallet_origin(origin, session, challenge,
                                {path: hashlib.sha256(files[path]).hexdigest() for path in WALLET_SCRIPT_HASHES.values()})
        files["transfer/wallet-origin.json"] = origin_blob
        files["NOTICE"] += (b"\nProfile: encrypted-wallet-v1. Read docs/MACBOOK_WALLET_TEST.md.\n"
                            b"The encrypted origin vault and its local passphrase are absent.\n"
                            b"Create a new local encrypted vault and passphrase on the target.\n")
    records = {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
               for name, data in sorted(files.items())}
    manifest = {"format": "qlu-recovery-source-kit", "version": 1,
                "session_id": identifier, "purpose": session["purpose"],
                "network_id": session["network_id"], "genesis_hash": session["genesis_hash"],
                "challenge_sha256": session["challenge_sha256"], "backup_sha256": session["backup_sha256"],
                "source_commit": _git(root, "rev-parse", "HEAD").decode().strip(),
                "source_has_uncommitted_changes": bool(_git(root, "status", "--porcelain", "--untracked-files=normal")),
                "upstream": json.loads(files["qlu/upstream.json"]), "files": records}
    if profile == WALLET_PROFILE:
        manifest.update(profile=profile, wallet_origin_sha256=hashlib.sha256(origin_blob).hexdigest())
    files["KIT-MANIFEST.json"] = _canonical(manifest) + b"\n"
    base = root / ".local" / "device-kits"
    secure_directory(base)
    prefix = ("qlu-wallet-" if profile == WALLET_PROFILE else "qlu-recovery-") + identifier
    revision = hashlib.sha256(_canonical(manifest)).hexdigest()[:12]
    archive = base / (prefix + "-" + revision + ".tar.gz")
    directory_fd, basename = recovery._open_parent(archive)
    try:
        fd = os.open(basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as tar:
                        directories = {prefix}
                        for name in files:
                            for parent in PurePosixPath(prefix, name).parents:
                                if parent.as_posix() != ".":
                                    directories.add(parent.as_posix())
                        for name in sorted(directories):
                            info = tarfile.TarInfo(name); info.type = tarfile.DIRTYPE; info.mode = 0o700
                            tar.addfile(info)
                        for name, data in sorted(files.items()):
                            info = tarfile.TarInfo(prefix + "/" + name)
                            info.size = len(data); info.mode = 0o600
                            tar.addfile(info, io.BytesIO(data))
                stream.flush(); os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    recovery.write_private(base / (archive.name + ".sha256"), (digest + "  " + archive.name + "\n").encode())
    result = {"archive": str(archive), "sha256": digest, "bytes": archive.stat().st_size,
              "source_files": len(records), "session_id": identifier, "purpose": session["purpose"],
              "code_included": False, "native_binary_included": False,
              "physical_device_test_completed": False}
    if profile == WALLET_PROFILE:
        result.update(profile=profile, origin_vault_included=False, passphrase_included=False)
    return result


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise KitError("Duplicate manifest field")
        result[key] = value
    return result


def verify(directory: Path) -> dict:
    directory = directory.resolve()
    manifest = json.loads(_read(directory, "KIT-MANIFEST.json", MAX_MANIFEST_BYTES), object_pairs_hook=_pairs)
    if (type(manifest) is not dict or manifest.get("format") != "qlu-recovery-source-kit"
            or type(manifest.get("version")) is not int or manifest["version"] != 1
            or type(manifest.get("session_id")) is not str
            or re.fullmatch(r"[0-9a-f]{32}", manifest["session_id"]) is None):
        raise KitError("Unsupported kit manifest")
    profile = manifest.get("profile", RECOVERY_PROFILE)
    source_files = _source_files(profile)
    transfer_files = {"NOTICE", "transfer/backup.json", "transfer/challenge.json"}
    if profile == WALLET_PROFILE:
        transfer_files.add("transfer/wallet-origin.json")
    records = manifest.get("files")
    if type(records) is not dict or not 1 <= len(records) <= 2000:
        raise KitError("Invalid kit file count")
    if not set(source_files).issubset(records) or not transfer_files.issubset(records):
        raise KitError("Required kit sources or transfer files are missing")
    # This command deliberately requires a pristine extraction, before a build
    # or Python imports create extra files. Unlisted .py/.pyc files could shadow
    # reviewed modules even when every manifest-listed source is unchanged.
    expected = set(records) | {"KIT-MANIFEST.json"}
    actual = set()
    for directory_name, directories, filenames in os.walk(directory, followlinks=False):
        parent = Path(directory_name)
        if any((parent / name).is_symlink() for name in directories):
            raise KitError("Unlisted or linked directory in source kit")
        for name in filenames:
            actual.add((parent / name).relative_to(directory).as_posix())
    if actual != expected:
        raise KitError("Source kit must be a pristine extraction without extra files")
    total = 0
    for name, record in records.items():
        _safe_name(name)
        if (name not in source_files and name not in transfer_files
                and not any(name.startswith(tree + "/") for tree in SOURCE_TREES)):
            raise KitError("Unexpected source path in manifest")
        if (type(record) is not dict or record.keys() != {"sha256", "bytes"}
                or type(record["bytes"]) is not int or not 0 <= record["bytes"] <= MAX_FILE_BYTES):
            raise KitError("Invalid source record")
        data = _read(directory, name)
        if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise KitError("Kit source fingerprint mismatch")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise KitError("Kit exceeded total size limit")
    backup = _read(directory, "transfer/backup.json")
    challenge = json.loads(_read(directory, "transfer/challenge.json"), object_pairs_hook=_pairs)
    if (type(challenge) is not dict or hashlib.sha256(backup).hexdigest() != manifest.get("backup_sha256")
            or hashlib.sha256(_canonical(challenge)).hexdigest() != manifest.get("challenge_sha256")
            or challenge.get("challenge_id") != manifest["session_id"]):
        raise KitError("Transfer files do not match manifest")
    if profile == WALLET_PROFILE:
        origin_blob = _read(directory, "transfer/wallet-origin.json", 8192)
        if hashlib.sha256(origin_blob).hexdigest() != manifest.get("wallet_origin_sha256"):
            raise KitError("Encrypted-wallet origin fingerprint does not match manifest")
        origin = json.loads(origin_blob, object_pairs_hook=_pairs)
        _validate_wallet_origin(origin, manifest, challenge,
                                {path: records[path]["sha256"] for path in WALLET_SCRIPT_HASHES.values()})
    result = {"verified": True, "session_id": manifest["session_id"], "files": len(records),
              "bytes": total, "scope": "File integrity only; compare archive SHA256 to the separate origin handoff first"}
    if profile == WALLET_PROFILE:
        result["profile"] = profile
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("create"); build.add_argument("--session", required=True)
    build.add_argument("--profile", choices=(RECOVERY_PROFILE, WALLET_PROFILE), default=RECOVERY_PROFILE)
    check = sub.add_parser("verify"); check.add_argument("--directory", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        result = create(args.session, profile=args.profile) if args.command == "create" else verify(args.directory)
        print(_canonical(result).decode())
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        print("QLU source kit failed: " + type(error).__name__ + ". Check source, session, file integrity, and permissions.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
