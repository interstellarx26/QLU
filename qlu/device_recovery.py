#!/usr/bin/env python3
"""Offline, disposable QLU recovery challenge on a second physical computer.

This is test tooling, not a consumer signing interface. It only signs an exact,
one-input/one-output qludev transfer with the fixed laboratory fee. A response
proves access to restored signing keys once the node accepts it; its device mode
is an operator statement, not remote hardware attestation. Never package the
recovery code with the encrypted backup. No seed or restored wallet is written.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol
import recovery
from test_framework.messages import CTransaction, CTxOut, ser_compact_size

MAX_DOCUMENT_BYTES = 32768
FEE_SAT = 100000
MAX_INPUT_SAT = 50 * 100000000
CHALLENGE_FIELDS = {"format", "version", "challenge_id", "network_id", "genesis_hash",
                    "wallet_commitment", "unsigned_tx", "previous_output", "recipient", "fee_sat"}
RESPONSE_FIELDS = {"format", "version", "challenge_id", "challenge_sha256", "network_id",
                   "genesis_hash", "wallet_commitment", "signed_tx", "txid", "mode",
                   "device", "tooling", "timing_seconds"}
TOOLING_FIELDS = {"device_recovery_sha256", "protocol_sha256", "recovery_sha256", "keytool_sha256"}
MODES = ("rehearsal", "physical-device")


class DeviceRecoveryError(ValueError):
    """A public challenge or response is invalid."""


def _hex(value, length: int) -> bytes:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{" + str(length * 2) + r"}", value) is None:
        raise DeviceRecoveryError("Invalid fixed-length hexadecimal field")
    return bytes.fromhex(value)


def _fields(value, names: set[str]) -> None:
    if type(value) is not dict or value.keys() != names:
        raise DeviceRecoveryError("Unsupported document fields")


def _integer(value, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DeviceRecoveryError("Invalid integer field")
    return value


def _script(value) -> bytes:
    script = _hex(value, 34)
    if script[:2] != b"\x52\x20":
        raise DeviceRecoveryError("Only hybrid QLU output scripts are supported")
    return script


def validate_challenge(challenge: dict) -> tuple[CTransaction, CTxOut]:
    """Strictly parse the entire unsigned transfer before touching wallet secrets.

    Reconstructing the expected serialization avoids interpreting attacker-chosen
    vector lengths, witness markers, extra outputs, or trailing transaction data.
    The actual previous-output existence and value are rechecked by the origin
    node. Offline signing alone cannot independently establish blockchain state.
    """
    _fields(challenge, CHALLENGE_FIELDS)
    if challenge["format"] != "qlu-device-recovery-challenge" or _integer(challenge["version"], 1, 1) != 1:
        raise DeviceRecoveryError("Unsupported challenge format")
    _hex(challenge["challenge_id"], 16)
    if challenge["network_id"] != protocol.NETWORK or challenge["genesis_hash"] != protocol.GENESIS:
        raise DeviceRecoveryError("Only the QLU private development chain is accepted")
    commitment = _hex(challenge["wallet_commitment"], 32)
    previous, recipient = challenge["previous_output"], challenge["recipient"]
    _fields(previous, {"txid", "vout", "value_sat", "script_pubkey"})
    _fields(recipient, {"value_sat", "script_pubkey"})
    txid = _hex(previous["txid"], 32)
    vout = _integer(previous["vout"], 0, 2**32 - 2)
    if txid == bytes(32):
        raise DeviceRecoveryError("Null previous transaction is not accepted")
    value = _integer(previous["value_sat"], FEE_SAT + 1, MAX_INPUT_SAT)
    destination_value = _integer(recipient["value_sat"], 1, MAX_INPUT_SAT)
    source_script = _script(previous["script_pubkey"])
    destination_script = _script(recipient["script_pubkey"])
    if source_script != b"\x52\x20" + commitment:
        raise DeviceRecoveryError("Previous output does not match wallet commitment")
    if source_script == destination_script:
        raise DeviceRecoveryError("Recovery drill must pay a separate recipient")
    _integer(challenge["fee_sat"], FEE_SAT, FEE_SAT)
    if value - destination_value != FEE_SAT:
        raise DeviceRecoveryError("Unexpected payment amount or fee")
    raw = _hex(challenge["unsigned_tx"], 94)
    expected = (b"\x02\x00\x00\x00\x01" + txid[::-1] + vout.to_bytes(4, "little")
                + b"\x00\xff\xff\xff\xff\x01" + destination_value.to_bytes(8, "little")
                + b"\x22" + destination_script + bytes(4))
    if raw != expected:
        raise DeviceRecoveryError("Transaction does not exactly match the approved challenge")
    tx = CTransaction()
    tx.deserialize(io.BytesIO(raw))
    return tx, CTxOut(value, source_script)


def challenge_hash(challenge: dict) -> str:
    validate_challenge(challenge)
    return hashlib.sha256(recovery._canonical(challenge)).hexdigest()


def make_challenge(tx: CTransaction, previous: CTxOut, wallet_commitment: str,
                   challenge_id: str | None = None) -> dict:
    if len(tx.vin) != 1 or len(tx.vout) != 1 or not tx.wit.is_null():
        raise DeviceRecoveryError("Expected one unsigned input and one output")
    challenge = {
        "format": "qlu-device-recovery-challenge", "version": 1,
        "challenge_id": secrets.token_hex(16) if challenge_id is None else challenge_id,
        "network_id": protocol.NETWORK, "genesis_hash": protocol.GENESIS,
        "wallet_commitment": wallet_commitment,
        "unsigned_tx": tx.serialize_without_witness().hex(),
        "previous_output": {"txid": f"{tx.vin[0].prevout.hash:064x}", "vout": tx.vin[0].prevout.n,
                            "value_sat": previous.nValue, "script_pubkey": previous.scriptPubKey.hex()},
        "recipient": {"value_sat": tx.vout[0].nValue, "script_pubkey": tx.vout[0].scriptPubKey.hex()},
        "fee_sat": previous.nValue - tx.vout[0].nValue,
    }
    validate_challenge(challenge)
    return challenge


def _device() -> dict:
    # No hostname, serial number, username, MAC address, or stable device ID.
    return {"system": platform.system(), "release": platform.release(),
            "machine": platform.machine(), "python": platform.python_version()}


def _tooling() -> dict:
    files = {"device_recovery_sha256": Path(__file__), "protocol_sha256": Path(protocol.__file__),
             "recovery_sha256": Path(recovery.__file__),
             "keytool_sha256": protocol.ROOT / "build/qlu-foundation/bin/qlu-keytool"}
    result = {}
    for name, path in files.items():
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[name] = digest.hexdigest()
    return result


def respond(backup: bytes, code: str, challenge: dict, *, mode: str = "rehearsal") -> dict:
    """Restore in memory and sign; physical-device is a human attestation only."""
    tx, previous = validate_challenge(challenge)
    if mode not in MODES:
        raise DeviceRecoveryError("Unsupported test mode")
    start = time.perf_counter()
    wallet = recovery.restore_backup(backup, code, protocol.NETWORK, protocol.GENESIS)
    restored_at = time.perf_counter()
    keys = protocol.keytool(wallet)
    if keys["key_commitment"] != challenge["wallet_commitment"]:
        raise DeviceRecoveryError("Recovered wallet does not match this challenge")
    signed = protocol.sign_transaction(wallet, tx, [previous])
    end = time.perf_counter()
    result = {
        "format": "qlu-device-recovery-response", "version": 1,
        "challenge_id": challenge["challenge_id"], "challenge_sha256": challenge_hash(challenge),
        "network_id": protocol.NETWORK, "genesis_hash": protocol.GENESIS,
        "wallet_commitment": keys["key_commitment"], "signed_tx": signed.serialize_with_witness().hex(),
        "txid": signed.txid_hex, "mode": mode, "device": _device(), "tooling": _tooling(),
        "timing_seconds": {"backup_decryption": restored_at - start,
                           "key_derivation_and_signing": end - restored_at},
    }
    validate_response(result, challenge)
    return result


def validate_response(response: dict, challenge: dict) -> CTransaction:
    """Bind a response to its exact challenge; node consensus verifies signatures."""
    unsigned, _ = validate_challenge(challenge)
    _fields(response, RESPONSE_FIELDS)
    if response["format"] != "qlu-device-recovery-response" or _integer(response["version"], 1, 1) != 1:
        raise DeviceRecoveryError("Unsupported response format")
    for field in ("challenge_id", "network_id", "genesis_hash", "wallet_commitment"):
        if response[field] != challenge[field]:
            raise DeviceRecoveryError("Response belongs to another challenge")
    if response["challenge_sha256"] != challenge_hash(challenge):
        raise DeviceRecoveryError("Response challenge fingerprint does not match")
    if response["mode"] not in MODES:
        raise DeviceRecoveryError("Unsupported test mode")
    _fields(response["device"], {"system", "release", "machine", "python"})
    for value in response["device"].values():
        if type(value) is not str or not 1 <= len(value) <= 128 or not value.isascii() or not value.isprintable():
            raise DeviceRecoveryError("Invalid public platform metadata")
    _fields(response["tooling"], TOOLING_FIELDS)
    for value in response["tooling"].values():
        _hex(value, 32)
    _fields(response["timing_seconds"], {"backup_decryption", "key_derivation_and_signing"})
    for value in response["timing_seconds"].values():
        if type(value) not in (int, float) or not 0 <= value <= 300:
            raise DeviceRecoveryError("Invalid timing metadata")
    # Known exact witness layout, including canonical CompactSize encodings.
    base = unsigned.serialize_without_witness()
    lengths = (1952, 32, 3309, 64)
    prefix = base[:4] + b"\x00\x01" + base[4:-4] + b"\x04"
    size = len(prefix) + sum(len(ser_compact_size(n)) + n for n in lengths) + 4
    raw = _hex(response["signed_tx"], size)
    if not raw.startswith(prefix) or raw[-4:] != bytes(4):
        raise DeviceRecoveryError("Signed transaction differs from challenge")
    cursor = len(prefix)
    witness = []
    for length in lengths:
        encoding = ser_compact_size(length)
        if raw[cursor:cursor + len(encoding)] != encoding:
            raise DeviceRecoveryError("Invalid hybrid witness encoding")
        cursor += len(encoding)
        witness.append(raw[cursor:cursor + length])
        cursor += length
    tag = hashlib.sha256(b"QLU/key-commitment/v1").digest()
    commitment = hashlib.sha256(tag + tag + b"\x01" + witness[0] + witness[1]).hexdigest()
    if commitment != challenge["wallet_commitment"]:
        raise DeviceRecoveryError("Signed transaction uses another wallet")
    signed = CTransaction()
    signed.deserialize(io.BytesIO(raw))
    if response["txid"] != signed.txid_hex:
        raise DeviceRecoveryError("Response transaction ID mismatch")
    return signed


def read_document(path: str | Path) -> dict:
    """Read bounded JSON with the recovery file ownership/link restrictions."""
    directory_fd, name = recovery._open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or not 1 <= info.st_size <= MAX_DOCUMENT_BYTES):
                raise DeviceRecoveryError("Document must be a private, single-link, bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                blob = stream.read(MAX_DOCUMENT_BYTES + 1)
            return recovery._parse(blob, MAX_DOCUMENT_BYTES)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def write_document(path: str | Path, document: dict) -> None:
    """Create public test evidence exclusively; never overwrite existing files."""
    blob = recovery._canonical(document) + b"\n"
    if not 1 <= len(blob) <= MAX_DOCUMENT_BYTES:
        raise DeviceRecoveryError("Document too large")
    directory_fd, name = recovery._open_parent(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(blob)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    answer = sub.add_parser("respond", help="Restore disposable test keys and return a signed private-chain payment")
    answer.add_argument("--backup", required=True)
    answer.add_argument("--challenge", required=True)
    answer.add_argument("--response", required=True)
    answer.add_argument("--code-file", help="Separate offline code file; omitted to enter the code without echo")
    answer.add_argument("--mode", choices=MODES, default="rehearsal",
                        help="physical-device states you are running on a different physical computer; not hardware attestation")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise DeviceRecoveryError("Use macOS, Linux, or WSL with a private Linux filesystem")
        challenge = read_document(args.challenge)
        validate_challenge(challenge)
        print("QLU private test only; these coins have no monetary value.")
        print(f"Challenge: {challenge['challenge_id']}")
        print(f"Recipient script: {challenge['recipient']['script_pubkey']}")
        print(f"Amount: {challenge['recipient']['value_sat'] / 100000000:.8f} QLU; fee: {FEE_SAT / 100000000:.8f} QLU")
        if args.mode == "physical-device":
            print("You attest this is a separate physical computer. Platform details alone cannot prove that.")
        else:
            print("REHEARSAL: this result is not a completed second-device test.")
        if args.code_file:
            code = recovery.read_private(args.code_file, recovery.MAX_CODE_BYTES).decode("ascii")
        else:
            # Refuse redirected input rather than risk getpass's echoing fallback.
            if not sys.stdin.isatty():
                raise DeviceRecoveryError("Enter recovery code in a terminal or use a separate private code file")
            code = getpass.getpass("Separate recovery code (hidden): ")
        response = respond(recovery.read_private(args.backup), code, challenge, mode=args.mode)
        write_document(args.response, response)
        print("Response saved. Return only the response file to the original computer for chain verification.")
        print("No restored wallet or seed was written. This process has not broadcast a payment.")
        return 0
    except (DeviceRecoveryError, recovery.RecoveryError, OSError, UnicodeError, RuntimeError,
            ValueError, KeyError, EOFError, subprocess.SubprocessError):
        print("Recovery challenge failed. Check the private files, network, code, and native key-tool build. Existing files are never overwritten.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
