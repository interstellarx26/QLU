#!/usr/bin/env python3
"""Origin coordinator for fresh encrypted-wallet physical-device trials.

Legacy funding, challenge formats and node verification remain unchanged.
Only valueless private-network coins are used. This module never prints codes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_lab
import device_recovery as device
import protocol
import recovery
from vault import WalletSession
import wallet_device

PROFILE = "encrypted-wallet-v1"
WALLET_SOURCES = {"vault_sha256": "qlu/vault.py", "wallet_sha256": "qlu/wallet.py",
                  "wallet_device_sha256": "qlu/wallet_device.py"}
ORIGIN_FIELDS = {"format", "version", "session_id", "purpose", "network_id", "genesis_hash",
                 "challenge_sha256", "backup_sha256", "wallet_commitment", "tooling",
                 "origin_vault_sha256", "origin_checks", "created_at"}


def tooling(root: Path = protocol.ROOT) -> dict:
    return {key: hashlib.sha256((root / path).read_bytes()).hexdigest()
            for key, path in WALLET_SOURCES.items()}


def prepare(root: Path = protocol.ROOT, *, rehearsal: bool = False) -> dict:
    # Generates fresh authority in memory and a portable encrypted backup;
    # the legacy coordinator never saves that wallet seed as plaintext.
    prepared = device_lab.prepare(root, rehearsal=rehearsal)
    run, manifest, challenge = device_lab.read_session(root, prepared["session_id"])
    session = None
    try:
        backup = recovery.read_private(run / "transfer/backup.json")
        code = recovery.read_private(run / "offline/code.txt", recovery.MAX_CODE_BYTES).decode("ascii")
        passphrase = secrets.token_urlsafe(32)
        origin_path = run / "origin.vault.json"
        session = WalletSession.restore(origin_path, backup, code, passphrase)
        session.lock()
        session = WalletSession(origin_path)
        if not session.locked:
            raise ValueError("New origin session is not locked")
        session.unlock(passphrase)
        if session.public_keys()["key_commitment"] != challenge["wallet_commitment"]:
            raise ValueError("Encrypted origin identity changed")
        if session.verify_backup(backup, code) is not True:
            raise ValueError("Origin backup mismatch")
        session.lock()
        del code, passphrase, backup
        origin = {"format": "qlu-wallet-device-origin", "version": 1,
                  "session_id": prepared["session_id"], "purpose": manifest["purpose"],
                  "network_id": protocol.NETWORK, "genesis_hash": protocol.GENESIS,
                  "challenge_sha256": manifest["challenge_sha256"], "backup_sha256": manifest["backup_sha256"],
                  "wallet_commitment": challenge["wallet_commitment"], "tooling": tooling(root),
                  "origin_vault_sha256": hashlib.sha256(recovery.read_private(origin_path)).hexdigest(),
                  "origin_checks": {"encrypted_reopen_same_identity": True, "portable_backup_verified": True},
                  "created_at": datetime.now(timezone.utc).isoformat()}
        device.write_document(run / "wallet-origin.json", origin)
        prepared.update(profile=PROFILE, wallet_origin=str(run / "wallet-origin.json"),
                        wallet_test_completed=False, status="awaiting-wallet-response")
        return prepared
    finally:
        if session is not None:
            session.lock()


def read_origin(identifier: str, root: Path = protocol.ROOT) -> tuple[Path, dict, dict, dict]:
    run, manifest, challenge = device_lab.read_session(root, device_lab.session_id(identifier))
    origin = device.read_document(run / "wallet-origin.json")
    if (origin.keys() != ORIGIN_FIELDS or origin["format"] != "qlu-wallet-device-origin"
            or type(origin["version"]) is not int or origin["version"] != 1):
        raise ValueError("Invalid wallet origin profile")
    for field in ("session_id", "purpose", "network_id", "genesis_hash", "challenge_sha256", "backup_sha256"):
        if origin[field] != manifest[field]:
            raise ValueError("Wallet origin identity mismatch")
    if origin["wallet_commitment"] != challenge["wallet_commitment"]:
        raise ValueError("Wallet origin commitment mismatch")
    if (type(origin["tooling"]) is not dict or origin["tooling"].keys() != WALLET_SOURCES.keys()
            or origin["tooling"] != tooling(root)):
        raise ValueError("Wallet sources changed since preparation")
    device._hex(origin["origin_vault_sha256"], 32)
    if hashlib.sha256(recovery.read_private(run / "origin.vault.json")).hexdigest() != origin["origin_vault_sha256"]:
        raise ValueError("Encrypted origin vault changed")
    checks = origin["origin_checks"]
    if (type(checks) is not dict or checks.keys() != {"encrypted_reopen_same_identity", "portable_backup_verified"}
            or any(value is not True for value in checks.values())):
        raise ValueError("Origin checks are incomplete")
    if type(origin["created_at"]) is not str or not 1 <= len(origin["created_at"]) <= 64:
        raise ValueError("Invalid origin creation time")
    if datetime.fromisoformat(origin["created_at"]).tzinfo is None:
        raise ValueError("Origin creation time must include its timezone")
    return run, manifest, challenge, origin


def _canonical_hash(document: dict) -> str:
    return hashlib.sha256(recovery._canonical(document)).hexdigest()


def _save_same(path: Path, document: dict) -> None:
    """Retry only identical public evidence; never replace another response."""
    if path.exists():
        if device.read_document(path) != document:
            raise ValueError("A different wallet response is already recorded")
    else:
        device.write_document(path, document)


def _validate_receipt(receipt: dict, identifier: str, manifest: dict, response: dict,
                      physical_attestation: bool):
    if (receipt.get("passed") is not True or receipt.get("session_id") != identifier
            or receipt.get("purpose") != manifest["purpose"]
            or receipt.get("signed_payment_confirmed_on_four_nodes") is not True
            or receipt.get("nodes") != "stopped"
            or receipt.get("physical_device_operator_attested") is not physical_attestation
            or receipt.get("hardware_attestation") is not False
            or receipt.get("challenge_sha256") != manifest["challenge_sha256"]
            or receipt.get("response_sha256") != _canonical_hash(response)
            or receipt.get("txid") != response["txid"]):
        raise ValueError("Existing chain receipt does not match this exact response")


def check(identifier: str, response_path: Path, root: Path = protocol.ROOT, *, physical_attestation: bool = False,
          allow_broadcast: bool = True) -> dict:
    run, manifest, challenge, origin = read_origin(identifier, root)
    envelope = device.read_document(response_path)
    wallet_device.validate_result(envelope, challenge)
    response = envelope["response"]
    device_lab.authorize_mode(manifest, response, physical_attestation)
    if envelope["wallet_test"]["tooling"] != origin["tooling"]:
        raise ValueError("Target used different encrypted-wallet sources")
    # Preserve the exact outer/inner public evidence before any broadcast. A
    # retry can complete a wrapper receipt only for precisely this response.
    saved = run / "results/wallet-response.json"
    nested = run / "results/wallet-payment-response.json"
    if (run / "receipt.json").exists():
        if not saved.exists() or not nested.exists():
            raise ValueError("Missing prior wallet response evidence")
        if device.read_document(saved) != envelope or device.read_document(nested) != response:
            raise ValueError("A different response already completed this challenge")
        receipt = device.read_document(run / "receipt.json")
    else:
        if not allow_broadcast:
            raise ValueError("Read-only status requires an existing chain receipt")
        _save_same(saved, envelope)
        _save_same(nested, response)
        receipt = device_lab.check(identifier, nested, root, physical_attestation=physical_attestation)
    _validate_receipt(receipt, identifier, manifest, response, physical_attestation)
    result = {"format": "qlu-wallet-device-receipt", "version": 1, "passed": True,
              "profile": PROFILE, "session_id": identifier, "purpose": manifest["purpose"],
              "wallet_response_sha256": _canonical_hash(envelope), "wallet_test": envelope["wallet_test"],
              "origin_checks": origin["origin_checks"], "chain_receipt": receipt,
              "physical_device_operator_attested": physical_attestation,
              "hardware_attestation": False, "nodes": "stopped",
              "scope": "Valid recovered-key payment; device, timings and wallet checks are operator/self-reported"}
    _save_same(run / "wallet-receipt.json", result)
    return result


def rehearse(root: Path = protocol.ROOT) -> dict:
    prepared = prepare(root, rehearsal=True)
    run, _, challenge, _ = read_origin(prepared["session_id"], root)
    code = recovery.read_private(run / "offline/code.txt", recovery.MAX_CODE_BYTES).decode("ascii")
    result = wallet_device.recover_sign(recovery.read_private(run / "transfer/backup.json"), code,
                                        secrets.token_urlsafe(32), challenge, run / "rehearsal.vault.json",
                                        mode="rehearsal", idle_seconds=0.05)
    del code
    response = run / "wallet-rehearsal-response.json"
    device.write_document(response, result)
    return check(prepared["session_id"], response, root)


def status(identifier: str, root: Path = protocol.ROOT) -> dict:
    run, manifest, _, _ = read_origin(identifier, root)
    result = {"session_id": identifier, "purpose": manifest["purpose"], "profile": PROFILE,
              "status": "awaiting-wallet-response", "physical_device_completed": False}
    if (run / "wallet-receipt.json").exists():
        # Revalidate the exact recorded response and both receipts without
        # starting nodes. check's existing-receipt branch cannot rebroadcast.
        receipt = check(identifier, run / "results/wallet-response.json", root,
                        physical_attestation=manifest["purpose"] == "physical-device", allow_broadcast=False)
        result.update(status="passed", receipt=receipt,
                      physical_device_completed=manifest["purpose"] == "physical-device")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare")
    sub.add_parser("rehearse")
    inspect = sub.add_parser("status"); inspect.add_argument("--session", required=True)
    verify = sub.add_parser("check")
    verify.add_argument("--session", required=True)
    verify.add_argument("--response", type=Path, required=True)
    verify.add_argument("--physical-device", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare": result = prepare()
        elif args.command == "rehearse": result = rehearse()
        elif args.command == "status": result = status(args.session)
        else: result = check(args.session, args.response, physical_attestation=args.physical_device)
        print(recovery._canonical(result).decode())
        return 0
    except (Exception, KeyboardInterrupt):
        print("QLU encrypted-wallet device test failed. Existing files were preserved; inspect its public session evidence.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
