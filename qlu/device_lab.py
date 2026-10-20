#!/usr/bin/env python3
"""Origin-computer coordinator for disposable, offline QLU recovery drills.

Each session owns a fresh four-node loopback development chain. Public transfer
files and the separate recovery code live in ignored .local storage. No live
wallet or existing chain is reused, reset, or erased. Physical-device completion
requires a returned signature and explicit operator attestation; software cannot
prove that the response was made on a second physical computer.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_recovery as device
import protocol
import recovery
from devnet import DevnetError, NODE_COUNT, PROJECT, secure_directory
from lab import private_port_lock as port_lock
from private_net import QLUPrivateNet
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut

SESSION_RE = re.compile(r"[0-9a-f]{32}")
FUNDING_SAT = 100000000
MANIFEST_FIELDS = {"format", "version", "session_id", "purpose", "network_id", "genesis_hash",
                   "created_at", "challenge_sha256", "backup_sha256", "controller_data_name",
                   "funding_txid", "funding_block", "mining_address", "origin_device",
                   "node_binary_sha256", "keytool_sha256", "origin_tooling"}


def session_id(value: str) -> str:
    if type(value) is not str or SESSION_RE.fullmatch(value) is None:
        raise DevnetError("Session must be a 32-character lowercase hexadecimal identifier")
    return value


def session_path(root: Path, identifier: str) -> Path:
    return root.resolve() / ".local" / "device-tests" / session_id(identifier)


class DeviceNet(QLUPrivateNet):
    def __init__(self, identifier: str, root: Path = PROJECT):
        identifier = session_id(identifier)
        self.data_name = "device-" + identifier
        self.process_label = "QLUDevice-" + identifier
        super().__init__(root)


@contextmanager
def running(controller: DeviceNet):
    controller.setup()
    controller.require_binaries()
    controller.require_stopped()
    controller.start()  # Controller cleans up its own partial starts on failure.
    try:
        controller.wait_synced()
        yield controller
    finally:
        controller.stop()
        if any(item["status"] != "stopped" for item in controller.status()):
            raise DevnetError("Recovery test nodes did not all stop")


def satoshis(value) -> int:
    amount = Decimal(str(value)) * 100000000
    if not amount.is_finite() or amount != amount.to_integral_value() or amount < 0:
        raise DevnetError("Node returned an invalid coin amount")
    return int(amount)


def rpc_null(value) -> bool:
    """bitcoin-cli prints JSON null as empty stdout; the controller preserves it."""
    return value is None or (type(value) is str and value == "")


def make_session(root: Path, identifier: str) -> Path:
    local = root.resolve() / ".local"
    secure_directory(local)
    base = local / "device-tests"
    secure_directory(base)
    run = session_path(root, identifier)
    run.mkdir(mode=0o700, exist_ok=False)
    for directory in ("transfer", "offline", "results"):
        secure_directory(run / directory)
    return run


def read_session(root: Path, identifier: str) -> tuple[Path, dict, dict]:
    run = session_path(root, identifier)
    manifest = device.read_document(run / "manifest.json")
    if manifest.keys() != MANIFEST_FIELDS:
        raise DevnetError("Unsupported recovery session manifest")
    if (manifest["format"] != "qlu-device-lab" or type(manifest["version"]) is not int
            or manifest["version"] != 1 or manifest["session_id"] != identifier
            or manifest["purpose"] not in device.MODES
            or manifest["network_id"] != protocol.NETWORK or manifest["genesis_hash"] != protocol.GENESIS
            or manifest["controller_data_name"] != "device-" + identifier):
        raise DevnetError("Recovery session identity does not match")
    hashes = ("challenge_sha256", "backup_sha256", "node_binary_sha256", "keytool_sha256")
    tooling = manifest["origin_tooling"]
    if (type(tooling) is not dict or tooling.keys() != {"device_recovery_sha256", "protocol_sha256", "recovery_sha256", "keytool_sha256"}
            or any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
                   for value in [manifest[name] for name in hashes] + list(tooling.values()))):
        raise DevnetError("Invalid recovery session provenance")
    challenge = device.read_document(run / "transfer/challenge.json")
    device.validate_challenge(challenge)
    if (challenge["challenge_id"] != identifier or device.challenge_hash(challenge) != manifest["challenge_sha256"]
            or challenge["previous_output"]["txid"] != manifest["funding_txid"]):
        raise DevnetError("Recovery challenge changed after preparation")
    if hashlib.sha256(recovery.read_private(run / "transfer/backup.json")).hexdigest() != manifest["backup_sha256"]:
        raise DevnetError("Recovery backup changed after preparation")
    return run, manifest, challenge


def _public_paths(root: Path, identifier: str) -> dict:
    run = session_path(root, identifier)
    return {"session_id": identifier, "transfer_directory": str(run / "transfer"),
            "separate_code_file": str(run / "offline/code.txt"),
            "manifest": str(run / "manifest.json")}


def prepare(root: Path = PROJECT, *, rehearsal: bool = False) -> dict:
    root = root.resolve()
    identifier = uuid.uuid4().hex
    with port_lock(root):
        run = make_session(root, identifier)
        controller = DeviceNet(identifier, root)
        try:
            with running(controller):
                if controller.rpc(0, "getblockcount") != 0:
                    raise DevnetError("New recovery session chain was not empty")
                sender = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
                recipient = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
                sink = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
                sender_keys, recipient_keys, sink_keys = [protocol.keytool(w) for w in (sender, recipient, sink)]
                mining_address = protocol.address_for(sender_keys)
                blocks = controller.rpc(0, "generatetoaddress", 101, mining_address)
                controller.wait_synced(blocks[-1])
                coinbase = controller.rpc(0, "getblock", blocks[0], 2)["tx"][0]
                coin = coinbase["vout"][0]
                previous = CTxOut(satoshis(coin["value"]), bytes.fromhex(coin["scriptPubKey"]["hex"]))
                if previous.scriptPubKey != protocol.script_for(sender_keys) or previous.nValue <= FUNDING_SAT + device.FEE_SAT:
                    raise DevnetError("Unexpected fresh development-chain reward")
                funding = CTransaction()
                funding.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), nSequence=0xffffffff)]
                funding.vout = [CTxOut(FUNDING_SAT, protocol.script_for(recipient_keys)),
                                CTxOut(previous.nValue - FUNDING_SAT - device.FEE_SAT, protocol.script_for(sender_keys))]
                signed = protocol.sign_transaction(sender, funding, [previous])
                funding_txid = controller.rpc(0, "sendrawtransaction", signed.serialize_with_witness().hex())
                funding_block = controller.rpc(0, "generateblock", mining_address, [signed.serialize_with_witness().hex()])["hash"]
                controller.wait_synced(funding_block)
                for node in range(NODE_COUNT):
                    actual = controller.rpc(node, "gettxout", funding_txid, 0)
                    if (not actual or actual["confirmations"] < 1 or satoshis(actual["value"]) != FUNDING_SAT
                            or actual["scriptPubKey"]["hex"] != funding.vout[0].scriptPubKey.hex()):
                        raise DevnetError("Recovery test funding did not confirm on every node")
                transaction = CTransaction()
                transaction.vin = [CTxIn(COutPoint(int(funding_txid, 16), 0), nSequence=0xffffffff)]
                transaction.vout = [CTxOut(FUNDING_SAT - device.FEE_SAT, protocol.script_for(sink_keys))]
                challenge = device.make_challenge(transaction, funding.vout[0], recipient_keys["key_commitment"], identifier)
                backup, code = recovery.make_backup(recipient)
                recovery.write_private(run / "transfer/backup.json", backup)
                recovery.write_private(run / "offline/code.txt", (code + "\n").encode())
                device.write_document(run / "transfer/challenge.json", challenge)
                manifest = {"format": "qlu-device-lab", "version": 1, "session_id": identifier,
                            "purpose": "rehearsal" if rehearsal else "physical-device",
                            "network_id": protocol.NETWORK, "genesis_hash": protocol.GENESIS,
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "challenge_sha256": device.challenge_hash(challenge),
                            "backup_sha256": hashlib.sha256(backup).hexdigest(),
                            "controller_data_name": controller.data_name, "funding_txid": funding_txid,
                            "funding_block": funding_block, "mining_address": mining_address,
                            "origin_device": device._device(),
                            "origin_tooling": device._tooling(),
                            "node_binary_sha256": controller.file_sha256(controller.binary),
                            "keytool_sha256": controller.file_sha256(root / "build/qlu-foundation/bin/qlu-keytool")}
                del sender, recipient, sink, code, backup  # Python cannot guarantee memory erasure.
            device.write_document(run / "manifest.json", manifest)
            result = _public_paths(root, identifier)
            result.update(status="awaiting-response", purpose=manifest["purpose"], nodes="stopped",
                          physical_device_completed=False, test_funding_qlu="1.00000000")
            return result
        except BaseException as error:
            device.write_document(run / "results/prepare-failure.json", {
                "passed": False, "session_id": identifier, "error": controller.error_summary(error)})
            raise


def authorize_mode(manifest: dict, response: dict, physical_attestation: bool) -> str:
    purpose = manifest["purpose"]
    if response["mode"] != purpose:
        raise DevnetError("Rehearsal and physical-device sessions cannot be interchanged")
    if purpose == "physical-device" and not physical_attestation:
        raise DevnetError("Physical-device check requires explicit confirmation that a separate computer produced the response")
    if purpose == "rehearsal" and physical_attestation:
        raise DevnetError("A same-host rehearsal cannot be relabeled as a physical-device test")
    return purpose


def check(identifier: str, response_path: Path, root: Path = PROJECT, *, physical_attestation: bool = False) -> dict:
    root = root.resolve()
    identifier = session_id(identifier)
    with port_lock(root):
        run, manifest, challenge = read_session(root, identifier)
        if (run / "receipt.json").exists():
            raise DevnetError("This recovery session already has a completed receipt")
        response = device.read_document(response_path)
        transaction = device.validate_response(response, challenge)
        purpose = authorize_mode(manifest, response, physical_attestation)
        controller = DeviceNet(identifier, root)
        current_tooling = device._tooling()
        for name in ("device_recovery_sha256", "protocol_sha256", "recovery_sha256"):
            if response["tooling"][name] != manifest["origin_tooling"][name] or current_tooling[name] != manifest["origin_tooling"][name]:
                raise DevnetError("Response used different recovery scripts from the prepared transfer kit")
        if (controller.file_sha256(controller.binary) != manifest["node_binary_sha256"]
                or controller.file_sha256(root / "build/qlu-foundation/bin/qlu-keytool") != manifest["keytool_sha256"]):
            raise DevnetError("Origin binaries changed since preparation; use the matching prepared build before checking this session")
        attempt = uuid.uuid4().hex
        try:
            with running(controller):
                if not controller.rpc(0, "validateaddress", manifest["mining_address"]).get("isvalid"):
                    raise DevnetError("Invalid session mining address")
                funded = challenge["previous_output"]
                for node in range(NODE_COUNT):
                    previous = controller.rpc(node, "gettxout", funded["txid"], funded["vout"])
                    if (not previous or previous["confirmations"] < 1
                            or satoshis(previous["value"]) != funded["value_sat"]
                            or previous["scriptPubKey"]["hex"] != funded["script_pubkey"]):
                        raise DevnetError("Prepared recovery output is missing, spent, or changed")
                raw = transaction.serialize_with_witness().hex()
                for node in range(NODE_COUNT):
                    accepted = controller.rpc(node, "testmempoolaccept", [raw])[0]
                    if accepted.get("allowed") is not True:
                        raise DevnetError("A node rejected the recovered-key signature")
                txid = controller.rpc(0, "sendrawtransaction", raw)
                if txid != response["txid"]:
                    raise DevnetError("Node returned a different transaction identifier")
                block = controller.rpc(0, "generateblock", manifest["mining_address"], [raw])["hash"]
                controller.wait_synced(block)
                for node in range(NODE_COUNT):
                    output = controller.rpc(node, "gettxout", txid, 0)
                    if (not output or output["confirmations"] < 1
                            or satoshis(output["value"]) != challenge["recipient"]["value_sat"]
                            or output["scriptPubKey"]["hex"] != challenge["recipient"]["script_pubkey"]
                            or not rpc_null(controller.rpc(node, "gettxout", funded["txid"], funded["vout"]))):
                        raise DevnetError("Recovered-key payment did not confirm on every node")
            result = {"passed": True, "session_id": identifier, "purpose": purpose,
                      "completed_at": datetime.now(timezone.utc).isoformat(), "nodes": "stopped",
                      "signed_payment_confirmed_on_four_nodes": True, "txid": txid, "block": block,
                      "physical_device_operator_attested": physical_attestation,
                      "hardware_attestation": False, "device": response["device"],
                      "tooling": response["tooling"],
                      "timing_seconds": response["timing_seconds"],
                      "challenge_sha256": manifest["challenge_sha256"],
                      "response_sha256": hashlib.sha256(recovery._canonical(response)).hexdigest()}
            device.write_document(run / "results" / (attempt + ".json"), result)
            device.write_document(run / "receipt.json", result)
            return result
        except BaseException as error:
            device.write_document(run / "results" / (attempt + "-failure.json"), {
                "passed": False, "session_id": identifier, "error": controller.error_summary(error)})
            raise


def status(identifier: str, root: Path = PROJECT) -> dict:
    run, manifest, _ = read_session(root, session_id(identifier))
    result = _public_paths(root, identifier)
    result.update(purpose=manifest["purpose"], status="awaiting-response", physical_device_completed=False)
    if (run / "receipt.json").exists():
        receipt = device.read_document(run / "receipt.json")
        expected_attestation = manifest["purpose"] == "physical-device"
        if (receipt.get("session_id") != identifier or receipt.get("purpose") != manifest["purpose"]
                or receipt.get("passed") is not True or receipt.get("signed_payment_confirmed_on_four_nodes") is not True
                or receipt.get("physical_device_operator_attested") is not expected_attestation
                or receipt.get("hardware_attestation") is not False
                or receipt.get("challenge_sha256") != manifest["challenge_sha256"]):
            raise DevnetError("Completed receipt is inconsistent with this session")
        result.update(status="passed", receipt=receipt,
                      physical_device_completed=bool(receipt.get("passed") and receipt.get("physical_device_operator_attested")))
    return result


def rehearse(root: Path = PROJECT) -> dict:
    prepared = prepare(root, rehearsal=True)
    run = session_path(root, prepared["session_id"])
    response_path = run / "rehearsal-response.json"
    completed = subprocess.run([sys.executable, str(root.resolve() / "qlu/device_recovery.py"), "respond",
                                "--backup", str(run / "transfer/backup.json"),
                                "--challenge", str(run / "transfer/challenge.json"),
                                "--response", str(response_path), "--code-file", str(run / "offline/code.txt"),
                                "--mode", "rehearsal"], capture_output=True, text=True, timeout=60)
    if completed.returncode:
        raise DevnetError("Separate-process recovery rehearsal failed; no physical-device success is claimed")
    result = check(prepared["session_id"], response_path, root)
    result["scope"] = "Fresh process on the origin computer; not a second physical device"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    actions.add_parser("prepare", help="Prepare a fresh disposable session for a second physical computer")
    actions.add_parser("rehearse", help="Run a separate disposable same-host rehearsal")
    inspect = actions.add_parser("status", help="Read session evidence without starting nodes")
    inspect.add_argument("--session", required=True)
    verify = actions.add_parser("check", help="Verify a returned signature and confirm its payment privately")
    verify.add_argument("--session", required=True)
    verify.add_argument("--response", required=True, type=Path)
    verify.add_argument("--physical-device", action="store_true", help="Attest the response was created on a different physical computer")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare()
        elif args.command == "rehearse":
            result = rehearse()
        elif args.command == "status":
            result = status(args.session)
        else:
            result = check(args.session, args.response, physical_attestation=args.physical_device)
        print(recovery._canonical(result).decode())
        return 0
    except (DevnetError, device.DeviceRecoveryError, recovery.RecoveryError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("QLU recovery lab failed: " + json.dumps(QLUPrivateNet.error_summary(error)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
