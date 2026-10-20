#!/usr/bin/env python3
"""Disposable encrypted-wallet drill on four fresh localhost QLU nodes.

Never uses an existing wallet or recovery session. Secrets travel to the child
through a pipe and exist only in memory; retained wallet/backup files are encrypted.
This is a same-computer test, not a physical-device recovery claim.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

import device_recovery as device
from device_lab import rpc_null, running, satoshis
from devnet import DevnetError, NODE_COUNT, secure_directory, write_private
from lab import private_port_lock
from private_net import QLUPrivateNet
import protocol
import recovery
from vault import VaultError, WalletSession
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, from_hex


class WalletNet(QLUPrivateNet):
    def __init__(self, identifier: str):
        self.data_name = "wallet-" + identifier
        self.process_label = "QLUWallet-" + identifier
        super().__init__(protocol.ROOT)


def expect_locked(session, tx, previous):
    try:
        session.sign(tx, [previous])
    except VaultError:
        return
    raise DevnetError("Locked wallet authorized a payment")


def restore_worker() -> int:
    """Internal test worker. Its stdout contains only public signing results."""
    session = None
    try:
        request = recovery._parse(sys.stdin.buffer.read(recovery.MAX_BACKUP_BYTES + 1),
                                  recovery.MAX_BACKUP_BYTES)
        if request.keys() != {"vault", "backup", "code", "passphrase", "challenge"}:
            raise ValueError("Invalid worker request")
        for field in ("vault", "backup", "code", "passphrase"):
            if type(request[field]) is not str:
                raise ValueError("Invalid worker request")
        tx, previous = device.validate_challenge(request["challenge"])
        session = WalletSession.restore(request["vault"], recovery.read_private(request["backup"]),
                                        request["code"], request["passphrase"])
        keys = session.public_keys()
        if keys["key_commitment"] != request["challenge"]["wallet_commitment"]:
            raise ValueError("Recovered authority mismatch")
        session.lock()
        expect_locked(session, tx, previous)
        # Exercise a fresh session reading the encrypted file, not just the
        # already-restored in-memory wallet.
        session = WalletSession(request["vault"])
        if not session.locked:
            raise ValueError("New session was unlocked")
        session.unlock(request["passphrase"])
        if session.public_keys() != keys:
            raise ValueError("Encrypted reload changed authority")
        signed = session.sign(tx, [previous])
        print(json.dumps({"commitment": keys["key_commitment"], "address": session.address(),
                          "signed_tx": signed.serialize_with_witness().hex(),
                          "encrypted_reload": True, "locked_sign_rejected": True}))
        return 0
    except Exception:
        # No exception details: request includes secret material.
        print("Encrypted recovery worker failed.", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            session.lock()


def confirmed(controller, txid, value, script):
    for index in range(NODE_COUNT):
        coin = controller.rpc(index, "gettxout", txid, 0)
        if (not isinstance(coin, dict) or coin.get("confirmations", 0) < 1
                or satoshis(coin["value"]) != value
                or coin["scriptPubKey"]["hex"] != script.hex()):
            raise DevnetError("Expected payment missing on a private node")


def smoke() -> dict:
    identifier = uuid.uuid4().hex
    local = protocol.ROOT / ".local"
    secure_directory(local)
    evidence = local / "evidence"
    secure_directory(evidence)
    base = local / "wallet-tests"
    secure_directory(base)
    run = base / identifier
    run.mkdir(mode=0o700)
    controller = WalletNet(identifier)
    report = {"format": "qlu-encrypted-wallet-test", "version": 1,
              "attempt_id": identifier, "started_at": datetime.now(timezone.utc).isoformat(),
              "network": protocol.NETWORK, "genesis": protocol.GENESIS,
              "scope": "same-computer fresh process; valueless test coins",
              "passed": False, "checks": {}, "phase": "preflight", "cleanup": "not-started"}

    def record():
        payload = json.dumps(report, indent=2) + "\n"
        write_private(evidence / ("wallet-" + identifier + ".json"), payload)
        write_private(evidence / "wallet-latest.json", payload)

    record()
    sessions = []
    try:
        report["source_sha256"] = {
            name: hashlib.sha256((protocol.ROOT / name).read_bytes()).hexdigest()
            for name in ("qlu/vault.py", "qlu/wallet.py", "qlu/wallet_smoke.py",
                         "qlu/protocol.py", "qlu/recovery.py")}
        report["node_sha256"] = controller.file_sha256(controller.binary)
        report["keytool_sha256"] = controller.file_sha256(protocol.ROOT / "build/qlu-foundation/bin/qlu-keytool")
        with private_port_lock():
            with running(controller):
                report["cleanup"] = "pending"
                if controller.rpc(0, "getblockcount") != 0:
                    raise DevnetError("Encrypted-wallet drill requires a fresh chain")
                report["phase"] = "create-and-backup"
                sender_pass, recipient_pass = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                sender = WalletSession.create(run / "mining.vault.json", sender_pass)
                original = WalletSession.create(run / "original.vault.json", recipient_pass)
                sessions.extend([sender, original])
                sender_keys, recipient_keys = sender.public_keys(), original.public_keys()
                mining_address = sender.address()
                receiving_address = original.address()
                blob, code = original.backup()
                backup_path = run / "backup.json"
                recovery.write_private(backup_path, blob)
                original.verify_backup(recovery.read_private(backup_path), code)
                original.lock()
                try:
                    original.unlock("This is deliberately the wrong passphrase")
                except VaultError:
                    pass
                else:
                    raise DevnetError("Wrong passphrase unlocked the vault")
                if not original.locked:
                    raise DevnetError("Failed unlock left an unlocked session")
                report["checks"]["encrypted_creation_backup_readback_wrong_passphrase"] = True

                report["phase"] = "fund-encrypted-wallet"
                blocks = controller.rpc(0, "generatetoaddress", 101, mining_address)
                controller.wait_synced(blocks[-1])
                coinbase = controller.rpc(0, "getblock", blocks[0], 2)["tx"][0]
                coin = coinbase["vout"][0]
                previous = CTxOut(satoshis(coin["value"]), bytes.fromhex(coin["scriptPubKey"]["hex"]))
                funding = CTransaction()
                funding.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), nSequence=0xffffffff)]
                funding.vout = [CTxOut(100000000, protocol.script_for(recipient_keys)),
                                CTxOut(previous.nValue - 100100000, protocol.script_for(sender_keys))]
                signed = sender.sign(funding, [previous])
                raw = signed.serialize_with_witness().hex()
                funding_txid = controller.rpc(0, "sendrawtransaction", raw)
                tip = controller.rpc(0, "generateblock", mining_address, [raw])["hash"]
                controller.wait_synced(tip)
                confirmed(controller, funding_txid, 100000000, funding.vout[0].scriptPubKey)
                report["checks"]["encrypted_wallet_received_confirmed_funds"] = True

                tx = CTransaction()
                tx.vin = [CTxIn(COutPoint(int(funding_txid, 16), 0), nSequence=0xffffffff)]
                tx.vout = [CTxOut(99900000, protocol.script_for(sender_keys))]
                expect_locked(original, tx, funding.vout[0])
                report["checks"]["locked_signing_rejected"] = True
                # Remove only the vault generated for this attempt. The restore
                # worker cannot access its seed or old unlock passphrase.
                (run / "original.vault.json").unlink()
                sessions.remove(original)
                del original, recipient_pass, blob
                report["phase"] = "fresh-process-encrypted-recovery"
                challenge = device.make_challenge(tx, funding.vout[0], recipient_keys["key_commitment"], identifier)
                request = {"vault": str(run / "restored.vault.json"), "backup": str(backup_path),
                           "code": code, "passphrase": secrets.token_urlsafe(32), "challenge": challenge}
                child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--restore-worker"],
                                       input=recovery._canonical(request), capture_output=True, timeout=45)
                del request, code
                if child.returncode != 0 or child.stderr or len(child.stdout) > 32768:
                    raise DevnetError("Fresh-process encrypted recovery failed")
                response = json.loads(child.stdout)
                if (response["commitment"] != recipient_keys["key_commitment"]
                        or response["address"] != receiving_address
                        or response["encrypted_reload"] is not True
                        or response["locked_sign_rejected"] is not True):
                    raise DevnetError("Recovered wallet identity changed")
                restored_tx = from_hex(CTransaction(), response["signed_tx"])
                if restored_tx.serialize_without_witness() != tx.serialize_without_witness():
                    raise DevnetError("Recovered wallet signed a different payment")
                report["checks"]["original_removed_new_process_restores_directly_encrypted"] = True
                report["checks"]["restored_vault_reopened_locked_then_unlocked_and_signed"] = True
                found = controller.rpc(1, "scantxoutset", "start", [f"raw({funding.vout[0].scriptPubKey.hex()})"])
                unspents = found.get("unspents", [])
                if (found.get("success") is not True or len(unspents) != 1
                        or unspents[0]["txid"] != funding_txid or unspents[0]["vout"] != 0
                        or satoshis(unspents[0]["amount"]) != 100000000):
                    raise DevnetError("Restored identity did not rediscover the funded output")
                report["checks"]["restored_identity_rediscovers_unspent_output"] = True

                report["phase"] = "confirm-restored-payment"
                for which in (2, 3):
                    damaged = CTransaction(restored_tx)
                    signature = bytearray(damaged.wit.vtxinwit[0].scriptWitness.stack[which])
                    signature[0] ^= 1
                    damaged.wit.vtxinwit[0].scriptWitness.stack[which] = bytes(signature)
                    controller.expect_rejected(damaged, "qlu-hybrid-signature")
                raw = restored_tx.serialize_with_witness().hex()
                for index in range(NODE_COUNT):
                    if controller.rpc(index, "testmempoolaccept", [raw])[0].get("allowed") is not True:
                        raise DevnetError("Restored encrypted wallet's signatures were rejected")
                txid = controller.rpc(1, "sendrawtransaction", raw)
                tip = controller.rpc(0, "generateblock", mining_address, [raw])["hash"]
                controller.wait_synced(tip)
                confirmed(controller, txid, 99900000, tx.vout[0].scriptPubKey)
                if any(not rpc_null(controller.rpc(i, "gettxout", funding_txid, 0)) for i in range(NODE_COUNT)):
                    raise DevnetError("Recovered input was not spent on every node")
                report["checks"]["both_signatures_required_and_payment_confirmed_four_nodes"] = True
                report.update(payment_txid=txid, confirmation_block=tip, paid_qlu="0.99900000", fee_qlu="0.00100000")
                report["phase"] = "restart"
                controller.stop()
                controller.start()
                controller.wait_synced(tip)
                confirmed(controller, txid, 99900000, tx.vout[0].scriptPubKey)
                report["checks"]["confirmed_payment_survives_four_node_restart"] = True
            report["cleanup"] = "all-four-nodes-stopped"
        report["passed"] = True
        report["phase"] = "complete"
    except BaseException as error:
        report["error_type"] = type(error).__name__
        # Retain only an error category and phase, never secret-bearing locals.
        try:
            if all(item["status"] == "stopped" for item in controller.status()):
                report["cleanup"] = "all-four-nodes-stopped"
        except Exception:
            report["cleanup"] = "status-check-failed"
        raise
    finally:
        for session in sessions:
            session.lock()
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        record()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.restore_worker:
        return restore_worker()
    try:
        report = smoke()
    except (Exception, KeyboardInterrupt):
        print("Encrypted-wallet drill failed; see .local/evidence/wallet-latest.json.", file=sys.stderr)
        return 1
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]),
                      "payment_txid": report["payment_txid"], "nodes": report["cleanup"],
                      "scope": report["scope"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
