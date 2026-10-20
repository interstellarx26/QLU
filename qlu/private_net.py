#!/usr/bin/env python3
"""Four-node QLU private v1 experiment. No real-value funds or public peers."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from devnet import Devnet, DevnetError, RpcError, NODE_COUNT, secure_directory, reject_symlinks, write_private
from protocol import GENESIS, NETWORK, ROOT, address_for, keytool, script_for, sign_transaction
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxOut, from_hex
from test_framework.blocktools import add_witness_commitment
from test_framework.segwit_addr import encode_segwit_address


class QLUPrivateNet(Devnet):
    chain = NETWORK
    p2p_base = 28440
    rpc_base = 28540
    data_name = "qlu-private-v1"
    process_label = "QLUPrivateV1"

    def setup(self):
        super().setup()

    def verify_node(self, index):
        info = super().verify_node(index)
        if self.rpc(index, "getblockhash", 0) != GENESIS:
            raise DevnetError("Unexpected QLU genesis; refusing to operate")
        return info

    def record_smoke(self, report):
        secure_directory(self.local)
        evidence = self.local / "evidence"
        secure_directory(evidence)
        contents = json.dumps(report, indent=2) + "\n"
        write_private(evidence / f"qlu-private-{report['attempt_id']}.json", contents)
        write_private(evidence / "qlu-private-latest.json", contents)

    def expect_rejected(self, tx, reason):
        raw = tx.serialize_with_witness().hex()
        for node in range(NODE_COUNT):
            result = self.rpc(node, "testmempoolaccept", [raw])[0]
            if result.get("allowed") is not False or reason not in result.get("reject-reason", ""):
                raise DevnetError(f"Unexpected rejection on node {node}: {result}")
        try:
            self.rpc(0, "sendrawtransaction", raw)
        except RpcError as error:
            if reason not in str(error):
                raise
        else:
            raise DevnetError("Invalid QLU transaction was accepted")

    def reject_direct_block(self, valid_block_hex, mutate, reason):
        block = from_hex(CBlock(), valid_block_hex)
        mutate(block)
        # Rebuild commitments and proof of work so rejection exercises the intended rule.
        add_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        for node in range(NODE_COUNT):
            # A rejected header can reach another connected node before its RPC.
            # Give each node a distinct solved header to exercise independent validation.
            block.nNonce += 1
            block.solve()
            raw = block.serialize().hex()
            result = self.rpc(node, "submitblock", raw)
            if result != reason:
                raise DevnetError(f"Direct block rejection on node {node}: expected {reason}, got {result}")

    def smoke(self):
        import recovery
        began = datetime.now(timezone.utc)
        report = {"attempt_id": began.strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8],
                  "network": NETWORK, "genesis": GENESIS, "passed": False,
                  "stage": "private-experimental-hybrid-v1", "randomx": False,
                  "checks": {}, "started_at": began.isoformat(), "cleanup": {"status": "not-started"}}
        self.record_smoke(report)
        started = False
        failure = None
        try:
            self.setup()
            self.require_binaries()
            self.require_stopped()
            report["binary_sha256"] = self.file_sha256(self.binary)
            report["keytool_sha256"] = self.file_sha256(ROOT / "build/qlu-foundation/bin/qlu-keytool")
            report["controller_sha256"] = self.file_sha256(Path(__file__))
            report["checkout_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=30).strip()
            diff = subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=ROOT, timeout=30)
            report["tracked_diff_sha256"] = hashlib.sha256(diff).hexdigest()
            self.start()
            started = True
            self.wait_synced()
            report["checks"]["four_qlu_nodes_separate_genesis_local_mesh"] = True
            sender = recovery.generate_wallet(NETWORK, GENESIS)
            recipient = recovery.generate_wallet(NETWORK, GENESIS)
            sender_keys, recipient_keys = keytool(sender), keytool(recipient)
            mining_address = address_for(sender_keys)
            if not self.rpc(0, "validateaddress", mining_address).get("isvalid"):
                raise DevnetError("QLU address did not decode")
            wrong_address = encode_segwit_address("bcrt", 2, bytes.fromhex(sender_keys["key_commitment"]))
            if self.rpc(0, "validateaddress", wrong_address).get("isvalid"):
                raise DevnetError("Wrong-network address accepted")
            blocks = self.rpc(0, "generatetoaddress", 101, mining_address)
            self.wait_synced(blocks[-1])
            coinbase = self.rpc(0, "getblock", blocks[0], 2)["tx"][0]
            source = coinbase["vout"][0]
            amount = round(source["value"] * 100000000)
            previous = CTxOut(amount, bytes.fromhex(source["scriptPubKey"]["hex"]))
            if previous.scriptPubKey != script_for(sender_keys):
                raise DevnetError("Mining reward does not require hybrid authorization")
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), nSequence=0xffffffff)]
            tx.vout = [CTxOut(amount - 100000, script_for(recipient_keys))]
            signed = sign_transaction(sender, tx, [previous])
            valid = self.rpc(0, "testmempoolaccept", [signed.serialize_with_witness().hex()])[0]
            if valid.get("allowed") is not True:
                raise DevnetError(f"Valid hybrid payment rejected: {valid}")
            report["checks"]["hybrid_reward_and_valid_payment"] = True

            mutated = CTransaction(signed); mutated.vout[0].nValue -= 1
            self.expect_rejected(mutated, "qlu-hybrid-signature")
            for which in (2, 3):
                mutated = CTransaction(signed)
                sig = bytearray(mutated.wit.vtxinwit[0].scriptWitness.stack[which]); sig[0] ^= 1
                mutated.wit.vtxinwit[0].scriptWitness.stack[which] = bytes(sig)
                self.expect_rejected(mutated, "qlu-hybrid-signature")
            mutated = CTransaction(signed); del mutated.wit.vtxinwit[0].scriptWitness.stack[2]
            self.expect_rejected(mutated, "qlu-witness-shape")
            self.expect_rejected(tx, "qlu-witness-shape")
            replay = sign_transaction(sender, tx, [previous], digest_genesis="00" * 32)
            self.expect_rejected(replay, "qlu-hybrid-signature")
            for script in (b"\x51", b"\x51\x20" + bytes(32), b"\x53\x20" + bytes(32)):
                mutated = CTransaction(signed); mutated.vout[0].scriptPubKey = script
                self.expect_rejected(mutated, "qlu-output-policy")
            report["checks"]["tamper_each_signature_missing_signature_replay_legacy_unknown_rejected"] = True

            candidate = self.rpc(0, "generateblock", mining_address, [signed.serialize_with_witness().hex()], False)["hex"]
            def corrupt_signature(block):
                sig = bytearray(block.vtx[1].wit.vtxinwit[0].scriptWitness.stack[2]); sig[0] ^= 1
                block.vtx[1].wit.vtxinwit[0].scriptWitness.stack[2] = bytes(sig)
            self.reject_direct_block(candidate, corrupt_signature, "qlu-hybrid-signature")
            self.reject_direct_block(candidate, lambda b: setattr(b.vtx[0].vout[0], "scriptPubKey", b"\x51"), "qlu-output-policy")
            self.reject_direct_block(candidate, lambda b: setattr(b.vtx[1].vout[0], "scriptPubKey", b"\x53\x20" + bytes(32)), "qlu-output-policy")
            def exceed_budget(block):
                block.vtx = block.vtx[:1]
                for group in range(17):
                    item = CTransaction()
                    item.vin = [CTxIn(COutPoint(group * 16 + i + 1, 0), nSequence=0xffffffff) for i in range(16)]
                    item.vout = [CTxOut(1, script_for(recipient_keys))]
                    block.vtx.append(item)
            self.reject_direct_block(candidate, exceed_budget, "qlu-block-auth-limit")
            report["checks"]["direct_blocks_reject_bad_signature_classical_reward_unknown_output_resource_excess"] = True

            # Invalid witness variants above share this txid; rejection must not poison it.
            txid = self.rpc(0, "sendrawtransaction", signed.serialize_with_witness().hex())
            deadline = time.monotonic() + 30
            while not all(txid in self.rpc(i, "getrawmempool") for i in range(NODE_COUNT)):
                if time.monotonic() > deadline:
                    raise DevnetError("Hybrid transaction did not propagate")
                time.sleep(.2)
            tip = self.rpc(0, "generatetoaddress", 1, mining_address)[0]
            self.wait_synced(tip)
            for node in range(NODE_COUNT):
                if self.rpc(node, "gettxout", txid, 0)["confirmations"] != 1:
                    raise DevnetError("Hybrid payment did not confirm on every node")
            report["checks"]["valid_after_invalid_witnesses_propagates_and_confirms"] = True

            run = self.local / "recovery-drills"; secure_directory(run)
            run = run / report["attempt_id"]; secure_directory(run)
            original, backup_file, code_file, restored_file = [run / name for name in ("original.json", "backup.json", "code.txt", "restored.json")]
            recovery.save_wallet(original, recipient)
            blob, code = recovery.make_backup(recipient)
            recovery.write_private(backup_file, blob)
            recovery.write_private(code_file, (code + "\n").encode())
            original.unlink()  # Only the wallet just generated by this drill.
            del recipient, code, blob
            restored = subprocess.run([sys.executable, str(ROOT / "qlu/recovery.py"), "restore",
                                       "--backup", str(backup_file), "--code-file", str(code_file),
                                       "--network", NETWORK, "--genesis", GENESIS, "--wallet", str(restored_file)],
                                      capture_output=True, text=True, timeout=15)
            if restored.returncode or original.exists():
                raise DevnetError("Fresh-process recovery failed")
            recovered = recovery.load_wallet(restored_file)
            if keytool(recovered) != recipient_keys:
                raise DevnetError("Recovered keys changed")
            recovered_script = script_for(keytool(recovered))
            found = self.rpc(1, "scantxoutset", "start", [f"raw({recovered_script.hex()})"])
            if not found.get("success") or len(found.get("unspents", [])) != 1:
                raise DevnetError("Restored keys did not rediscover their unspent payment")
            recovered_coin = found["unspents"][0]
            recovered_output = CTxOut(round(recovered_coin["amount"] * 100000000), bytes.fromhex(recovered_coin["scriptPubKey"]))
            return_tx = CTransaction()
            return_tx.vin = [CTxIn(COutPoint(int(recovered_coin["txid"], 16), recovered_coin["vout"]), nSequence=0xffffffff)]
            return_tx.vout = [CTxOut(recovered_output.nValue - 100000, script_for(sender_keys))]
            recovery_tx = sign_transaction(recovered, return_tx, [recovered_output])
            recovery_txid = self.rpc(1, "sendrawtransaction", recovery_tx.serialize_with_witness().hex())
            # Explicit raw tx avoids relying on asynchronous relay for the restore check.
            tip = self.rpc(0, "generateblock", mining_address, [recovery_tx.serialize_with_witness().hex()])["hash"]
            self.wait_synced(tip)
            if any(self.rpc(n, "gettxout", recovery_txid, 0) is None for n in range(NODE_COUNT)):
                raise DevnetError("Restored wallet payment missing")
            report["checks"]["original_removed_fresh_process_restore_spends_on_chain"] = True
            report["checks"]["restored_keys_rediscover_unspent_funds"] = True
            report["recovery_scope"] = "New process and wallet file on this Mac; not a second physical device. Test backup/code colocated only for automation."
            self.stop(); started = False
            self.start(); started = True
            self.wait_synced(tip)
            if any(self.rpc(n, "gettxout", recovery_txid, 0) is None for n in range(NODE_COUNT)):
                raise DevnetError("Recovered payment lost across restart")
            report["checks"]["restart_preserves_recovered_payment"] = True
            report.update(payment_txid=txid, recovery_txid=recovery_txid, bestblockhash=tip,
                          transaction_bytes=len(signed.serialize_with_witness()), passed=True)
        except BaseException as error:
            failure = error
            report["error"] = self.error_summary(error)
        finally:
            if started:
                try:
                    self.stop()
                except BaseException as error:
                    failure = failure or error
                    report["cleanup"]["error"] = self.error_summary(error)
            report["passed"] = report["passed"] and failure is None
            try:
                statuses = self.status()
                stopped = all(item["status"] == "stopped" for item in statuses)
                report["cleanup"].update(status="stopped" if stopped else "incomplete", nodes=statuses)
                if not stopped:
                    failure = failure or DevnetError("Private nodes did not all stop")
                    report["passed"] = False
            except BaseException as error:
                failure = failure or error
                report["passed"] = False
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            self.record_smoke(report)
        if failure:
            raise failure
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("setup", "start", "status", "stop", "smoke"))
    args = parser.parse_args()
    os.umask(0o077)
    controller = QLUPrivateNet()
    secure_directory(controller.local); secure_directory(controller.data)
    reject_symlinks(controller.data)
    fd = os.open(controller.data / "controller.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "r+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = getattr(controller, args.command)()
    print(json.dumps(result, indent=2) if result is not None else f"QLU {args.command} complete.")


if __name__ == "__main__":
    try:
        main()
    except (DevnetError, ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"QLU private-network error: {error}")
