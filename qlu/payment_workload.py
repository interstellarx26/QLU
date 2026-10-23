#!/usr/bin/env python3
"""Fixed private-node payment workload, not a throughput or wallet-UI benchmark."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time
import traceback
import uuid

import cryptography

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import DevnetError, RpcError, secure_directory, write_private
from lab import private_port_lock
from private_net import QLUPrivateNet
import protocol
import recovery
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxOut, from_hex

BATCHES, WIDTH, FUNDING_BLOCKS = 8, 4, 149
FEE_SATS = 100000
MAX_FIXTURE_BYTES = 100 * 1024 * 1024
MAX_WORK_SECONDS = 600
MAX_BLOCK_BYTES = 128 * 1024
SOURCES = ("payment_workload.py", "protocol.py", "recovery.py", "private_net.py", "devnet.py", "lab.py")
BINARIES = ("bitcoind", "bitcoin-cli", "qlu-keytool")


def require(condition, message):
    if not condition:
        raise DevnetError(message)


def sats(value):
    """RPC decimal conversion without rounded float arithmetic."""
    require(type(value) in (str, int, float, Decimal), "Invalid decimal amount")
    try:
        amount = Decimal(str(value)) * 100000000
        require(amount.is_finite() and amount == amount.to_integral_value()
                and 0 <= amount <= 21000000 * 100000000, "Invalid decimal amount")
        return int(amount)
    except (InvalidOperation, ValueError, OverflowError):
        raise DevnetError("Invalid decimal amount") from None


def subsidy(height):
    """Existing temporary qludev rule, never a proposed production emission."""
    require(type(height) is int and height >= 1, "Invalid workload height")
    halvings = height // 150
    return 0 if halvings >= 64 else (50 * 100000000) >> halvings


def timed(operation):
    started = time.perf_counter_ns()
    value = operation()
    return value, time.perf_counter_ns() - started


def failure_summary(report):
    """Public diagnostic allowlist, excluding arbitrary future report payloads."""
    names = ("attempt", "phase", "passed", "error_type", "error_location", "cleanup",
             "cleanup_error_type", "integrity_error_type", "evidence_error_type", "ports_free")
    return {name: report[name] for name in names if name in report}


def fingerprints():
    root = protocol.ROOT
    source_paths = [Path("qlu") / name for name in SOURCES]
    source_paths += [Path("test/functional/test_framework/messages.py"), Path("test/functional/test_framework/segwit_addr.py"),
                     Path("qlu/recovery-requirements.txt")]
    return {"source": {str(path): hashlib.sha256((root / path).read_bytes()).hexdigest() for path in source_paths},
            "binaries": {name: hashlib.sha256((root / "build/qlu-foundation/bin" / name).read_bytes()).hexdigest()
                         for name in BINARIES}}


def fixture_size(directory):
    """Bounded metadata walk; never follow links or read chain/cookie contents."""
    logical = allocated = files = 0
    require(stat.S_ISDIR(Path(directory).lstat().st_mode), "Invalid workload directory")
    for base, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs + names:
            entry = Path(base) / name
            metadata = entry.lstat()
            require(not stat.S_ISLNK(metadata.st_mode), "Linked workload fixture")
            if name in dirs:
                require(stat.S_ISDIR(metadata.st_mode), "Invalid workload directory entry")
                continue
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "Invalid workload file")
            files += 1
            require(files <= 4096, "Workload file-count limit exceeded")
            logical += metadata.st_size
            allocated += metadata.st_blocks * 512
    require(max(logical, allocated) <= MAX_FIXTURE_BYTES, "Workload disk budget exceeded")
    return {"logical_bytes": logical, "allocated_bytes": allocated, "files": files}


class WorkloadNet(QLUPrivateNet):
    process_label = "QLUPaymentWorkload"

    def __init__(self, root, identifier):
        require(type(identifier) is str and re.fullmatch(r"[0-9a-f]{32}", identifier) is not None,
                "Invalid workload identifier")
        self.data_name = "payment-workload-" + identifier
        super().__init__(root)
        require(not self.data.exists() and not self.data.is_symlink(), "Workload must use a fresh directory")
        self.work_deadline = None

    def check_deadline(self):
        require(self.work_deadline is None or time.monotonic() < self.work_deadline,
                "Workload time budget exceeded")

    def rpc(self, index, method, *params, **kwargs):
        self.check_deadline()
        result = super().rpc(index, method, *params, **kwargs)
        self.check_deadline()
        return result


class Ledger:
    """Independent expected outpoints and exact authorized bytes for this fixture."""
    def __init__(self, scripts):
        require(len(scripts) == 4 and len(set(scripts)) == 4, "Four distinct wallet scripts required")
        self.scripts = set(scripts)
        self.outputs = {}
        self.txids = set()
        self.height, self.tip = 0, protocol.GENESIS
        self.coinbase_sats = self.fee_sats = 0

    def connect(self, block, expected):
        require(len(block.vtx) == len(expected) + 1, "Unexpected block transaction count")
        require(f"{block.hashPrevBlock:064x}" == self.tip, "Unexpected previous block")
        actual = {tx.txid_hex: tx.serialize_with_witness() for tx in block.vtx[1:]}
        require(actual == expected and len(actual) == len(block.vtx) - 1, "Authorized transaction bytes changed or duplicated")
        outputs, txids = dict(self.outputs), set(self.txids)
        fees = 0
        for tx in block.vtx[1:]:
            require(tx.version == 2 and len(tx.vin) == 1 and len(tx.vout) == 1, "Unexpected payment shape")
            outpoint = (f"{tx.vin[0].prevout.hash:064x}", tx.vin[0].prevout.n)
            require(outpoint in outputs, "Missing or already spent workload input")
            value, _ = outputs.pop(outpoint)
            output = tx.vout[0]
            require(output.scriptPubKey in self.scripts and output.nValue > 0, "Unexpected payment output")
            fee = value - output.nValue
            require(fee == FEE_SATS, "Workload payment fee changed")
            require(tx.txid_hex not in txids, "Duplicate workload transaction")
            txids.add(tx.txid_hex)
            outputs[(tx.txid_hex, 0)] = (output.nValue, bytes(output.scriptPubKey))
            fees += fee
        coinbase = block.vtx[0]
        require(len(coinbase.vin) == 1 and coinbase.vin[0].prevout.hash == 0
                and coinbase.vin[0].prevout.n == 0xffffffff, "Missing workload coinbase")
        require(coinbase.txid_hex not in txids, "Duplicate coinbase")
        reward = 0
        for index, output in enumerate(coinbase.vout):
            require(output.nValue >= 0, "Invalid coinbase value")
            if output.scriptPubKey in self.scripts:
                outputs[(coinbase.txid_hex, index)] = (output.nValue, bytes(output.scriptPubKey))
                reward += output.nValue
            else:
                require(output.nValue == 0 and output.scriptPubKey.startswith(b"\x6a"), "Unexpected coinbase output")
        require(reward == subsidy(self.height + 1) + fees, "Actual coinbase reward or fees mismatch")
        txids.add(coinbase.txid_hex)
        require(sum(value for value, _ in outputs.values()) == self.coinbase_sats + reward - self.fee_sats - fees,
                "Workload monetary accounting mismatch")
        self.outputs, self.txids = outputs, txids
        self.coinbase_sats += reward
        self.fee_sats += fees
        self.height += 1
        self.tip = block.hash_hex
        return {"height": self.height, "hash": self.tip, "serialized_bytes": len(block.serialize()),
                "coinbase_sats": reward, "subsidy_sats": subsidy(self.height), "fee_sats": fees,
                "payment_txids": [tx.txid_hex for tx in block.vtx[1:]]}

    def verify_scan(self, scan):
        require(type(scan) is dict and scan.get("success") is True
                and scan.get("bestblock") == self.tip and scan.get("height") == self.height,
                "Workload scan did not match the expected tip")
        rows = scan.get("unspents")
        require(type(rows) is list and len(rows) == len(self.outputs), "Workload output count mismatch")
        observed = {}
        for row in rows:
            require(type(row) is dict and type(row.get("txid")) is str and type(row.get("vout")) is int,
                    "Malformed workload scan")
            outpoint = (row["txid"], row["vout"])
            require(outpoint not in observed, "Duplicate workload scan outpoint")
            try:
                script = bytes.fromhex(row["scriptPubKey"])
            except (KeyError, ValueError, TypeError):
                raise DevnetError("Malformed workload script") from None
            observed[outpoint] = (sats(row["amount"]), script)
        require(observed == self.outputs, "Workload UTXO values or scripts mismatch")
        require(sats(scan.get("total_amount")) == sum(value for value, _ in observed.values()), "Workload scan total mismatch")


def read_block(net, blockhash, expected, ledger, *, all_nodes):
    require(type(blockhash) is str and re.fullmatch(r"[0-9a-f]{64}", blockhash), "Invalid workload block hash")
    raw = net.rpc(0, "getblock", blockhash, 0)
    require(type(raw) is str and 0 < len(raw) <= MAX_BLOCK_BYTES * 2, "Workload block size exceeds bound")
    block = from_hex(CBlock(), raw)
    require(block.serialize().hex() == raw and block.hash_hex == blockhash, "Noncanonical workload block")
    if all_nodes:
        for index in range(1, 4):
            require(net.rpc(index, "getblock", blockhash, 0) == raw, "Node stored different authorized block bytes")
    row = ledger.connect(block, expected)
    row["block_sha256"] = hashlib.sha256(bytes.fromhex(raw)).hexdigest()
    return block, row


def checkpoint(net, ledger):
    rows = []
    for index in range(4):
        net.verify_node(index)
        require(net.rpc(index, "getbestblockhash") == ledger.tip, "Node tip mismatch")
        require(net.rpc(index, "getrawmempool") == [], "Unexpected pending workload payment")
        scan = net.rpc(index, "scantxoutset", "start", [f"raw({script.hex()})" for script in sorted(ledger.scripts)])
        ledger.verify_scan(scan)
        info = net.rpc(index, "gettxoutsetinfo")
        require(info["height"] == ledger.height and info["bestblock"] == ledger.tip
                and info["txouts"] == len(ledger.outputs), "Whole-chain UTXO count or tip mismatch")
        total = sats(info["total_amount"])
        require(total == ledger.coinbase_sats - ledger.fee_sats, "Whole-chain UTXO total mismatch")
        fingerprint = info["hash_serialized_3"]
        require(type(fingerprint) is str and re.fullmatch(r"[0-9a-f]{64}", fingerprint), "Invalid UTXO fingerprint")
        rows.append(fingerprint)
    require(len(set(rows)) == 1, "Nodes disagree on UTXO contents")
    return {"height": ledger.height, "tip": ledger.tip, "utxo_hash": rows[0], "utxos": len(ledger.outputs),
            "total_sats": ledger.coinbase_sats - ledger.fee_sats, "confirmed_on_nodes": 4}


def resources(net, phase, *, running=True):
    result = {"phase": phase, "disk": fixture_size(net.data), "rss_kib_snapshots": []}
    if running:
        state = net.read_state()
        require(set(state) == {str(index) for index in range(4)}, "Missing owned workload node")
        for index in range(4):
            entry = state[str(index)]
            require(net.owned(index, entry), "Workload node ownership changed")
            text = subprocess.check_output(["ps", "-p", str(entry["pid"]), "-o", "rss="], text=True, timeout=5).strip()
            require(text.isdigit() and int(text) > 0 and net.owned(index, entry), "Workload RSS unavailable")
            result["rss_kib_snapshots"].append({"node": index, "kib": int(text)})
    return result


def wait_mempools(net, expected):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        seen = [set(net.rpc(index, "getrawmempool")) for index in range(4)]
        require(all(row <= expected for row in seen), "Unexpected workload mempool transaction")
        if all(row == expected for row in seen):
            return
        time.sleep(.1)
    raise DevnetError("Workload payment propagation timed out")


def replay_confirmed(net, transaction, ledger):
    before = checkpoint(net, ledger)
    observations = []
    for index in range(4):
        try:
            txid = net.rpc(index, "sendrawtransaction", transaction.serialize_with_witness().hex())
            require(txid == transaction.txid_hex, "Replay returned a different transaction")
            observations.append({"node": index, "result": "same-txid"})
        except RpcError as error:
            require(error.code == -27, "Unexpected confirmed replay rejection")
            observations.append({"node": index, "result": "already-in-chain", "rpc_code": error.code})
    after = checkpoint(net, ledger)
    require(before == after, "Confirmed replay changed balances or chain")
    return observations, after


def run():
    identifier = uuid.uuid4().hex
    net = WorkloadNet(protocol.ROOT, identifier)
    report = {"format": "qlu-payment-workload-v1", "attempt": identifier, "passed": False, "phase": "setup",
              "started_at": datetime.now(timezone.utc).isoformat(), "network": protocol.NETWORK, "genesis": protocol.GENESIS,
              "plan": {"batches": BATCHES, "payments_per_batch": WIDTH, "funding_blocks": FUNDING_BLOCKS,
                       "fee_per_payment_sats": FEE_SATS, "disk_limit_bytes": MAX_FIXTURE_BYTES, "work_limit_seconds": MAX_WORK_SECONDS},
              "scope": "Fixed sequential protocol workload on four same-host nodes, not encrypted wallet UI/history endurance, TPS, internet latency, decentralization, finality, peak RAM, long-term storage, production capacity, phone support, or a security audit. Restarts are graceful and controlled, not crashes or power loss.",
              "timing_scope": "Raw wall-clock samples include Python, helper/CLI startup, serialization, loopback RPC, polling and uncontrolled desktop load. No warmup samples excluded or independent peer timing claim.",
              "resource_scope": "Owned-node RSS snapshots are not peak memory. Logical and allocated regular-file bytes include database/log/block-file allocation, excluding filesystem metadata and directories. Non-atomic checkpoints are a sampled stop threshold, not an OS quota.",
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "python": platform.python_version()},
              "cryptography_version": cryptography.__version__,
              "checks": {}, "payments": [], "blocks": [], "resources": [], "restarts": [], "replay": [], "cleanup": "not-started"}
    evidence = protocol.ROOT / ".local/evidence"
    attempted_start = False
    failure = None
    with private_port_lock(protocol.ROOT):
        secure_directory(evidence)
        def save():
            contents = json.dumps(report, indent=2) + "\n"
            write_private(evidence / f"payment-workload-{identifier}.json", contents)
            write_private(evidence / "payment-workload-latest.json", contents)
        try:
            net.setup(); net.require_binaries(); net.require_stopped()
            report["fingerprints_start"] = fingerprints()
            report["head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=protocol.ROOT, text=True, timeout=10).strip()
            save()
            net.work_deadline = time.monotonic() + MAX_WORK_SECONDS
            attempted_start = True
            net.start()
            wallets = [recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS) for _ in range(4)]
            keys = [protocol.keytool(wallet) for wallet in wallets]
            scripts = [protocol.script_for(key) for key in keys]
            ledger = Ledger(scripts)
            miner = protocol.address_for(keys[0])
            report["phase"] = "funding"
            print("Preparing fresh private payment inputs.", flush=True)
            hashes = net.rpc(0, "generatetoaddress", FUNDING_BLOCKS, miner)
            require(len(hashes) == FUNDING_BLOCKS and len(set(hashes)) == FUNDING_BLOCKS, "Unexpected funding blocks")
            net.wait_synced(hashes[-1])
            chains = []
            for index, blockhash in enumerate(hashes):
                block, row = read_block(net, blockhash, {}, ledger, all_nodes=False)
                if index < WIDTH:
                    chains.append(((block.vtx[0].txid_hex, 0), 0))
                if index == FUNDING_BLOCKS - 1:
                    report["funding_last_block"] = row
            report["funding_checkpoint"] = checkpoint(net, ledger)
            report["resources"].append(resources(net, "funded"))
            report["checks"]["fresh_four_node_funding_ledger"] = True
            replay_tx = None
            for batch in range(BATCHES):
                report["phase"] = f"batch-{batch + 1}"
                net.check_deadline()
                fixture_size(net.data)
                expected, pending = {}, []
                for lane, (outpoint, owner) in enumerate(chains):
                    value, own_script = ledger.outputs[outpoint]
                    require(own_script == scripts[owner], "Workload signer mismatch")
                    recipient = (owner + 1) % 4
                    tx = CTransaction()
                    tx.vin = [CTxIn(COutPoint(int(outpoint[0], 16), outpoint[1]), nSequence=0xffffffff)]
                    tx.vout = [CTxOut(value - FEE_SATS, scripts[recipient])]
                    signed, signing = timed(lambda: protocol.sign_transaction(wallets[owner], tx, [CTxOut(value, own_script)]))
                    raw = signed.serialize_with_witness()
                    require(signed.txid_hex not in expected and signed.txid_hex not in ledger.txids, "Duplicate planned payment")
                    accepted, preflight = timed(lambda: net.rpc(0, "testmempoolaccept", [raw.hex()]))
                    require(len(accepted) == 1 and accepted[0].get("allowed") is True, "Valid workload payment rejected")
                    txid, broadcast = timed(lambda: net.rpc(lane, "sendrawtransaction", raw.hex()))
                    require(txid == signed.txid_hex, "Broadcast returned a different transaction")
                    expected[txid] = raw
                    pending.append(((txid, 0), recipient))
                    report["payments"].append({"batch": batch + 1, "lane": lane, "txid": txid, "wtxid": signed.wtxid_hex,
                        "input_txid": outpoint[0], "input_vout": outpoint[1], "input_sats": value,
                        "output_sats": signed.vout[0].nValue, "fee_sats": FEE_SATS, "serialized_bytes": len(raw),
                        "sign_ns": signing, "preflight_ns": preflight, "broadcast_ns": broadcast})
                    replay_tx = signed
                _, propagation = timed(lambda: wait_mempools(net, set(expected)))
                mined, mining = timed(lambda: net.rpc(0, "generatetoaddress", 1, miner))
                require(len(mined) == 1, "Unexpected workload mining count")
                _, agreement = timed(lambda: net.wait_synced(mined[0]))
                _, row = read_block(net, mined[0], expected, ledger, all_nodes=True)
                row.update(batch=batch + 1, propagation_ns=propagation, mining_rpc_ns=mining, agreement_after_mining_ns=agreement)
                report["blocks"].append(row)
                chains = pending
                report["resources"].append(resources(net, f"batch-{batch + 1}"))
                save()
                if batch + 1 in (BATCHES // 2, BATCHES):
                    before = checkpoint(net, ledger)
                    _, restart = timed(lambda: (net.stop(), net.start(), net.wait_synced(ledger.tip)))
                    after = checkpoint(net, ledger)
                    require(before == after, "Restart changed confirmed workload state")
                    # Re-read every authorized block after each restart.
                    for stored in report["blocks"]:
                        for index in range(4):
                            raw = net.rpc(index, "getblock", stored["hash"], 0)
                            require(hashlib.sha256(bytes.fromhex(raw)).hexdigest() == stored["block_sha256"],
                                    "Restart changed stored workload bytes")
                    report["restarts"].append({"after_batch": batch + 1, "elapsed_ns": restart, "checkpoint": after})
                    report["resources"].append(resources(net, f"restart-{batch + 1}"))
            report["checks"]["32_original_payments_and_two_restarts"] = True
            report["phase"] = "confirmed-replay"
            report["replay"], after = replay_confirmed(net, replay_tx, ledger)
            report["checks"]["confirmed_replay_has_no_new_transaction_fee_or_balance_effect"] = True
            report["final_checkpoint"] = after
            require(len(report["payments"]) == WIDTH * BATCHES and ledger.fee_sats == WIDTH * BATCHES * FEE_SATS,
                    "Workload count or fee total mismatch")
            require(report["funding_last_block"]["subsidy_sats"] == 50 * 100000000
                    and report["blocks"][0]["subsidy_sats"] == 25 * 100000000, "Workload did not cross laboratory halving")
            report["checks"]["actual_coinbases_fees_and_halving_accounted"] = True
            report["totals"] = {"payments": len(report["payments"]), "fee_sats": ledger.fee_sats,
                                "coinbase_sats": ledger.coinbase_sats, "utxo_sats": ledger.coinbase_sats - ledger.fee_sats}
            report["passed"], report["phase"] = True, "complete"
        except BaseException as error:
            failure = error
            report["error_type"] = type(error).__name__
            report["error_location"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                        for frame in traceback.extract_tb(error.__traceback__)]
        finally:
            # Cleanup has its own existing controller bounds even after work expires.
            net.work_deadline = None
            try:
                if attempted_start:
                    net.stop()
                statuses = net.status()
                require(all(item["status"] == "stopped" for item in statuses), "Workload nodes remain active")
                report["cleanup"] = "owned-nodes-stopped"
                report["resources"].append(resources(net, "stopped", running=False))
                report["ports_free"] = {str(port): net.port_free(port) for port in (*range(28440, 28444), *range(28540, 28544))}
                require(all(report["ports_free"].values()), "Workload ports remain occupied")
            except BaseException as error:
                failure = failure or error
                report["cleanup"] = "needs-attention"
                report["cleanup_error_type"] = type(error).__name__
            try:
                report["fingerprints_end"] = fingerprints()
                require(report.get("fingerprints_start") == report["fingerprints_end"], "Workload source or binaries changed")
            except BaseException as error:
                failure = failure or error
                report["integrity_error_type"] = type(error).__name__
            report["passed"] = report["passed"] and failure is None
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            try:
                save()
            except BaseException as error:
                failure = failure or error
                report["passed"] = False
                report["evidence_error_type"] = type(error).__name__
            if not report["passed"]:
                # The safe location survives even when evidence publication
                # failed. Never print exception messages or the full report.
                print(json.dumps(failure_summary(report), indent=2), flush=True)
    if failure is not None:
        raise DevnetError("Private payment workload failed; retained evidence records its phase") from None
    print(json.dumps({"passed": report["passed"], "phase": report["phase"], "report": str(evidence / f"payment-workload-{identifier}.json")}))
    return report


if __name__ == "__main__":
    try:
        run()
    except Exception:
        print("Private payment workload failed; inspect its retained evidence.", file=sys.stderr)
        raise SystemExit(1)
