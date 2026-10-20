#!/usr/bin/env python3
"""Bounded private-network measurements; never a public throughput claim."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import time
import uuid

from devnet import DevnetError, NODE_COUNT, secure_directory, write_private
from lab import private_port_lock
from private_net import QLUPrivateNet
from protocol import GENESIS, NETWORK, ROOT, address_for, keytool, script_for, sign_transaction
import recovery
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut


def statistics(samples):
    """Keep raw samples and avoid claiming reliable tails from small node samples."""
    ordered = sorted(samples)
    if not ordered or any(type(n) is not int or n < 0 for n in ordered):
        raise ValueError("Expected nonnegative integer timing samples")
    return {"count": len(ordered), "min_ns": ordered[0],
            "median_ns": ordered[math.ceil(len(ordered) / 2) - 1],
            "max_ns": ordered[-1], "samples_ns": samples}


def measured(operation):
    start = time.perf_counter_ns()
    result = operation()
    elapsed = time.perf_counter_ns() - start
    return result, elapsed


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance():
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                    cwd=ROOT, timeout=30).decode().split("\0")
    # Includes newly added benchmark/recovery tooling, unlike git diff alone.
    sources = {p: sha256(ROOT / p) for p in sorted(set(paths)) if p and (ROOT / p).is_file()}
    binary = ROOT / "build/qlu-foundation/bin"
    result = {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=30).strip(),
              "source_files_sha256": sources,
              "binaries_sha256": {name: sha256(binary / name) for name in ("bitcoind", "bitcoin-cli", "qlu-keytool", "qlu-bench")},
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                       "macos": platform.mac_ver()[0], "python": platform.python_version()}}
    if platform.system() == "Darwin":
        for field in ("hw.model", "hw.memsize", "hw.ncpu", "machdep.cpu.brand_string"):
            result["host"][field] = subprocess.check_output(["sysctl", "-n", field], text=True, timeout=10).strip()
    return result


def unsigned_payment(coins, output_script, fee):
    if not 1 <= len(coins) <= 16 or type(fee) is not int or fee <= 0:
        raise ValueError("Invalid benchmark transaction shape or fee")
    total = sum(out.nValue for _, out in coins)
    if total <= fee:
        raise ValueError("Benchmark inputs cannot pay the fee")
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(int(txid, 16), 0), nSequence=0xffffffff) for txid, _ in coins]
    tx.vout = [CTxOut(total - fee, output_script)]
    return tx


def candidate_block(coins, wallet, script, tip, height, block_time, variant):
    """Fresh signatures/txids per proposal; all preparation is outside timers."""
    txs, fees = [], 0
    for start in range(0, len(coins), 16):
        group = coins[start:start + 16]
        fee = 100000 + variant * 100 + start
        unsigned = unsigned_payment(group, script, fee)
        txs.append(sign_transaction(wallet, unsigned, [out for _, out in group]))
        fees += fee
    coinbase = create_coinbase(height, script_pubkey=script, fees=fees, halving_period=150)
    block = create_block(int(tip, 16), coinbase, block_time, txlist=txs)
    add_witness_commitment(block)
    return block


def run():
    attempt = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    class BenchmarkNet(QLUPrivateNet):
        data_name = "performance-" + attempt
        process_label = "QLUBenchmarkV1"
    net = BenchmarkNet(ROOT)
    evidence = ROOT / ".local/evidence"
    report = {"format": "qlu-performance-v1", "attempt_id": attempt, "passed": False,
              "network": NETWORK, "genesis": GENESIS, "started_at": datetime.now(timezone.utc).isoformat(),
              "phase": "setup", "data_directory": str(net.data), "cleanup": "not-started",
              "methodology": {
                  "client_and_node": "Warm local process/UTXO state. Distinct txids per sample. CLI process, JSON encoding/decoding and loopback RPC included. testmempoolaccept performs policy and consensus signature checks. Single sequential caller; background load and thermal/power state uncontrolled.",
                  "blocks": "Three unique proposals per size; getblocktemplate proposal runs TestBlockValidity with PoW disabled and Merkle checking enabled. Not connected or persisted. One solved 256-input block is then submitted; separate four-node agreement time includes polling/RPC overhead. No timing sample reused as an independent peer observation.",
                  "limits": "Local exploratory measurements, not TPS, internet latency, payment finality, fee estimates, attack capacity, phone support or a security audit. Small RPC sample counts have no reliable tail estimates. Recovery in this report stays on one physical host.",
                  "quantile_method": "nearest_rank"}}
    failure = None
    attempted_start = False
    with private_port_lock(ROOT):
        secure_directory(evidence)
        def save():
            contents = json.dumps(report, indent=2) + "\n"
            write_private(evidence / f"performance-{attempt}.json", contents)
            write_private(evidence / "performance-latest.json", contents)
        try:
            net.setup(); net.require_binaries(); net.require_stopped()
            report["provenance"] = provenance()
            save()
            report["phase"] = "native-cryptography"
            print("Measuring native cryptography (five batches).", flush=True)
            result = subprocess.run([str(ROOT / "build/qlu-foundation/bin/qlu-bench")],
                                    capture_output=True, text=True, timeout=180, check=True)
            report["native"] = json.loads(result.stdout)
            if report["native"].get("all_correctness_checks_passed") is not True:
                raise DevnetError("Native benchmark correctness failed")
            save()

            report["phase"] = "funding-fresh-chain"
            print("Preparing a fresh four-node chain and mature test inputs.", flush=True)
            attempted_start = True
            net.start()
            wallet = recovery.generate_wallet(NETWORK, GENESIS)
            keys = keytool(wallet); script = script_for(keys)
            blocks = net.rpc(0, "generatetoaddress", 357, address_for(keys))
            tip = net.wait_synced(blocks[-1])
            coins = []
            for blockhash in blocks[:257]:
                coinbase = net.rpc(0, "getblock", blockhash, 2)["tx"][0]
                out = coinbase["vout"][0]
                value = Decimal(str(out["value"])) * 100000000
                if value != value.to_integral_value() or bytes.fromhex(out["scriptPubKey"]["hex"]) != script:
                    raise DevnetError("Unexpected benchmark coin")
                coins.append((coinbase["txid"], CTxOut(int(value), script)))
            report["funding"] = {"height": 357, "mature_inputs": len(coins), "temporary_halving_interval": 150}

            report["phase"] = "wallet-and-mempool"
            print("Measuring payment signing and local acceptance for 1, 4 and 16 inputs.", flush=True)
            payments = {}
            for count in (1, 4, 16):
                signing, acceptance = [], []
                group = coins[:count]
                for sample in range(11):
                    tx = unsigned_payment(group, script, 100000 + count * 100 + sample)
                    signed, duration = measured(lambda: sign_transaction(wallet, tx, [out for _, out in group]))
                    raw = signed.serialize_with_witness()
                    accepted, elapsed = measured(lambda: net.rpc(0, "testmempoolaccept", [raw.hex()]))
                    if accepted[0].get("allowed") is not True:
                        raise DevnetError("Valid benchmark payment rejected")
                    if sample:  # One complete warm-up per shape.
                        signing.append(duration); acceptance.append(elapsed)
                base = len(signed.serialize_without_witness())
                weight = 3 * base + len(raw)
                payments[str(count)] = {"inputs": count, "outputs": 1, "serialized_bytes": len(raw),
                    "weight": weight, "weight_virtual_bytes": (weight + 3) // 4,
                    "mempool_effective_virtual_bytes": accepted[0]["vsize"],
                    "signing_with_native_helper_launches": statistics(signing),
                    "local_testmempoolaccept": statistics(acceptance)}
            report["payments"] = payments
            save()

            report["phase"] = "backup-and-restore"
            encrypt, decrypt, reconstruct = [], [], []
            for sample in range(101):
                (blob, code), elapsed_encrypt = measured(lambda: recovery.make_backup(wallet))
                restored, elapsed_decrypt = measured(lambda: recovery.restore_backup(blob, code, expected_network=NETWORK, expected_genesis=GENESIS))
                if restored != wallet:
                    raise DevnetError("Recovery changed benchmark wallet")
                if sample:
                    encrypt.append(elapsed_encrypt); decrypt.append(elapsed_decrypt)
                if 1 <= sample <= 10:
                    recovered_keys, elapsed_keys = measured(lambda: keytool(restored))
                    if recovered_keys != keys:
                        raise DevnetError("Recovery changed signing keys")
                    reconstruct.append(elapsed_keys)
            report["recovery_same_host"] = {"encrypted_bytes": len(blob), "encrypt": statistics(encrypt),
                "decrypt_validate": statistics(decrypt), "reconstruct_keys_with_helper_launch": statistics(reconstruct),
                "physical_second_device": False}
            del restored, blob, code

            report["phase"] = "block-proposals"
            print("Measuring block checks up to the 256-input consensus limit.", flush=True)
            header = net.rpc(0, "getblockheader", tip)
            cases = {}
            final_block = None
            for count in (1, 16, 64, 128, 256):
                samples = []
                for sample in range(3):
                    block = candidate_block(coins[:count], wallet, script, tip, 358, header["time"] + 1, count * 10 + sample)
                    raw = block.serialize().hex()
                    result, duration = measured(lambda: net.rpc(0, "getblocktemplate", {"mode": "proposal", "data": raw, "rules": ["segwit"]}))
                    # bitcoin-cli prints JSON null as empty stdout; Devnet.rpc
                    # preserves that empty string rather than returning None.
                    if result not in (None, ""):
                        raise DevnetError(f"Valid {count}-input proposal rejected: {result}")
                    samples.append(duration)
                cases[str(count)] = {"authorizations": count, "transactions_excluding_coinbase": len(block.vtx) - 1,
                    "serialized_bytes": len(block.serialize()), "local_proposal_rpc": statistics(samples)}
                final_block = block
            report["blocks"] = cases
            excessive = candidate_block(coins, wallet, script, tip, 358, header["time"] + 1, 9999)
            rejection = net.rpc(0, "getblocktemplate", {"mode": "proposal", "data": excessive.serialize().hex(), "rules": ["segwit"]})
            if rejection != "qlu-block-auth-limit":
                raise DevnetError("257-input proposal did not enforce consensus ceiling")
            report["reject_257_authorizations"] = rejection
            save()

            report["phase"] = "block-connection"
            final_block.solve()
            result, elapsed = measured(lambda: net.rpc(0, "submitblock", final_block.serialize().hex()))
            if result not in (None, ""):
                raise DevnetError("Solved benchmark block rejected")
            _, agreement = measured(lambda: net.wait_synced(final_block.hash_hex))
            for i in range(NODE_COUNT):
                for tx in final_block.vtx[1:]:
                    output = net.rpc(i, "gettxout", tx.txid_hex, 0)
                    if output is None or output["confirmations"] != 1:
                        raise DevnetError("Benchmark block output missing from a node")
            rss = []
            for index, entry in net.read_state().items():
                if not net.owned(int(index), entry):
                    raise DevnetError("Benchmark process ownership changed")
                value = subprocess.check_output(["ps", "-p", str(entry["pid"]), "-o", "rss="], text=True, timeout=10)
                rss.append({"node": int(index), "rss_kib_snapshot": int(value.strip())})
            report["connected_block"] = {"hash": final_block.hash_hex, "height": 358, "authorizations": 256,
                "submitblock_rpc_ns": elapsed, "four_node_agreement_after_submission_ns": agreement,
                "every_created_output_confirmed_on_all_four_nodes": True, "rss_snapshot_not_peak": rss}
            report["passed"] = True
            report["phase"] = "completed"
        except BaseException as error:
            failure = error
            report["error"] = net.error_summary(error)
        finally:
            if attempted_start:
                try:
                    net.stop()
                except BaseException as error:
                    failure = failure or error
                    report["cleanup_error"] = net.error_summary(error)
            try:
                statuses = net.status()
                report["cleanup"] = statuses
                if not all(item["status"] == "stopped" for item in statuses):
                    failure = failure or DevnetError("Benchmark nodes remain running")
            except BaseException as error:
                failure = failure or error
            report["passed"] = report["passed"] and failure is None
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            save()
            write_private(evidence / "performance-latest.json", json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "phase": report["phase"], "report": str(evidence / f"performance-{attempt}.json")}))
    if failure:
        raise DevnetError("Benchmark failed; inspect the retained phase report") from failure
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    run()
