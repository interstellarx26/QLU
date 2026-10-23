#!/usr/bin/env python3
"""Bounded malformed V1 P2P traffic on fresh, owned localhost QLU nodes.

This is a small regression drill, not an internet exposure, load test, or V2
transport assessment. Test keys exist only in memory; no user wallet is opened.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import DevnetError, secure_directory, write_private
from lab import private_port_lock
from private_net import QLUPrivateNet
from payment_workload import fixture_size, sats, wait_mempools
from p2p_probe import WirePeer, WireBudget, wire_cases, frame
import protocol
import recovery
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxOut, from_hex

MAX_WORK_SECONDS = 600
MAX_LOG_BYTES = 65536
FUNDING_BLOCKS = 104
FEE_SATS = 100000
WIRE_NAMES = (
    "wrong-magic", "length-4000001", "length-ffffffff", "wrong-checksum-ping",
    "command-nonprintable", "command-nul-trailing", "short-ping-0", "short-ping-7",
    "tx-empty", "tx-truncated-version", "tx-noncanonical-compactsize", "tx-oversized-compactsize",
)
SOURCE_PATHS = tuple(["qlu/" + name for name in (
    "p2p_resilience.py", "p2p_probe.py", "protocol.py", "recovery.py", "private_net.py", "devnet.py", "lab.py",
    "payment_workload.py", "tests/test_p2p_probe.py", "tests/test_p2p_resilience.py")]
    + ["test/functional/test_framework/" + name for name in ("messages.py", "segwit_addr.py")]
    + ["src/" + name for name in ("net.cpp", "net_processing.cpp", "net.h", "protocol.cpp", "protocol.h",
        "serialize.h", "primitives/transaction.h", "node/txdownloadman_impl.cpp", "qlu/consensus.cpp", "qlu/crypto.cpp")])


def require(condition, message):
    if not condition:
        raise DevnetError(message)


def corpus_description():
    cases = wire_cases()
    require(tuple(case.name for case in cases) == WIRE_NAMES, "P2P wire corpus changed")
    return [{"name": case.name, "expected": case.expected, "raw_hex": case.raw.hex(),
             "forbidden_pongs": list(case.forbidden_pongs)} for case in cases]


def fingerprints():
    corpus = json.dumps(corpus_description(), sort_keys=True, separators=(",", ":")).encode()
    return {"sources": {path: hashlib.sha256((protocol.ROOT / path).read_bytes()).hexdigest() for path in SOURCE_PATHS},
            "corpus_sha256": hashlib.sha256(corpus).hexdigest(),
            "binaries": {name: hashlib.sha256((protocol.ROOT / "build/qlu-foundation/bin" / name).read_bytes()).hexdigest()
                         for name in ("bitcoind", "bitcoin-cli", "qlu-keytool")}}


class ResilienceNet(QLUPrivateNet):
    process_label = "QLUP2PResilience"

    def __init__(self, root, identifier):
        require(type(identifier) is str and re.fullmatch(r"[0-9a-f]{32}", identifier), "Invalid P2P drill identifier")
        self.data_name = "p2p-resilience-" + identifier
        super().__init__(root)
        require(not self.data.exists() and not self.data.is_symlink(), "P2P drill requires a fresh directory")
        self.work_deadline = None

    def check_deadline(self):
        require(self.work_deadline is None or time.monotonic() < self.work_deadline, "P2P drill time budget exceeded")

    def rpc(self, index, method, *params, **kwargs):
        self.check_deadline()
        result = super().rpc(index, method, *params, **kwargs)
        self.check_deadline()
        return result


def owned_identity(net):
    state = net.read_state()
    require(set(state) == {str(index) for index in range(4)}, "Missing owned P2P fixture process")
    require(all(net.owned(index, state[str(index)]) for index in range(4)), "P2P fixture process ownership changed")
    return {key: {"pid": entry["pid"], "token": entry["token"]} for key, entry in sorted(state.items())}


def parse_txout(result):
    # bitcoin-cli renders a JSON null RPC result as empty stdout. The shared
    # controller therefore returns "" for an absent output on this build.
    if result is None or (type(result) is str and result == ""):
        return None
    require(type(result) is dict, "Malformed P2P output lookup result")
    return result


def state_snapshot(net, outpoints):
    identity = owned_identity(net)
    nodes = []
    for index in range(4):
        info = net.verify_node(index)
        require(info.get("initialblockdownload") is False, "P2P transaction checks require a synchronized node")
        pool = net.rpc(index, "getrawmempool")
        require(isinstance(pool, list) and len(pool) == len(set(pool)), "Malformed P2P mempool state")
        utxos = []
        for txid, vout in outpoints:
            output = parse_txout(net.rpc(index, "gettxout", txid, vout))
            utxos.append(None if output is None else {
                "value_sats": sats(output["value"]), "script": output["scriptPubKey"]["hex"],
                "confirmations": output["confirmations"], "coinbase": output["coinbase"], "bestblock": output["bestblock"]})
        all_outputs = net.rpc(index, "gettxoutsetinfo", "hash_serialized_3")
        require(all_outputs["bestblock"] == info["bestblockhash"] and all_outputs["height"] == info["blocks"],
                "P2P state changed during snapshot")
        nodes.append({"tip": info["bestblockhash"], "height": info["blocks"], "mempool": sorted(pool),
                      "utxos": utxos, "utxo_hash": all_outputs["hash_serialized_3"],
                      "utxo_count": all_outputs["txouts"], "total_sats": sats(all_outputs["total_amount"])})
    require(all(node == nodes[0] for node in nodes), "P2P nodes disagree on chain, mempool or UTXO state")
    require(owned_identity(net) == identity, "P2P fixture process changed during snapshot")
    return {"identity": identity, "outpoints": [list(outpoint) for outpoint in outpoints], "nodes": nodes}


def assert_same_state(before, after):
    require(before == after, "Invalid or replayed P2P traffic changed process or payment state")


class LogWindow:
    """Read only a fresh, bounded region of this owned fixture's node log."""
    def __init__(self, net, index):
        require(str(index) in owned_identity(net), "P2P log target is not owned")
        self.path = net.node(index) / "qludev/debug.log"
        meta = self.path.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == os.getuid(), "Unsafe P2P fixture log")
        self.identity = (meta.st_dev, meta.st_ino)
        self.offset = meta.st_size

    def lines(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            meta = os.fstat(fd)
            require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
                    and (meta.st_dev, meta.st_ino) == self.identity, "P2P fixture log was replaced")
            length = meta.st_size - self.offset
            require(0 <= length <= MAX_LOG_BYTES, "P2P log observation exceeded its byte limit")
            os.lseek(fd, self.offset, os.SEEK_SET)
            return os.read(fd, length).decode("utf-8", errors="replace").splitlines()
        finally:
            os.close(fd)

    def matched(self, reason, peer_id, txid=None, wtxid=None, *, command=None, payload_bytes=None):
        require(type(peer_id) is int and peer_id >= 0, "Invalid P2P log peer identifier")
        peer = re.compile(r"peer=" + str(peer_id) + r"(?![0-9])")
        lines = self.lines()
        if command is None:
            matches = [line for line in lines if reason in line and peer.search(line)
                       and (txid is None or txid in line) and (wtxid is None or wtxid in line)]
            if not matches:
                return None
            selected = [matches[-1]]
        else:
            # Upstream's deserialization exception line omits peer id. Pair the
            # exact command/size/peer receipt with its subsequent matching-size
            # exception inside this one-probe window. No other test peer sends
            # transactions concurrently; unrelated mesh traffic is unchanged.
            receipt = f"received: {command} ({payload_bytes} bytes)"
            exception = f"ProcessMessages({command}, {payload_bytes} bytes): Exception"
            selected = None
            for i, line in enumerate(lines):
                if receipt in line and peer.search(line):
                    for entry in lines[i + 1:]:
                        # The next dispatch receipt would make the peer-less
                        # exception ambiguous, even if its size matched.
                        if "received: " in entry:
                            break
                        if exception in entry and reason in entry:
                            selected = [line, entry]
                            break
                    if selected is not None:
                        break
            if selected is None:
                return None
        return {"peer_id": peer_id, "reason": reason, "correlation": "same-line" if command is None else "receipt-and-exception",
                "matched_line_sha256": [hashlib.sha256(line.encode()).hexdigest() for line in selected]}


def wait_log(net, window, reason, peer_id, **kwargs):
    deadline = min(net.work_deadline, time.monotonic() + 10)
    while time.monotonic() < deadline:
        net.check_deadline()
        result = window.matched(reason, peer_id, **kwargs)
        if result is not None:
            return result
        time.sleep(0.02)
    raise DevnetError("Expected peer-scoped P2P rejection evidence was absent")


def case_log(case):
    if case.name == "wrong-magic":
        return "Header error: Wrong MessageStart", {}
    if case.name.startswith("length-"):
        return "Header error: Size too large", {}
    if case.name == "wrong-checksum-ping":
        return "Header error: Wrong checksum", {}
    if case.name.startswith("command-"):
        return "Header error: Invalid message type", {}
    reason = ("non-canonical ReadCompactSize" if "noncanonical" in case.name else
              "ReadCompactSize(): size too large" if "oversized-compactsize" in case.name else "end of data")
    return reason, {"command": "ping" if case.name.startswith("short-ping-") else "tx", "payload_bytes": len(case.raw) - 24}


def hybrid_variants(signed):
    variants = []
    for index, name in ((2, "corrupt-mldsa"), (3, "corrupt-schnorr")):
        changed = CTransaction(signed)
        data = bytearray(changed.wit.vtxinwit[0].scriptWitness.stack[index]); data[0] ^= 1
        changed.wit.vtxinwit[0].scriptWitness.stack[index] = bytes(data)
        variants.append((name, changed, "qlu-hybrid-signature"))
    stripped = CTransaction(signed)
    stripped.wit.vtxinwit = []
    variants.append(("missing-witness", stripped, "qlu-witness-shape"))
    require(all(tx.txid_hex == signed.txid_hex for _, tx, _ in variants)
            and len({tx.wtxid_hex for _, tx, _ in variants} | {signed.wtxid_hex}) == 4,
            "P2P witness variants must preserve txid and have distinct wtxids")
    return variants


def verify_confirmed(net, payments):
    observations = []
    for payment in payments:
        require(hashlib.sha256(bytes.fromhex(payment["raw"])).hexdigest() == payment["transaction_sha256"], "P2P expected transaction changed")
        for node in range(4):
            raw = net.rpc(node, "getblock", payment["blockhash"], 0)
            require(type(raw) is str and len(raw) < 128 * 1024 * 2, "Oversized P2P payment block")
            require(hashlib.sha256(bytes.fromhex(raw)).hexdigest() == payment["block_sha256"], "Stored P2P payment block changed")
            block = from_hex(CBlock(), raw)
            require(len(block.vtx) == 2 and block.vtx[1].serialize_with_witness().hex() == payment["raw"],
                    "Confirmed P2P transaction bytes changed")
            output = parse_txout(net.rpc(node, "gettxout", payment["txid"], 0))
            require(output is not None and sats(output["value"]) == payment["output_sats"]
                    and output["scriptPubKey"]["hex"] == payment["recipient_script"] and output["confirmations"] >= 1,
                    "Confirmed P2P output mismatch")
        observations.append({"txid": payment["txid"], "blockhash": payment["blockhash"], "nodes": 4,
                             "transaction_sha256": payment["transaction_sha256"], "block_sha256": payment["block_sha256"]})
    return observations


def confirm_p2p(net, signed, mining_address, index):
    wait_mempools(net, {signed.txid_hex})
    hashes = net.rpc(index, "generatetoaddress", 1, mining_address)
    require(len(hashes) == 1, "Unexpected P2P confirmation block count")
    net.wait_synced(hashes[0])
    raw = net.rpc(index, "getblock", hashes[0], 0)
    block = from_hex(CBlock(), raw)
    coinbase_value = sum(out.nValue for out in block.vtx[0].vout)
    require(coinbase_value == 50 * 100000000 + FEE_SATS, "P2P coinbase does not include the exact payment fee")
    row = {"node": index, "txid": signed.txid_hex, "wtxid": signed.wtxid_hex,
           "raw": signed.serialize_with_witness().hex(), "blockhash": hashes[0],
           "block_sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
           "transaction_sha256": hashlib.sha256(signed.serialize_with_witness()).hexdigest(),
           "output_sats": signed.vout[0].nValue, "fee_sats": FEE_SATS, "coinbase_sats": coinbase_value,
           "recipient_script": bytes(signed.vout[0].scriptPubKey).hex()}
    verify_confirmed(net, [row])
    require(all(net.rpc(node, "getrawmempool") == [] for node in range(4)), "Unexpected P2P post-confirmation mempool")
    return row


def check_accounting(net, sender_script, recipient_script, payments):
    require(len(payments) == 4 and len({p["txid"] for p in payments}) == 4, "P2P payment count mismatch")
    fees = sum(row["fee_sats"] for row in payments)
    recipient_total = sum(row["output_sats"] for row in payments)
    require(fees == 4 * FEE_SATS and recipient_total + fees == 4 * 50 * 100000000, "P2P amounts or fees changed")
    expected = {(row["txid"], 0): (row["output_sats"], recipient_script.hex()) for row in payments}
    observations = []
    for index in range(4):
        recipient = net.rpc(index, "scantxoutset", "start", [f"raw({recipient_script.hex()})"])
        sender = net.rpc(index, "scantxoutset", "start", [f"raw({sender_script.hex()})"])
        require(recipient.get("success") is True and sender.get("success") is True
                and recipient["height"] == sender["height"] == FUNDING_BLOCKS + 4
                and recipient["bestblock"] == sender["bestblock"], "P2P account scan failed")
        received = {(row["txid"], row["vout"]): (sats(row["amount"]), row["scriptPubKey"]) for row in recipient["unspents"]}
        require(len(recipient["unspents"]) == 4 and received == expected and sats(recipient["total_amount"]) == recipient_total,
                "P2P recipient ledger mismatch")
        total = (FUNDING_BLOCKS + 4) * 50 * 100000000
        require(sats(sender["total_amount"]) + recipient_total == total and len(sender["unspents"]) == FUNDING_BLOCKS,
                "P2P total supply or sender ledger mismatch")
        require(all(row["scriptPubKey"] == sender_script.hex() for row in sender["unspents"]), "P2P sender script mismatch")
        info = net.rpc(index, "gettxoutsetinfo", "hash_serialized_3")
        require(info["txouts"] == FUNDING_BLOCKS + 4 and sats(info["total_amount"]) == total
                and info["height"] == recipient["height"] and info["bestblock"] == recipient["bestblock"],
                "P2P global UTXO accounting mismatch")
        observations.append({"height": info["height"], "tip": info["bestblock"], "utxo_hash": info["hash_serialized_3"],
                             "utxo_count": info["txouts"], "total_sats": total, "recipient_sats": recipient_total,
                             "sender_sats": sats(sender["total_amount"]), "fee_sats": fees})
    require(all(row == observations[0] for row in observations), "P2P account totals differ across nodes")
    return observations


def public_report(report):
    """Explicit console allowlist: no wallet material, raw txs, or exceptions.

    Hosted workers retain console output after their private evidence directory
    disappears. Preserve the case-level proof and source identity here without
    widening the output when new internal report fields are added.
    """
    def pick(row, names):
        return {name: row[name] for name in names if name in row}

    def proof(row):
        return pick(row, ("peer_id", "reason", "correlation", "matched_line_sha256"))

    def fingerprint(row):
        # Fingerprints come exclusively from the fixed inventory, never paths
        # or strings supplied by a remote peer.
        return {"sources": {path: value for path, value in row.get("sources", {}).items()
                            if path in SOURCE_PATHS},
                "binaries": pick(row.get("binaries", {}), ("bitcoind", "bitcoin-cli", "qlu-keytool")),
                **pick(row, ("corpus_sha256",))}

    def snapshot(row):
        return {"nodes": [{**pick(node, ("tip", "height", "utxo_hash", "utxo_count", "total_sats")),
                           "mempool_count": len(node.get("mempool", [])),
                           "relevant_utxos_sha256": hashlib.sha256(json.dumps(node.get("utxos", []),
                               sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
                          for node in row.get("nodes", [])]}

    result = pick(report, ("format", "attempt", "passed", "phase", "network", "genesis", "scope", "head",
                           "started_at", "finished_at", "cleanup", "error_type",
                           "peer_cleanup_error_type", "cleanup_error_type", "integrity_error_type", "evidence_error_type"))
    result["host"] = pick(report.get("host", {}), ("system", "machine", "python"))
    result["fixture_bytes"] = pick(report.get("fixture_bytes", {}), ("logical_bytes", "allocated_bytes", "files"))
    result["plan"] = pick(report.get("plan", {}), ("wire_cases_per_node", "nodes", "incomplete_client_closes_per_node",
        "hybrid_rejections_per_node", "funding_blocks", "payments", "work_limit_seconds", "disk_sample_limit_bytes",
        "log_window_limit_bytes", "sent_limit_per_node", "received_limit_per_node", "payload_limit_bytes"))
    result["checks"] = pick(report.get("checks", {}), ("fresh_owned_nodes_funded_and_out_of_ibd",
        "48_wire_cases_and_8_client_closed_partial_frames", "12_hybrid_rejections_then_four_original_p2p_payments",
        "restart_preserves_exact_blocks_transactions_and_utxos", "confirmed_p2p_replay_creates_no_payment_fee_or_balance_change"))
    for name in ("fingerprints_start", "fingerprints_end"):
        if name in report:
            result[name] = fingerprint(report[name])
    result["wire_cases"] = [{**pick(row, ("node", "name", "outcome", "bytes_sent")), "evidence": proof(row.get("evidence", {}))}
                            for row in report.get("wire_cases", [])]
    result["hybrid_rejections"] = [{**pick(row, ("node", "name", "txid", "wtxid", "reason")),
                                    "evidence": proof(row.get("evidence", {}))}
                                   for row in report.get("hybrid_rejections", [])]
    result["incomplete_observations"] = [{**pick(row, ("node", "name", "bytes_sent", "client_closed",
        "new_peer_ping_succeeded", "server_rejection_claimed")),
        "receipt": pick(row.get("receipt", {}), ("peer_id", "sent_bytes", "peer_bytes_received"))}
        for row in report.get("incomplete_observations", [])]
    result["controls"] = [{**pick(row, ("node", "fragmented_ping", "coalesced_ping_pair", "peer_id", "wtxid_relay")),
                           "fragment_receipts": [pick(receipt, ("peer_id", "sent_bytes", "peer_bytes_received"))
                                                 for receipt in row.get("fragment_receipts", [])]}
                          for row in report.get("controls", [])]
    result["payments"] = [pick(row, ("node", "txid", "wtxid", "blockhash", "block_sha256", "transaction_sha256",
                                    "output_sats", "fee_sats", "coinbase_sats", "recipient_script"))
                           for row in report.get("payments", [])]
    result["accounting"] = [pick(row, ("height", "tip", "utxo_hash", "utxo_count", "total_sats", "recipient_sats",
                                      "sender_sats", "fee_sats")) for row in report.get("accounting", [])]
    result["snapshots"] = [{"phase": row["phase"], "before": snapshot(row["before"]), "after": snapshot(row["after"]),
                            "owned_processes_unchanged": row["before"].get("identity") == row["after"].get("identity")}
                           for row in report.get("snapshots", [])]
    if "restart" in report:
        result["restart"] = {"verified": [pick(row, ("txid", "blockhash", "nodes", "transaction_sha256", "block_sha256"))
                                          for row in report["restart"].get("verified", [])],
                             "before": snapshot(report["restart"]["before"]), "after": snapshot(report["restart"]["after"])}
    if "confirmed_replay" in report:
        row = report["confirmed_replay"]
        result["confirmed_replay"] = {"nodes": row["nodes"], "unchanged": row["before"] == row["after"],
                                       "before": snapshot(row["before"]), "after": snapshot(row["after"])}
    result["wire_budgets"] = [pick(row, ("node", "sent_bytes", "received_bytes")) for row in report.get("wire_budgets", [])]
    result["ports_free"] = pick(report.get("ports_free", {}), tuple(str(port) for port in (*range(28440, 28444), *range(28540, 28544))))
    result["error_location"] = [pick(row, ("file", "line", "function")) for row in report.get("error_location", [])]
    return result


def run():
    identifier = uuid.uuid4().hex
    net = ResilienceNet(protocol.ROOT, identifier)
    report = {"format": "qlu-p2p-resilience-v1", "attempt": identifier, "passed": False, "phase": "setup",
              "network": protocol.NETWORK, "genesis": protocol.GENESIS, "checks": {}, "wire_cases": [],
              "incomplete_observations": [], "controls": [], "hybrid_rejections": [], "payments": [], "snapshots": [],
              "cleanup": "not-started", "started_at": datetime.now(timezone.utc).isoformat(),
              "host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
              "scope": "Fixed V1 corpus on four same-host localhost nodes, not V2, fuzzing, sustained load, independent operators or internet security acceptance.",
              "plan": {"wire_cases_per_node": 12, "nodes": 4, "incomplete_client_closes_per_node": 2,
                       "hybrid_rejections_per_node": 3, "funding_blocks": FUNDING_BLOCKS, "payments": 4,
                       "work_limit_seconds": MAX_WORK_SECONDS, "disk_sample_limit_bytes": 104857600,
                       "log_window_limit_bytes": MAX_LOG_BYTES, "sent_limit_per_node": 1048576,
                       "received_limit_per_node": 2097152, "payload_limit_bytes": 8192}}
    evidence = protocol.ROOT / ".local/evidence"
    failure, attempted_start = None, False
    peers, budget = [], WireBudget()
    with private_port_lock(protocol.ROOT):
        secure_directory(evidence)

        def save():
            # Transaction bytes are public synthetic evidence; seeds and RPC
            # cookies never enter this report or console output.
            text = json.dumps(report, indent=2) + "\n"
            write_private(evidence / f"p2p-resilience-{identifier}.json", text)
            write_private(evidence / "p2p-resilience-latest.json", text)

        def peer_for(index):
            peer = WirePeer(net, index, net.work_deadline, budget=budget, wtxid_relay=index % 2 == 0)
            peers.append(peer)
            return peer

        def close_peer(peer):
            peer.close()
            peer.wait_peer_removed()

        try:
            require(shutil.disk_usage(protocol.ROOT).free >= 1024 ** 3, "P2P drill requires one GiB free disk space")
            net.setup(); net.require_binaries(); net.require_stopped()
            net.work_deadline = time.monotonic() + MAX_WORK_SECONDS
            report["fingerprints_start"] = fingerprints()
            report["head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=protocol.ROOT, text=True, timeout=10).strip()
            save()
            attempted_start = True
            net.start()
            for index in range(4):
                logging = net.rpc(index, "logging", ["net", "mempoolrej"])
                require(logging.get("net") is True and logging.get("mempoolrej") is True, "P2P rejection logging unavailable")
            wallets = [recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS) for _ in range(2)]
            keys = [protocol.keytool(wallet) for wallet in wallets]
            scripts = [protocol.script_for(key) for key in keys]
            mining_address = protocol.address_for(keys[0])
            require(scripts[0] != scripts[1], "P2P fixture keys must differ")
            report["phase"] = "funding"
            hashes = net.rpc(0, "generatetoaddress", FUNDING_BLOCKS, mining_address)
            require(len(hashes) == FUNDING_BLOCKS and len(set(hashes)) == FUNDING_BLOCKS, "P2P funding count mismatch")
            net.wait_synced(hashes[-1])
            funding, payments = [], []
            for blockhash in hashes[:4]:
                block = net.rpc(0, "getblock", blockhash, 2)
                coinbase = block["tx"][0]
                output = coinbase["vout"][0]
                require(output["scriptPubKey"]["hex"] == scripts[0].hex() and sats(output["value"]) == 50 * 100000000,
                        "Unexpected P2P funding output")
                funding.append((coinbase["txid"], 0))
                tx = CTransaction()
                tx.vin = [CTxIn(COutPoint(int(coinbase["txid"], 16), 0), nSequence=0xffffffff)]
                tx.vout = [CTxOut(sats(output["value"]) - FEE_SATS, scripts[1])]
                payments.append(protocol.sign_transaction(wallets[0], tx, [CTxOut(sats(output["value"]), scripts[0])]))
            outpoints = funding + [(payment.txid_hex, 0) for payment in payments]
            initial = state_snapshot(net, outpoints)
            require(initial["nodes"][0]["mempool"] == [] and all(coin is not None and coin["confirmations"] >= 100
                    for coin in initial["nodes"][0]["utxos"][:4]), "P2P funding is not mature")
            report["initial_snapshot"] = initial
            report["checks"]["fresh_owned_nodes_funded_and_out_of_ibd"] = True
            fixture_size(net.data); save()

            for index in range(4):
                report["phase"] = f"wire-node-{index}"
                before = state_snapshot(net, outpoints)
                with peer_for(index) as peer:
                    receipts = peer.ping(1000 + index * 10, fragmented=True)
                    peer.begin_case()
                    peer.ping_pair(1001 + index * 10, 1002 + index * 10)
                    report["controls"].append({"node": index, "fragmented_ping": True, "coalesced_ping_pair": True,
                                               "peer_id": peer.peer_id, "wtxid_relay": index % 2 == 0,
                                               "fragment_receipts": receipts})
                    close_peer(peer)
                for number, case in enumerate(wire_cases()):
                    net.check_deadline()
                    with peer_for(index) as peer:
                        window = LogWindow(net, index)
                        peer.send_raw(case.raw)
                        if case.expected == "disconnect":
                            peer.wait_disconnect(); peer.wait_peer_removed()
                        else:
                            require(case.expected == "ignore", "Unexpected P2P corpus expectation")
                            peer.ping(2000 + index * 100 + number, forbidden_pongs=case.forbidden_pongs)
                        reason, kwargs = case_log(case)
                        observation = wait_log(net, window, reason, peer.peer_id, **kwargs)
                        report["wire_cases"].append({"node": index, "name": case.name, "outcome": case.expected,
                                                     "bytes_sent": len(case.raw), "evidence": observation})
                        close_peer(peer)
                for label, prefix in (("partial-header", 12), ("partial-payload", 28)):
                    with peer_for(index) as peer:
                        packet = frame(b"ping", (3000 + index).to_bytes(8, "little"))
                        peer.send_raw(packet[:prefix])
                        receipt = {"peer_id": peer.peer_id, "sent_bytes": peer.sent_bytes,
                                   "peer_bytes_received": peer.wait_received()}
                        # The sender intentionally closes. Do not claim the node
                        # rejected a valid-but-incomplete transport frame.
                        close_peer(peer)
                    with peer_for(index) as healthy:
                        healthy.ping(3100 + index)
                        close_peer(healthy)
                    net.verify_node(index)
                    report["incomplete_observations"].append({"node": index, "name": label,
                        "bytes_sent": prefix, "client_closed": True, "new_peer_ping_succeeded": True,
                        "server_rejection_claimed": False, "receipt": receipt})
                net.wait_connected(net.read_state())
                after = state_snapshot(net, outpoints)
                assert_same_state(before, after)
                report["snapshots"].append({"phase": f"wire-node-{index}", "before": before, "after": after})
                fixture_size(net.data); save()

                report["phase"] = f"hybrid-node-{index}"
                before = state_snapshot(net, outpoints)
                require(before["nodes"][0]["mempool"] == [], "Unexpected P2P pre-payment mempool")
                with peer_for(index) as peer:
                    for number, (name, changed, reason) in enumerate(hybrid_variants(payments[index])):
                        peer.begin_case()
                        window = LogWindow(net, index)
                        peer.send_message(b"tx", changed.serialize_with_witness())
                        peer.ping(4000 + index * 10 + number)
                        observed = wait_log(net, window, reason, peer.peer_id, txid=changed.txid_hex, wtxid=changed.wtxid_hex)
                        report["hybrid_rejections"].append({"node": index, "name": name, "txid": changed.txid_hex,
                            "wtxid": changed.wtxid_hex, "reason": reason, "evidence": observed})
                    after = state_snapshot(net, outpoints)
                    assert_same_state(before, after)
                    report["snapshots"].append({"phase": f"hybrid-node-{index}", "before": before, "after": after})
                    # Same peer and original transaction, exclusively through
                    # P2P. No RPC admission or broadcasting bypasses the cache.
                    peer.begin_case()
                    peer.send_message(b"tx", payments[index].serialize_with_witness())
                    peer.ping(4100 + index)
                    close_peer(peer)
                net.wait_connected(net.read_state())
                report["payments"].append(confirm_p2p(net, payments[index], mining_address, index))
                fixture_size(net.data); save()

            require(len(report["wire_cases"]) == 48 and len(report["hybrid_rejections"]) == 12
                    and len(report["incomplete_observations"]) == 8 and len(report["controls"]) == 4,
                    "P2P drill case count mismatch")
            report["checks"]["48_wire_cases_and_8_client_closed_partial_frames"] = True
            report["checks"]["12_hybrid_rejections_then_four_original_p2p_payments"] = True
            report["accounting"] = check_accounting(net, scripts[0], scripts[1], report["payments"])
            report["phase"] = "restart"
            before = state_snapshot(net, outpoints)
            net.stop(); net.start(); net.wait_synced(before["nodes"][0]["tip"])
            after = state_snapshot(net, outpoints)
            require(before["nodes"] == after["nodes"] and before["outpoints"] == after["outpoints"], "Restart changed P2P payment state")
            require(all(before["identity"][str(i)]["token"] != after["identity"][str(i)]["token"] for i in range(4)),
                    "P2P restart did not replace owned processes")
            report["restart"] = {"before": before, "after": after, "verified": verify_confirmed(net, report["payments"])}
            report["checks"]["restart_preserves_exact_blocks_transactions_and_utxos"] = True
            report["phase"] = "confirmed-replay"
            before = state_snapshot(net, outpoints)
            for index in range(4):
                with peer_for(index) as peer:
                    peer.send_message(b"tx", payments[index].serialize_with_witness())
                    peer.ping(5000 + index)
                    close_peer(peer)
            net.wait_connected(net.read_state())
            after = state_snapshot(net, outpoints)
            assert_same_state(before, after)
            require(check_accounting(net, scripts[0], scripts[1], report["payments"]) == report["accounting"],
                    "P2P replay changed payment accounting")
            report["confirmed_replay"] = {"before": before, "after": after, "nodes": 4}
            report["checks"]["confirmed_p2p_replay_creates_no_payment_fee_or_balance_change"] = True
            report["wire_budgets"] = budget.stats()
            report["fixture_bytes"] = fixture_size(net.data)
            report["passed"], report["phase"] = True, "complete"
        except BaseException as error:
            failure = error
            report["error_type"] = type(error).__name__
            report["error_location"] = [{"file": Path(row.filename).name, "line": row.lineno, "function": row.name}
                                        for row in traceback.extract_tb(error.__traceback__)]
        finally:
            # Socket close and owned-node cleanup remain possible after expiry.
            net.work_deadline = None
            for peer in peers:
                try:
                    peer.close()
                except BaseException as error:
                    failure = failure or error
                    report["peer_cleanup_error_type"] = type(error).__name__
            try:
                if attempted_start:
                    net.stop()
                require(all(row["status"] == "stopped" for row in net.status()), "P2P fixture nodes remain active")
                report["cleanup"] = "owned-nodes-stopped"
                report["ports_free"] = {str(port): net.port_free(port) for port in (*range(28440, 28444), *range(28540, 28544))}
                require(all(report["ports_free"].values()), "P2P fixture ports remain occupied")
            except BaseException as error:
                failure = failure or error
                report["cleanup"], report["cleanup_error_type"] = "needs-attention", type(error).__name__
            try:
                report["fingerprints_end"] = fingerprints()
                require(report.get("fingerprints_start") == report["fingerprints_end"], "P2P tooling or node binaries changed")
            except BaseException as error:
                failure = failure or error
                report["integrity_error_type"] = type(error).__name__
            report["passed"] = report["passed"] and failure is None
            report["wire_budgets"] = budget.stats()
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            try:
                save()
            except BaseException as error:
                failure = failure or error
                report["passed"], report["evidence_error_type"] = False, type(error).__name__
            if not report["passed"]:
                print(json.dumps(public_report(report), indent=2), flush=True)
    if failure is not None:
        raise DevnetError("Private P2P resilience failed; retained evidence records its phase") from None
    print(json.dumps(public_report(report), indent=2))
    return report


if __name__ == "__main__":
    try:
        run()
    except Exception:
        print("Private P2P resilience failed; inspect retained evidence.", file=sys.stderr)
        raise SystemExit(1)
