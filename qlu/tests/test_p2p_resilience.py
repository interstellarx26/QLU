"""Failure-boundary checks for the fresh, owned QLU P2P integration drill."""
from contextlib import contextmanager, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from qlu import p2p_resilience as drill


class SnapshotNet:
    """Small deterministic RPC fixture; never starts or contacts a node."""
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else None
        self.state = {str(i): {"pid": 100 + i, "token": str(i) * 32} for i in range(4)}
        self.foreign = None
        self.change = None
        self.identity_reads = 0
        self.rpc_calls = []

    def read_state(self):
        self.identity_reads += 1
        state = copy.deepcopy(self.state)
        if self.change == "identity" and self.identity_reads > 1:
            state["2"]["token"] = "a" * 32
        return state

    def owned(self, index, entry):
        return index != self.foreign

    def node(self, index):
        return self.root / f"node{index}"

    def verify_node(self, index):
        return {"initialblockdownload": self.change == "ibd" and index == 2,
                "bestblockhash": "a" * 64, "blocks": 104}

    def rpc(self, index, method, *args):
        self.rpc_calls.append((index, method, args))
        changed = index == 2
        if method == "getrawmempool":
            if changed and self.change == "duplicate-pool":
                return ["c" * 64, "c" * 64]
            return ["c" * 64] if changed and self.change == "pool" else []
        if method == "gettxout":
            if changed and self.change == "missing-output":
                return None
            return {"value": 49 if changed and self.change == "value" else 50,
                    "scriptPubKey": {"hex": "5220" + "d" * 64}, "confirmations": 104,
                    "coinbase": True, "bestblock": "a" * 64}
        if method == "gettxoutsetinfo":
            return {"bestblock": "b" * 64 if changed and self.change == "tip" else "a" * 64,
                    "height": 105 if changed and self.change == "height" else 104,
                    "hash_serialized_3": ("e" if changed and self.change == "utxo-hash" else "f") * 64,
                    "txouts": 104, "total_amount": 5200}
        raise AssertionError(method)


class FreshFixtureTests(unittest.TestCase):
    def test_invalid_identifier_and_existing_or_linked_fixture_fail_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for identifier in ("", "../outside", "A" * 32, None, True):
                with self.subTest(identifier=identifier), self.assertRaises(drill.DevnetError):
                    drill.ResilienceNet(root, identifier)
            self.assertEqual(list(root.iterdir()), [])
            net = drill.ResilienceNet(root, "ab" * 16)
            net.data.mkdir(parents=True)
            with self.assertRaises(drill.DevnetError):
                drill.ResilienceNet(root, "ab" * 16)
            net.data.rmdir()
            net.data.symlink_to(root / "missing")
            with self.assertRaises(drill.DevnetError):
                drill.ResilienceNet(root, "ab" * 16)

    def test_expired_work_refuses_rpc_and_completion_after_deadline_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            net = drill.ResilienceNet(Path(directory), "ab" * 16)
            net.work_deadline = 5
            with patch.object(drill.time, "monotonic", return_value=5), \
                    patch.object(drill.QLUPrivateNet, "rpc") as rpc, self.assertRaises(drill.DevnetError):
                net.rpc(0, "getbestblockhash")
            rpc.assert_not_called()
            with patch.object(drill.time, "monotonic", side_effect=[4, 5]), \
                    patch.object(drill.QLUPrivateNet, "rpc", return_value="tip") as rpc, \
                    self.assertRaises(drill.DevnetError):
                net.rpc(0, "getbestblockhash")
            rpc.assert_called_once()


class StateBoundaryTests(unittest.TestCase):
    def test_cli_null_output_is_empty_text_and_normalizes_to_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            net = drill.ResilienceNet(Path(directory), "ab" * 16)
            completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with patch.object(drill.subprocess, "run", return_value=completed):
                absent = net.rpc(0, "gettxout", "c" * 64, 0)
            self.assertEqual(absent, "")
            self.assertIsNone(drill.parse_txout(absent))

    def test_snapshot_accepts_both_absent_output_encodings_but_not_malformed_results(self):
        for absent in (None, ""):
            net = SnapshotNet(); original_rpc = net.rpc
            def rpc(index, method, *args):
                return absent if method == "gettxout" else original_rpc(index, method, *args)
            with self.subTest(absent=absent), patch.object(net, "rpc", side_effect=rpc):
                snapshot = drill.state_snapshot(net, [("c" * 64, 0)])
            self.assertEqual([node["utxos"] for node in snapshot["nodes"]], [[None]] * 4)
        for malformed in ([], False, True, 0, 1, 0.0, "null", " ", "not-an-output"):
            net = SnapshotNet(); original_rpc = net.rpc
            def rpc(index, method, *args):
                return malformed if method == "gettxout" else original_rpc(index, method, *args)
            with self.subTest(malformed=malformed), patch.object(net, "rpc", side_effect=rpc), \
                    self.assertRaises(drill.DevnetError):
                drill.state_snapshot(net, [("c" * 64, 0)])

    def test_missing_or_foreign_process_refuses_snapshot_before_rpc(self):
        for mode in ("missing", "foreign"):
            net = SnapshotNet()
            if mode == "missing":
                del net.state["3"]
            else:
                net.foreign = 2
            with self.subTest(mode=mode), self.assertRaises(drill.DevnetError):
                drill.state_snapshot(net, [("c" * 64, 0)])
            self.assertEqual(net.rpc_calls, [])

    def test_snapshot_checks_each_node_and_process_identity(self):
        points = [("c" * 64, 0)]
        expected = drill.state_snapshot(SnapshotNet(), points)
        self.assertEqual(len(expected["nodes"]), 4)
        self.assertEqual(expected["nodes"][0]["utxos"][0]["value_sats"], 5000000000)
        for mode in ("ibd", "pool", "duplicate-pool", "missing-output", "value", "tip", "height", "utxo-hash", "identity"):
            net = SnapshotNet(); net.change = mode
            with self.subTest(mode=mode), self.assertRaises(drill.DevnetError):
                drill.state_snapshot(net, points)

    def test_replay_comparison_rejects_common_changes_on_all_nodes(self):
        before = drill.state_snapshot(SnapshotNet(), [("c" * 64, 0)])
        drill.assert_same_state(before, copy.deepcopy(before))
        for key, value in (("tip", "b" * 64), ("height", 105), ("mempool", ["c" * 64]),
                           ("utxo_hash", "e" * 64), ("total_sats", 0)):
            changed = copy.deepcopy(before)
            for node in changed["nodes"]:
                node[key] = value
            with self.subTest(key=key), self.assertRaises(drill.DevnetError):
                drill.assert_same_state(before, changed)


class LogEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.net = SnapshotNet(self.directory.name)
        self.path = self.net.node(0) / "qludev/debug.log"
        self.path.parent.mkdir(parents=True)
        self.path.write_text("old rejection peer=12\n")
        self.window = drill.LogWindow(self.net, 0)

    def append(self, text):
        with self.path.open("a") as output:
            output.write(text)

    def test_only_fresh_exact_peer_and_transaction_evidence_matches(self):
        txid, wtxid = "a" * 64, "b" * 64
        self.assertIsNone(self.window.matched("old rejection", 12))
        self.append(f"{txid} (wtxid={wtxid}) from peer=123 was not accepted: qlu-hybrid-signature\n")
        self.assertIsNone(self.window.matched("qlu-hybrid-signature", 12, txid, wtxid))
        self.append(f"{txid} (wtxid={wtxid}) from peer=12 was not accepted: qlu-hybrid-signature\n")
        result = self.window.matched("qlu-hybrid-signature", 12, txid, wtxid)
        self.assertEqual(result["peer_id"], 12)
        self.assertEqual(len(result["matched_line_sha256"]), 1)
        self.assertNotIn(txid, json.dumps(result))
        self.assertIsNone(self.window.matched("qlu-hybrid-signature", 12, "c" * 64, wtxid))
        self.assertIsNone(self.window.matched("qlu-hybrid-signature", 12, txid, "c" * 64))
        with self.assertRaises(drill.DevnetError):
            self.window.matched("qlu-hybrid-signature", True)

    def test_parser_exception_needs_our_receipt_before_matching_exception(self):
        self.append("ProcessMessages(tx, 0 bytes): Exception 'end of data' caught\n")
        self.assertIsNone(self.window.matched("end of data", 12, command="tx", payload_bytes=0))
        self.append("received: tx (0 bytes) peer=12\nProcessMessages(tx, 0 bytes): Exception 'end of data' caught\n")
        result = self.window.matched("end of data", 12, command="tx", payload_bytes=0)
        self.assertEqual(result["correlation"], "receipt-and-exception")
        self.assertEqual(len(result["matched_line_sha256"]), 2)

    def test_intervening_foreign_receipt_cannot_lend_its_exception_to_our_peer(self):
        self.append("received: tx (0 bytes) peer=12\nreceived: tx (0 bytes) peer=123\n"
                    "ProcessMessages(tx, 0 bytes): Exception 'end of data' caught\n")
        self.assertIsNone(self.window.matched("end of data", 12, command="tx", payload_bytes=0))

    def test_replaced_truncated_oversized_and_linked_logs_fail_closed(self):
        for mode in ("replace", "truncate", "oversize", "link"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                net = SnapshotNet(directory)
                path = net.node(0) / "qludev/debug.log"
                path.parent.mkdir(parents=True); path.write_text("baseline\n")
                window = drill.LogWindow(net, 0)
                if mode == "replace":
                    path.rename(path.with_name("original.log")); path.write_text("replacement\n")
                elif mode == "truncate":
                    path.write_text("")
                elif mode == "oversize":
                    with path.open("a") as output: output.write("x" * (drill.MAX_LOG_BYTES + 1))
                else:
                    path.with_name("linked.log").hardlink_to(path)
                with self.assertRaises(drill.DevnetError):
                    window.lines()

    def test_fifo_replacement_cannot_block_before_file_type_validation(self):
        self.path.unlink()
        os.mkfifo(self.path)
        original_open = os.open
        def bounded_open(path, flags, *args, **kwargs):
            # Guard the regression itself from hanging if NONBLOCK is removed.
            # A pre-open type rejection is also an acceptable implementation.
            self.assertTrue(flags & os.O_NONBLOCK, "Opening a replaced FIFO must not block")
            return original_open(path, flags, *args, **kwargs)
        with patch.object(drill.os, "open", side_effect=bounded_open), self.assertRaises(drill.DevnetError):
            self.window.lines()


class PaymentAndReportTests(unittest.TestCase):
    def payment_fixture(self):
        from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
        document = json.loads((Path(drill.__file__).parent / "conformance_vectors.json").read_text())
        transaction = drill.from_hex(drill.CTransaction(), document["reference_signed_transaction"])
        block = create_block(1234, create_coinbase(105, script_pubkey=transaction.vout[0].scriptPubKey),
                             1792368100, txlist=[transaction])
        add_witness_commitment(block)
        raw = transaction.serialize_with_witness().hex()
        blockraw = block.serialize().hex()
        payment = {"raw": raw, "transaction_sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
                   "blockhash": block.hash_hex, "block_sha256": hashlib.sha256(bytes.fromhex(blockraw)).hexdigest(),
                   "txid": transaction.txid_hex, "output_sats": transaction.vout[0].nValue,
                   "recipient_script": bytes(transaction.vout[0].scriptPubKey).hex()}
        return transaction, blockraw, payment

    def test_bad_witnesses_keep_original_txid_and_distinct_wtxids_without_mutating_original(self):
        transaction, _, _ = self.payment_fixture()
        original = transaction.serialize_with_witness()
        variants = drill.hybrid_variants(transaction)
        self.assertEqual(transaction.serialize_with_witness(), original)
        self.assertEqual([name for name, _, _ in variants], ["corrupt-mldsa", "corrupt-schnorr", "missing-witness"])
        self.assertTrue(all(tx.txid_hex == transaction.txid_hex for _, tx, _ in variants))
        self.assertEqual(len({tx.wtxid_hex for _, tx, _ in variants} | {transaction.wtxid_hex}), 4)
        self.assertEqual([reason for _, _, reason in variants],
                         ["qlu-hybrid-signature", "qlu-hybrid-signature", "qlu-witness-shape"])

    def test_confirmations_require_exact_block_bytes_and_unspent_recipient_on_each_node(self):
        _, blockraw, payment = self.payment_fixture()
        class Network:
            mode = None
            def rpc(inner, index, method, *args):
                if method == "getblock":
                    return blockraw[:-2] + "ff" if inner.mode == "block" and index == 3 else blockraw
                if method == "gettxout":
                    if inner.mode == "spent" and index == 3: return None
                    return {"value": payment["output_sats"] / 100000000,
                            "scriptPubKey": {"hex": "00" if inner.mode == "recipient" and index == 3 else payment["recipient_script"]},
                            "confirmations": 0 if inner.mode == "unconfirmed" and index == 3 else 1}
                raise AssertionError(method)
        net = Network()
        self.assertEqual(drill.verify_confirmed(net, [payment])[0]["nodes"], 4)
        for mode in ("block", "spent", "recipient", "unconfirmed"):
            net.mode = mode
            with self.subTest(mode=mode), self.assertRaises(drill.DevnetError):
                drill.verify_confirmed(net, [payment])

    def test_confirmed_output_rejects_both_absent_encodings_and_malformed_results(self):
        _, blockraw, payment = self.payment_fixture()
        for output in (None, "", [], False, True, 0, 1, 0.0, "null", " ", "not-an-output"):
            class Network:
                def rpc(inner, index, method, *args):
                    if method == "getblock": return blockraw
                    if method == "gettxout": return output
                    raise AssertionError(method)
            with self.subTest(output=output), self.assertRaises(drill.DevnetError):
                drill.verify_confirmed(Network(), [payment])

    def test_public_summary_preserves_evidence_but_drops_private_and_unexpected_fields(self):
        secret = "MUST-NOT-APPEAR-IN-CONSOLE"
        snapshot = drill.state_snapshot(SnapshotNet(), [("c" * 64, 0)])
        snapshot["identity"]["0"]["token"] = secret
        source = drill.SOURCE_PATHS[0]
        report = {"format": "qlu-p2p-resilience-v1", "attempt": "ab" * 16, "passed": True,
                  "phase": "complete", "master_seed": secret, "cookie": secret, "exception": secret,
                  "fixture_bytes": {"logical_bytes": 100, "allocated_bytes": 200, "files": 4, "private": secret},
                  "checks": {"fresh_owned_nodes_funded_and_out_of_ibd": True, "unexpected": secret},
                  "fingerprints_end": {"sources": {source: "a" * 64, secret: secret},
                      "binaries": {"bitcoind": "b" * 64, "unexpected": secret}, "corpus_sha256": "c" * 64},
                  "wire_cases": [{"node": 0, "name": "wrong-magic", "outcome": "disconnect", "raw": secret,
                      "evidence": {"peer_id": 12, "reason": "Wrong MessageStart", "matched_line_sha256": ["d" * 64], "raw_log": secret}}],
                  "payments": [{"node": 0, "txid": "e" * 64, "raw": secret, "seed": secret, "fee_sats": 100000}],
                  "snapshots": [{"phase": "wire-node-0", "before": snapshot, "after": copy.deepcopy(snapshot)}],
                  "confirmed_replay": {"nodes": 4, "before": snapshot, "after": copy.deepcopy(snapshot)},
                  "error_location": [{"file": "p2p_resilience.py", "line": 1, "function": "run", "locals": secret}],
                  "ports_free": {"28440": True, "unexpected": secret}}
        public = drill.public_report(report)
        self.assertNotIn(secret, json.dumps(public))
        self.assertEqual(public["fingerprints_end"]["sources"], {source: "a" * 64})
        self.assertEqual(public["wire_cases"][0]["evidence"]["matched_line_sha256"], ["d" * 64])
        self.assertEqual(public["payments"][0]["fee_sats"], 100000)
        self.assertEqual(public["fixture_bytes"], {"logical_bytes": 100, "allocated_bytes": 200, "files": 4})
        self.assertTrue(public["snapshots"][0]["owned_processes_unchanged"])
        self.assertTrue(public["confirmed_replay"]["unchanged"])


class LifecycleFailureTests(unittest.TestCase):
    def exercise_failure(self, mode):
        secret = "DISPOSABLE-SECRET-MUST-NOT-ESCAPE"
        events, saved = [], []
        @contextmanager
        def lock(root):
            (root / ".local").mkdir(mode=0o700)
            events.append("lock")
            try: yield
            finally: events.append("unlock")
        class Network:
            work_deadline = None
            def __init__(inner, root, identifier): inner.data = root / ".local" / ("p2p-resilience-" + identifier)
            def setup(inner): pass
            def require_binaries(inner): pass
            def require_stopped(inner):
                if mode == "occupied": raise drill.DevnetError(secret)
            def start(inner):
                self.assertIsNotNone(inner.work_deadline)
                events.append("start"); inner.work_deadline = 0
                raise drill.DevnetError(secret)
            def stop(inner):
                self.assertIsNone(inner.work_deadline)
                events.append("stop")
                if mode == "cleanup": raise OSError(secret)
            def status(inner): return [{"status": "stopped"}] * 4
            def port_free(inner, port): return not (mode in ("occupied", "port") and port == 28440)
        def save(path, text):
            saved.append(json.loads(text))
            if mode == "evidence" and len(saved) > 2: raise OSError(secret)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(drill.protocol, "ROOT", Path(directory)), \
                patch.object(drill, "private_port_lock", lock), patch.object(drill, "ResilienceNet", Network), \
                patch.object(drill, "fingerprints", return_value={"public": "digest"}), \
                patch.object(drill.subprocess, "check_output", return_value="public-head"), \
                patch.object(drill.shutil, "disk_usage", return_value=type("Disk", (), {"free": 2 ** 32})()), \
                patch.object(drill, "write_private", side_effect=save), redirect_stdout(output):
            with self.assertRaisesRegex(drill.DevnetError, "Private P2P resilience failed"):
                drill.run()
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn(directory, output.getvalue())
        self.assertFalse(saved[-1]["passed"])
        return events, saved[-1], output.getvalue()

    def test_occupied_foreign_port_never_starts_or_stops_a_network(self):
        events, report, _ = self.exercise_failure("occupied")
        self.assertEqual(events, ["lock", "unlock"])
        self.assertEqual(report["cleanup"], "needs-attention")

    def test_expired_start_still_stops_owned_network_before_unlock(self):
        events, report, _ = self.exercise_failure("start")
        self.assertEqual(events, ["lock", "start", "stop", "unlock"])
        self.assertEqual(report["cleanup"], "owned-nodes-stopped")
        self.assertTrue(all(report["ports_free"].values()))

    def test_failed_cleanup_or_occupied_port_cannot_report_complete_cleanup(self):
        for mode in ("cleanup", "port"):
            with self.subTest(mode=mode):
                events, report, _ = self.exercise_failure(mode)
                self.assertEqual(events, ["lock", "start", "stop", "unlock"])
                self.assertEqual(report["cleanup"], "needs-attention")

    def test_evidence_failure_does_not_prevent_cleanup_or_leak_exception(self):
        events, _, output = self.exercise_failure("evidence")
        self.assertEqual(events, ["lock", "start", "stop", "unlock"])
        self.assertIn('"evidence_error_type": "OSError"', output)


if __name__ == "__main__":
    unittest.main()
