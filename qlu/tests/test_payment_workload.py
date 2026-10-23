"""Accounting and safety checks for the fixed, disposable node workload."""
import copy
from contextlib import contextmanager, redirect_stdout
import hashlib
import io
import json
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qlu import payment_workload as workload
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness


SCRIPTS = [b"\x52\x20" + bytes([index]) * 32 for index in range(4)]


def block_for(ledger, transactions=()):
    coinbase = create_coinbase(ledger.height + 1, script_pubkey=SCRIPTS[0],
                              fees=len(transactions) * workload.FEE_SATS, halving_period=150)
    block = create_block(int(ledger.tip, 16), coinbase, 1792368100 + ledger.height, txlist=list(transactions))
    add_witness_commitment(block)
    return block


def payment(outpoint, value, script=SCRIPTS[1]):
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(int(outpoint[0], 16), outpoint[1]), nSequence=0xffffffff)]
    tx.vout = [CTxOut(value - workload.FEE_SATS, script)]
    witness = CTxInWitness()
    witness.scriptWitness.stack = [bytes(1952), bytes(32), bytes(3309), bytes(64)]
    tx.wit.vtxinwit = [witness]
    return tx


def expected(*transactions):
    return {tx.txid_hex: tx.serialize_with_witness() for tx in transactions}


def scan_for(ledger):
    return {"success": True, "height": ledger.height, "bestblock": ledger.tip,
            "total_amount": str(Decimal(sum(value for value, _ in ledger.outputs.values())) / 100000000),
            "unspents": [{"txid": txid, "vout": index, "amount": str(Decimal(value) / 100000000), "scriptPubKey": script.hex()}
                         for (txid, index), (value, script) in ledger.outputs.items()]}


class WorkloadLedgerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = workload.Ledger(SCRIPTS)
        block = block_for(self.ledger)
        self.ledger.connect(block, {})
        self.outpoint = (block.vtx[0].txid_hex, 0)
        self.value = block.vtx[0].vout[0].nValue

    def assert_rejected_without_mutation(self, block, authorized):
        before = copy.deepcopy(vars(self.ledger))
        with self.assertRaises(workload.DevnetError):
            self.ledger.connect(block, authorized)
        self.assertEqual(vars(self.ledger), before)

    def test_actual_reward_fees_and_output_ledger(self):
        tx = payment(self.outpoint, self.value)
        row = self.ledger.connect(block_for(self.ledger, [tx]), expected(tx))
        self.assertNotIn(self.outpoint, self.ledger.outputs)
        self.assertEqual(self.ledger.outputs[(tx.txid_hex, 0)], (self.value - workload.FEE_SATS, SCRIPTS[1]))
        self.assertEqual(row["fee_sats"], workload.FEE_SATS)
        self.assertEqual(row["coinbase_sats"], 50 * 100000000 + workload.FEE_SATS)
        self.assertEqual(sum(value for value, _ in self.ledger.outputs.values()), 100 * 100000000)

    def test_height_149_to_150_uses_actual_halved_reward_plus_fees(self):
        ledger = workload.Ledger(SCRIPTS)
        ledger.height = 148
        first = block_for(ledger)
        self.assertEqual(ledger.connect(first, {})["coinbase_sats"], 50 * 100000000)
        tx = payment((first.vtx[0].txid_hex, 0), first.vtx[0].vout[0].nValue)
        second = ledger.connect(block_for(ledger, [tx]), expected(tx))
        self.assertEqual(second["subsidy_sats"], 25 * 100000000)
        self.assertEqual(second["coinbase_sats"], 25 * 100000000 + workload.FEE_SATS)
        self.assertEqual(ledger.coinbase_sats - ledger.fee_sats, 75 * 100000000)

    def test_changed_witness_with_same_txid_is_not_accepted(self):
        tx = payment(self.outpoint, self.value)
        authorized = expected(tx)
        old_txid = tx.txid_hex
        tx.wit.vtxinwit[0].scriptWitness.stack[2] = b"x" * 3309
        self.assertEqual(tx.txid_hex, old_txid)
        self.assert_rejected_without_mutation(block_for(self.ledger, [tx]), authorized)

    def test_missing_extra_or_duplicate_payments_are_rejected(self):
        tx = payment(self.outpoint, self.value)
        for transactions, authorized in (([], expected(tx)), ([tx], {}), ([tx, tx], expected(tx))):
            with self.subTest(count=len(transactions)):
                self.assert_rejected_without_mutation(block_for(self.ledger, transactions), authorized)

    def test_double_use_of_input_is_rejected_atomically(self):
        first = payment(self.outpoint, self.value, SCRIPTS[1])
        second = payment(self.outpoint, self.value, SCRIPTS[2])
        self.assert_rejected_without_mutation(block_for(self.ledger, [first, second]), expected(first, second))

    def test_bad_input_script_fee_or_reward_is_rejected(self):
        for change in ("input", "script", "fee", "reward", "previous"):
            tx = payment(self.outpoint, self.value)
            if change == "input":
                tx.vin[0].prevout.hash = 123
            if change == "script":
                tx.vout[0].scriptPubKey = b"\x51"
            if change == "fee":
                tx.vout[0].nValue -= 1
            block = block_for(self.ledger, [tx])
            if change == "reward":
                block.vtx[0].vout[0].nValue += 1
            if change == "previous":
                block.hashPrevBlock = 123
            with self.subTest(change=change):
                self.assert_rejected_without_mutation(block, expected(tx))

    def test_scan_proves_every_outpoint_value_script_and_total(self):
        scan = scan_for(self.ledger)
        self.ledger.verify_scan(scan)
        for change in ("duplicate", "missing", "value", "script", "tip", "total", "fraction", "vout-type"):
            altered = copy.deepcopy(scan)
            if change == "duplicate":
                altered["unspents"] *= 2
            elif change == "missing":
                altered["unspents"] = []
            elif change == "value":
                altered["unspents"][0]["amount"] = "49"
            elif change == "script":
                altered["unspents"][0]["scriptPubKey"] = SCRIPTS[1].hex()
            elif change == "tip":
                altered["bestblock"] = "00" * 32
            elif change == "total":
                altered["total_amount"] = "49"
            elif change == "fraction":
                altered["unspents"][0]["amount"] = "0.000000001"
            elif change == "vout-type":
                altered["unspents"][0]["vout"] = False
            with self.subTest(change=change), self.assertRaises(workload.DevnetError):
                self.ledger.verify_scan(altered)

    def test_other_nodes_must_store_exact_original_block_bytes(self):
        tx = payment(self.outpoint, self.value)
        block = block_for(self.ledger, [tx])
        class Network:
            def rpc(inner, index, *args):
                return block.serialize().hex() + ("00" if index == 2 else "")
        before = copy.deepcopy(vars(self.ledger))
        with self.assertRaises(workload.DevnetError):
            workload.read_block(Network(), block.hash_hex, expected(tx), self.ledger, all_nodes=True)
        self.assertEqual(vars(self.ledger), before)

    def test_workload_scripts_must_be_distinct(self):
        with self.assertRaises(workload.DevnetError):
            workload.Ledger([SCRIPTS[0]] * 4)

    def test_read_block_keeps_original_byte_fingerprint_for_restart(self):
        tx = payment(self.outpoint, self.value)
        block = block_for(self.ledger, [tx])
        raw = block.serialize()
        class Network:
            def rpc(inner, index, *args):
                return raw.hex()
        _, row = workload.read_block(Network(), block.hash_hex, expected(tx), self.ledger, all_nodes=True)
        self.assertEqual(row["block_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(row["serialized_bytes"], len(raw))
        self.assertEqual(row["payment_txids"], [tx.txid_hex])

    def test_checkpoint_detects_extra_global_outputs_or_node_disagreement(self):
        ledger = self.ledger
        class Network:
            mode = "valid"
            def verify_node(inner, index):
                pass
            def rpc(inner, index, method, *args):
                if method == "getbestblockhash":
                    return "ab" * 32 if inner.mode == "tip" and index == 2 else ledger.tip
                if method == "getrawmempool":
                    return ["ab" * 32] if inner.mode == "mempool" and index == 2 else []
                if method == "scantxoutset":
                    return scan_for(ledger)
                if method == "gettxoutsetinfo":
                    return {"height": ledger.height, "bestblock": ledger.tip,
                            "txouts": len(ledger.outputs) + (1 if inner.mode == "extra" else 0),
                            "total_amount": "51" if inner.mode == "total" else "50",
                            "hash_serialized_3": "ab" * 32 if inner.mode == "hash" and index == 2 else "cd" * 32}
                raise AssertionError(method)
        net = Network()
        self.assertEqual(workload.checkpoint(net, ledger)["total_sats"], 5000000000)
        for mode in ("tip", "mempool", "extra", "total", "hash"):
            net.mode = mode
            with self.subTest(mode=mode), self.assertRaises(workload.DevnetError):
                workload.checkpoint(net, ledger)

    def test_replay_accepts_only_original_identifier_or_known_already_mined(self):
        tx = payment(self.outpoint, self.value)
        class Network:
            mode = "valid"
            calls = 0
            def rpc(inner, index, method, raw):
                inner.calls += 1
                self.assertEqual((method, raw), ("sendrawtransaction", tx.serialize_with_witness().hex()))
                if inner.mode == "known-rejection" or inner.mode == "unknown-rejection":
                    raise workload.RpcError("private backend message", -27 if inner.mode == "known-rejection" else -25)
                return "ab" * 32 if inner.mode == "wrong-txid" else tx.txid_hex
        for mode in ("valid", "known-rejection"):
            net = Network(); net.mode = mode
            with patch.object(workload, "checkpoint", return_value={"tip": "original"}):
                rows, _ = workload.replay_confirmed(net, tx, self.ledger)
            self.assertEqual(net.calls, 4)
            self.assertEqual(len(rows), 4)
        for mode in ("wrong-txid", "unknown-rejection"):
            net = Network(); net.mode = mode
            with patch.object(workload, "checkpoint", return_value={"tip": "original"}), self.assertRaises(workload.DevnetError):
                workload.replay_confirmed(net, tx, self.ledger)
            self.assertEqual(net.calls, 1)
        with patch.object(workload, "checkpoint", side_effect=[{"tip": "original"}, {"tip": "changed"}]), \
                self.assertRaises(workload.DevnetError):
            workload.replay_confirmed(Network(), tx, self.ledger)


class WorkloadBoundaryTests(unittest.TestCase):
    def test_failure_summary_excludes_unknown_payloads(self):
        safe = {"phase": "setup", "passed": False, "error_type": "DevnetError", "cleanup": "owned-nodes-stopped"}
        report = {**safe, "master_seed": "private", "error": "private", "stdout": "private", "payments": ["private"]}
        self.assertEqual(workload.failure_summary(report), safe)

    def test_expired_work_still_stops_owned_nodes_and_reports_when_save_fails(self):
        secret = "disposable-secret-that-must-never-be-printed"
        events, saved = [], []
        @contextmanager
        def port_lock(root):
            (root / ".local").mkdir(mode=0o700)
            events.append("lock")
            try:
                yield
            finally:
                events.append("unlock")
        class Network:
            work_deadline = None
            def __init__(inner, root, identifier):
                inner.data = root / ".local" / ("payment-workload-" + identifier)
            def setup(inner):
                pass
            def require_binaries(inner):
                pass
            def require_stopped(inner):
                pass
            def start(inner):
                self.assertIsNotNone(inner.work_deadline)
                events.append("started-owned-fixture")
                inner.work_deadline = 0.0
                workload.WorkloadNet.check_deadline(inner)
            def stop(inner):
                self.assertIsNone(inner.work_deadline, "Expired work budget must not prevent owned cleanup")
                events.append("stopped-owned-fixture")
            def status(inner):
                return [{"status": "stopped"}] * 4
            def port_free(inner, port):
                return True
        # Capture the real deadline check before replacing the constructor.
        check_deadline = workload.WorkloadNet.check_deadline
        def save(path, contents):
            saved.append(json.loads(contents))
            if len(saved) > 2:
                raise OSError(secret)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(workload.protocol, "ROOT", Path(directory)), \
                patch.object(workload, "private_port_lock", port_lock), \
                patch.object(workload, "WorkloadNet", Network), \
                patch.object(Network, "check_deadline", check_deadline, create=True), \
                patch.object(workload, "fingerprints", return_value={"public": "fingerprint"}), \
                patch.object(workload.subprocess, "check_output", return_value="public-head"), \
                patch.object(workload, "resources", return_value={"phase": "stopped"}), \
                patch.object(workload, "write_private", side_effect=save), redirect_stdout(output):
            with self.assertRaisesRegex(workload.DevnetError, "Private payment workload failed"):
                workload.run()
        self.assertEqual(events, ["lock", "started-owned-fixture", "stopped-owned-fixture", "unlock"])
        self.assertFalse(saved[-1]["passed"])
        self.assertEqual(saved[-1]["cleanup"], "owned-nodes-stopped")
        self.assertIn('"evidence_error_type": "OSError"', output.getvalue())
        self.assertIn('"error_type": "DevnetError"', output.getvalue())
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn("fingerprint", output.getvalue())
        self.assertNotIn(directory, output.getvalue())

    def test_decimal_amounts_and_temporary_subsidy_boundaries(self):
        self.assertEqual(workload.sats("0.00000001"), 1)
        self.assertEqual(workload.sats(Decimal("25.004")), 2500400000)
        for value in (True, None, "nan", "inf", "-1", "0.000000001", "21000001", "bad"):
            with self.subTest(value=value), self.assertRaises(workload.DevnetError):
                workload.sats(value)
        self.assertEqual([workload.subsidy(height) for height in (149, 150, 299, 300)],
                         [5000000000, 2500000000, 2500000000, 1250000000])
        self.assertEqual(workload.subsidy(150 * 64), 0)

    def test_fixture_walk_rejects_links_and_sampled_size_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "public-fixture"
            path.write_bytes(b"abc")
            self.assertEqual(workload.fixture_size(root)["logical_bytes"], 3)
            with patch.object(workload, "MAX_FIXTURE_BYTES", 2), self.assertRaises(workload.DevnetError):
                workload.fixture_size(root)
            (root / "linked").symlink_to(path)
            with self.assertRaises(workload.DevnetError):
                workload.fixture_size(root)
            (root / "linked").unlink()
            (root / "hardlinked").hardlink_to(path)
            with self.assertRaises(workload.DevnetError):
                workload.fixture_size(root)

    def test_new_network_requires_uuid_and_never_reuses_existing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for identifier in ("../outside", "", "A" * 32, None):
                with self.assertRaises(workload.DevnetError):
                    workload.WorkloadNet(root, identifier)
            self.assertEqual(list(root.iterdir()), [])
            net = workload.WorkloadNet(root, "ab" * 16)
            net.data.mkdir(parents=True)
            with self.assertRaises(workload.DevnetError):
                workload.WorkloadNet(root, "ab" * 16)

    def test_expired_work_budget_never_calls_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            net = workload.WorkloadNet(Path(directory), "ab" * 16)
            net.work_deadline = 5
            with patch.object(workload.time, "monotonic", return_value=5), \
                    patch.object(workload.QLUPrivateNet, "rpc") as rpc:
                with self.assertRaises(workload.DevnetError):
                    net.rpc(0, "getbestblockhash")
                rpc.assert_not_called()

    def test_foreign_process_is_not_sampled(self):
        class Network:
            data = None
            def read_state(self):
                return {str(index): {"pid": index + 10} for index in range(4)}
            def owned(self, index, entry):
                return False
        with patch.object(workload, "fixture_size", return_value={}), \
                patch.object(workload.subprocess, "check_output") as ps:
            with self.assertRaises(workload.DevnetError):
                workload.resources(Network(), "public-fixture")
            ps.assert_not_called()

    def test_unexpected_mempool_transaction_is_not_retried(self):
        class Network:
            def rpc(self, *args):
                return ["foreign"]
        with patch.object(workload.time, "sleep") as sleep:
            with self.assertRaises(workload.DevnetError):
                workload.wait_mempools(Network(), {"expected"})
            sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
