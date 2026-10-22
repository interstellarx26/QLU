"""Durable broadcast boundary and active-chain reconciliation; no real keys/nodes."""
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_wallet_app_network import ADDRESS, BLOCK, KEYS, TIP, FakeController
import wallet_app_network as app
import protocol

TXID = "dd" * 32
COINBASE = "ee" * 32
ORPHAN = "ff" * 32


class HistoryController(FakeController):
    def __init__(self):
        super().__init__()
        self.blocks = {height: f"{height + 1000:064x}" for height in range(self.height + 1)}
        self.blocks[self.height] = self.tip
        self.transactions = {value: [COINBASE] for value in self.blocks.values()}
        self.headers = {value: height for height, value in self.blocks.items()}
        self.pools = [set() for _ in range(4)]
        self.calls = []
        self.divergent_node = None

    def rpc(self, index, method, *args):
        self.calls.append((index, method, args))
        if method == "getblockhash":
            if self.divergent_node == index:
                return ORPHAN
            return self.blocks[args[0]]
        if method == "getblockheader":
            return {"hash": args[0], "height": self.headers[args[0]]}
        if method == "getblock":
            height = self.headers[args[0]]
            return {"hash": args[0], "height": height,
                    "confirmations": self.height - height + 1 if self.blocks.get(height) == args[0] else -1,
                    "tx": self.transactions[args[0]]}
        if method == "getrawmempool":
            return sorted(self.pools[index])
        if method == "sendrawtransaction":
            try:
                return super().rpc(index, method, *args)
            finally:
                if self.pending is not None:
                    for pool in self.pools:
                        pool.add(self.pending.txid_hex)
        if method == "generateblock":
            payload = args[1][0]
            if len(payload) == 64:
                assert self.pending is not None and payload == self.pending.txid_hex
                assert payload in self.pools[index]
                raw = self.pending.serialize_with_witness().hex()
            else:
                raw = payload
            result = super().rpc(index, method, args[0], [raw])
            self.blocks[self.height] = self.tip
            self.headers[self.tip] = self.height
            self.transactions[self.tip] = [COINBASE, self.pending.txid_hex]
            for pool in self.pools:
                pool.discard(self.pending.txid_hex)
            return result
        return super().rpc(index, method, *args)


class PaymentStatusTests(unittest.TestCase):
    def setUp(self):
        self.network = app.WalletAppNetwork()
        self.controller = HistoryController()
        self.network.controller = self.controller
        self.network._faucet_wallet = {"synthetic": True}
        self.network._faucet_keys = KEYS

        @contextmanager
        def lock(root):
            yield
        self.lock_patch = patch.object(app, "private_port_lock", lock)
        self.lock_patch.start()
        self.network.start()

    def tearDown(self):
        self.network.stop()
        self.lock_patch.stop()

    def record(self, **changes):
        return {"txid": TXID, "recipient": ADDRESS, "amount": "0.99900000",
                "fee": "0.00100000", "start_height": 101, **changes}

    def payment(self):
        return self.network.prepare(KEYS, ADDRESS, "0.999")

    @staticmethod
    def session():
        return Mock(locked=False, sign=Mock(side_effect=lambda tx, spent: tx))

    def test_durable_callback_follows_preflight_and_precedes_first_broadcast(self):
        payment = self.payment()
        saved = []
        def save(record):
            self.assertEqual(self.controller.broadcast_calls, 0)
            self.assertEqual(self.controller.checked_nodes, [0, 1, 2, 3])
            saved.append(record)
        receipt = self.network.send(self.session(), payment, before_broadcast=save)
        self.assertEqual(saved, [self.record(txid=payment.tx.txid_hex,
                                            transaction=payment.tx.serialize_without_witness().hex(),
                                            signed_transaction=payment.tx.serialize_with_witness().hex(),
                                            spent_outputs=[{"value": out.nValue, "script": out.scriptPubKey.hex()}
                                                           for out in payment.spent])])
        self.assertEqual(receipt["start_height"], 101)
        self.assertEqual(self.controller.broadcast_calls, 1)

    def test_failed_durable_callback_prevents_broadcast_and_is_not_pending(self):
        def fail(record):
            raise OSError("private file detail")
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(self.session(), self.payment(), before_broadcast=fail)
        self.assertNotIsInstance(caught.exception, app.PaymentPending)
        self.assertEqual(caught.exception.code, "history_failed")
        self.assertNotIn("private file detail", str(caught.exception))
        self.assertEqual(self.controller.broadcast_calls, 0)
        self.assertEqual(self.controller.mine_calls, 0)

    def test_rejection_never_calls_durable_callback(self):
        payment = self.payment()
        self.controller.reject_node = 3
        save = Mock()
        with self.assertRaises(app.NetworkError):
            self.network.send(self.session(), payment, before_broadcast=save)
        save.assert_not_called()

    def test_boolean_height_is_refused_before_callback_or_broadcast(self):
        payment = self.payment()
        original = self.controller.rpc
        def rpc(index, method, *args):
            return True if method == "getblockcount" else original(index, method, *args)
        save = Mock()
        with patch.object(self.controller, "rpc", side_effect=rpc), self.assertRaises(app.NetworkError):
            self.network.send(self.session(), payment, before_broadcast=save)
        save.assert_not_called()
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_faucet_uses_same_durable_boundary(self):
        saved = []
        with patch.object(protocol, "sign_transaction", side_effect=lambda wallet, tx, spent: tx):
            receipt = self.network.faucet(ADDRESS, before_broadcast=saved.append)
        self.assertEqual(saved[0]["amount"], "1.00000000")
        self.assertEqual(saved[0]["txid"], receipt["txid"])
        self.assertEqual(saved[0]["start_height"], 101)

    def test_broadcast_timeout_leaves_a_record_that_reconciles_in_mempool(self):
        payment = self.payment()
        saved = []
        self.controller.broadcast_error = TimeoutError()
        with self.assertRaises(app.PaymentPending):
            self.network.send(self.session(), payment, before_broadcast=saved.append)
        result = self.network.payment_status(saved[0])
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["status_reason"], "mempool")
        self.assertEqual(self.controller.broadcast_calls, 1)
        self.assertEqual(self.controller.mine_calls, 0)

    def test_confirmation_uses_block_membership_with_all_outputs_already_spent(self):
        self.controller.transactions[TIP].append(TXID)
        self.controller.coins.clear()
        self.controller.calls.clear()
        result = self.network.payment_status(self.record())
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["confirmed_nodes"], 4)
        self.assertEqual(result["block"], TIP)
        self.assertFalse(any(method == "gettxout" for _, method, _ in self.controller.calls))
        self.assertEqual({index for index, method, _ in self.controller.calls if method == "getblock"}, {0, 1, 2, 3})

    def test_absence_is_pending_never_definitive_rejection(self):
        result = self.network.payment_status(self.record(), finish=True)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["status_reason"], "not_found")
        self.assertEqual(self.controller.mine_calls, 0)

    def test_finish_mines_existing_txid_only_without_signing_or_rebroadcast(self):
        payment = self.payment()
        saved = []
        session = self.session()
        self.controller.broadcast_error = TimeoutError()
        with self.assertRaises(app.PaymentPending):
            self.network.send(session, payment, before_broadcast=saved.append)
        result = self.network.payment_status(saved[0], finish=True)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["confirmed_nodes"], 4)
        self.assertEqual(self.controller.broadcast_calls, 1)
        session.sign.assert_called_once()
        generate = [args for _, method, args in self.controller.calls if method == "generateblock"]
        self.assertEqual(generate[0][1], [payment.tx.txid_hex])

    def test_divergent_active_blocks_cannot_confirm(self):
        self.controller.transactions[TIP].append(TXID)
        self.controller.headers[ORPHAN] = 101
        self.controller.transactions[ORPHAN] = [COINBASE]
        self.controller.divergent_node = 3
        result = self.network.payment_status(self.record())
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["status_reason"], "network_unavailable")

    def test_divergent_membership_in_one_node_cannot_confirm(self):
        self.controller.transactions[TIP].append(TXID)
        original = self.controller.rpc
        def rpc(index, method, *args):
            value = original(index, method, *args)
            if method == "getblock" and index == 3:
                return {**value, "tx": [COINBASE]}
            return value
        with patch.object(self.controller, "rpc", side_effect=rpc):
            result = self.network.payment_status(self.record())
        self.assertEqual(result["status_reason"], "network_unavailable")

    def test_tip_change_during_lookup_cannot_publish_stale_confirmation(self):
        self.controller.transactions[TIP].append(TXID)
        original = self.controller.rpc
        def rpc(index, method, *args):
            value = original(index, method, *args)
            if method == "getblock" and index == 3:
                self.controller.tip = BLOCK
            return value
        with patch.object(self.controller, "rpc", side_effect=rpc):
            result = self.network.payment_status(self.record())
        self.assertEqual(result["status_reason"], "network_unavailable")

    def test_finish_timeout_rechecks_existing_confirmation_without_new_payment(self):
        saved = []
        payment = self.payment()
        self.controller.broadcast_error = TimeoutError()
        with self.assertRaises(app.PaymentPending):
            self.network.send(self.session(), payment, before_broadcast=saved.append)
        original = self.controller.rpc
        def rpc(index, method, *args):
            value = original(index, method, *args)
            if method == "generateblock":
                raise TimeoutError()
            return value
        with patch.object(self.controller, "rpc", side_effect=rpc):
            result = self.network.payment_status(saved[0], finish=True)
        self.assertEqual(result["status"], "pending")
        checked = self.network.payment_status(saved[0], finish=True)
        self.assertEqual(checked["status"], "confirmed")
        self.assertEqual(self.controller.broadcast_calls, 1)
        self.assertEqual(self.controller.mine_calls, 1)

    def test_orphaned_saved_confirmation_is_downgraded_to_pending(self):
        self.controller.headers[ORPHAN] = 101
        self.controller.transactions[ORPHAN] = [COINBASE, TXID]
        result = self.network.payment_status(self.record(block=ORPHAN))
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["status_reason"], "not_found")
        self.assertNotIn("block", result)

    def test_remined_transaction_uses_new_active_block_not_saved_hint(self):
        self.controller.headers[ORPHAN] = 101
        self.controller.transactions[ORPHAN] = [COINBASE, TXID]
        self.controller.transactions[TIP].append(TXID)
        result = self.network.payment_status(self.record(block=ORPHAN))
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["block"], TIP)

    def test_partial_mempool_propagation_cannot_finish(self):
        self.controller.pools[0].add(TXID)
        result = self.network.payment_status(self.record(), finish=True)
        self.assertEqual(result["status_reason"], "network_unavailable")
        self.assertEqual(self.controller.mine_calls, 0)

    def test_wrong_node_identity_remains_pending_without_mining(self):
        self.controller.altered_node = 3
        result = self.network.payment_status(self.record(), finish=True)
        self.assertEqual(result["status_reason"], "network_unavailable")
        self.assertEqual(self.controller.mine_calls, 0)

    def test_empty_loopback_handshake_is_rechecked_then_accepted_only_when_owned(self):
        original = self.controller.rpc
        calls = []
        def rpc(index, method, *args):
            result = original(index, method, *args)
            if method == "getpeerinfo":
                calls.append(index)
                if len(calls) <= 4:
                    return result + [{"addr": "127.0.0.1:39999", "subver": ""}]
            return result
        with patch.object(self.controller, "rpc", side_effect=rpc), patch.object(app.time, "sleep") as sleep:
            self.assertEqual(self.network._validate(), TIP)
        self.assertEqual(calls, [0, 1, 2, 3, 0, 1, 2, 3])
        sleep.assert_called_once_with(0.05)

    def test_persistent_empty_handshake_fails_at_deadline(self):
        original = self.controller.rpc
        def rpc(index, method, *args):
            result = original(index, method, *args)
            return result + [{"addr": "127.0.0.1:39999", "subver": ""}] if method == "getpeerinfo" else result
        with patch.object(self.controller, "rpc", side_effect=rpc), \
                patch.object(app.time, "monotonic", side_effect=[0, 2.1]), \
                patch.object(app.time, "sleep") as sleep, self.assertRaises(app.NetworkError):
            self.network._validate()
        sleep.assert_not_called()

    def test_foreign_or_nonlocal_peer_fails_without_handshake_retry(self):
        original = self.controller.rpc
        for peer in ({"addr": "127.0.0.1:39999", "subver": "/Foreign/"},
                     {"addr": "198.51.100.1:39999", "subver": ""}):
            with self.subTest(peer=peer):
                def rpc(index, method, *args):
                    result = original(index, method, *args)
                    return result + [peer] if method == "getpeerinfo" else result
                with patch.object(self.controller, "rpc", side_effect=rpc), \
                        patch.object(app.time, "sleep") as sleep, self.assertRaises(app.NetworkError):
                    self.network._validate()
                sleep.assert_not_called()

    def test_changed_ownership_during_handshake_retry_fails(self):
        original = self.controller.rpc
        def rpc(index, method, *args):
            result = original(index, method, *args)
            return result + [{"addr": "127.0.0.1:39999", "subver": ""}] if method == "getpeerinfo" else result
        def change_owner(interval):
            self.controller.live = False
        with patch.object(self.controller, "rpc", side_effect=rpc), \
                patch.object(app.time, "sleep", side_effect=change_owner) as sleep, self.assertRaises(app.NetworkError):
            self.network._validate()
        sleep.assert_called_once_with(0.05)

    def test_scan_limit_is_bounded_and_does_not_claim_rejection(self):
        self.controller.height = app.PAYMENT_SCAN_LIMIT
        result = self.network.payment_status(self.record(start_height=0))
        self.assertEqual(result["status_reason"], "scan_limit")
        self.assertFalse(any(method == "getblock" for _, method, _ in self.controller.calls))

    def test_known_confirmed_block_can_be_verified_beyond_scan_limit(self):
        self.controller.height = app.PAYMENT_SCAN_LIMIT + 1
        self.controller.transactions[TIP].append(TXID)
        result = self.network.payment_status(self.record(start_height=0, block=TIP))
        self.assertEqual(result["status"], "confirmed")

    def test_scan_limit_still_allows_finishing_unanimous_existing_mempool_tx(self):
        saved = []
        payment = self.payment()
        self.controller.broadcast_error = TimeoutError()
        with self.assertRaises(app.PaymentPending):
            self.network.send(self.session(), payment, before_broadcast=saved.append)
        self.controller.height = app.PAYMENT_SCAN_LIMIT + 101
        pending = self.network.payment_status(saved[0])
        self.assertEqual(pending["status_reason"], "mempool")
        result = self.network.payment_status(saved[0], finish=True)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(self.controller.broadcast_calls, 1)
        generated = [args for _, method, args in self.controller.calls if method == "generateblock"]
        self.assertEqual(generated[0][1], [payment.tx.txid_hex])

    def test_malformed_records_are_rejected_before_network_queries(self):
        for changes in ({"txid": "bad"}, {"start_height": True}, {"start_height": -1},
                        {"block": "bad"}, {"amount": "1e0"}, {"fee": "0"}, {"recipient": "wrong"}):
            with self.subTest(changes=changes):
                self.controller.calls.clear()
                with self.assertRaises(app.NetworkError) as caught:
                    self.network.payment_status(self.record(**changes))
                self.assertEqual(caught.exception.code, "invalid_payment_record")
                self.assertFalse(self.controller.calls)


if __name__ == "__main__":
    unittest.main()
