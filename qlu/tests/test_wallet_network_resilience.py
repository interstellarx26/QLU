"""Disconnected and changing node states must never authorize stale payments."""
from contextlib import nullcontext
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_wallet_app_network import FakeController, KEYS, OWN, ADDRESS, SOURCE, TIP, BLOCK
import wallet_app_network as app


class NetworkResilienceTests(unittest.TestCase):
    def setUp(self):
        self.network = app.WalletAppNetwork()
        self.controller = FakeController()
        self.network.controller = self.controller
        self.lock_patch = patch.object(app, "private_port_lock", return_value=nullcontext())
        self.lock_patch.start()
        self.network.start()
        self.network._faucet_wallet = {"disposable": True}
        self.network._faucet_keys = KEYS

    def tearDown(self):
        self.network.stop()
        self.lock_patch.stop()

    def test_no_peers_partial_mesh_and_duplicate_peers_cannot_prepare(self):
        original = self.controller.rpc
        for mode in ("none", "partition", "duplicate", "no_pong", "own_identity"):
            with self.subTest(mode=mode):
                def rpc(index, method, *args):
                    value = original(index, method, *args)
                    if method == "getpeerinfo":
                        if mode == "none": return []
                        if mode == "partition": return value[:1]
                        if mode == "duplicate": return [value[0]] * 3
                        if mode == "no_pong": return [{**p, "bytesrecv_per_msg": {}} for p in value]
                        if mode == "own_identity": return [{**value[0], "subver": f"/QLUWalletApp-{str(index) * 32}/"}]
                    return value
                with patch.object(self.controller, "rpc", side_effect=rpc), \
                        patch.object(app.time, "monotonic", side_effect=range(100)), \
                        patch.object(app.time, "sleep"), self.assertRaises(app.NetworkError) as caught:
                    self.network.prepare(KEYS, ADDRESS, "0.1")
                self.assertEqual(caught.exception.code, "network_identity")
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_disabled_network_cannot_sign_an_already_prepared_payment(self):
        prepared = self.network.prepare(KEYS, ADDRESS, "0.1")
        session = Mock(locked=False)
        original = self.controller.rpc
        def rpc(index, method, *args):
            if method == "getnetworkinfo" and index == 2: return {"networkactive": False}
            return original(index, method, *args)
        with patch.object(self.controller, "rpc", side_effect=rpc), self.assertRaises(app.NetworkError) as caught:
            self.network.send(session, prepared)
        self.assertEqual(caught.exception.code, "network_identity")
        session.sign.assert_not_called()
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_all_four_mempools_constrain_available_balance(self):
        original = self.controller.rpc
        def rpc(index, method, *args):
            if method == "gettxout" and index == 3: return None
            return original(index, method, *args)
        with patch.object(self.controller, "rpc", side_effect=rpc):
            self.assertEqual(self.network.balance(OWN)["balance"], "0.00000000")
            with self.assertRaises(app.NetworkError) as caught:
                self.network.prepare(KEYS, ADDRESS, "0.1")
        self.assertEqual(caught.exception.code, "insufficient_funds")
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_conflicting_node_metadata_cannot_produce_balance(self):
        original = self.controller.rpc
        for changed in ({"value": "2.10000000"}, {"bestblock": "ff" * 32}, {"coinbase": True}, {"confirmations": 99}):
            with self.subTest(changed=changed):
                def rpc(index, method, *args):
                    value = original(index, method, *args)
                    return {**value, **changed} if method == "gettxout" and index == 2 else value
                with patch.object(self.controller, "rpc", side_effect=rpc), self.assertRaises(app.NetworkError):
                    self.network.balance(OWN)

    def test_another_node_changes_chain_during_scan_balance_is_refused(self):
        original = self.controller.rpc
        scanned = [False]
        def rpc(index, method, *args):
            value = original(index, method, *args)
            if method == "scantxoutset": scanned[0] = True
            if scanned[0] and method == "getbestblockhash" and index == 3: return "ff" * 32
            return value
        with patch.object(self.controller, "rpc", side_effect=rpc), self.assertRaises(app.NetworkError):
            self.network.balance(OWN)

    def test_tip_change_after_earlier_node_output_check_stays_pending(self):
        prepared = self.network.prepare(KEYS, ADDRESS, "0.1")
        session = Mock(locked=False)
        session.sign.side_effect = lambda tx, spent: tx
        original = self.controller.rpc
        checked_last_node = [False]
        def rpc(index, method, *args):
            value = original(index, method, *args)
            if self.controller.tip == BLOCK and method == "gettxout" and index == 3:
                checked_last_node[0] = True
            if checked_last_node[0] and method == "getbestblockhash" and index == 0:
                return "ff" * 32
            return value
        marked = []
        with patch.object(self.controller, "rpc", side_effect=rpc), self.assertRaises(app.PaymentPending) as caught:
            self.network.send(session, prepared, before_broadcast=marked.append)
        self.assertEqual(len(marked), 1)
        self.assertEqual(caught.exception.txid, marked[0]["txid"])
        self.assertEqual(self.controller.broadcast_calls, 1)
        self.assertEqual(self.controller.mine_calls, 1)


if __name__ == "__main__":
    unittest.main()
