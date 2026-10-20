"""Wallet network boundaries without starting nodes or using secret key material."""
from contextlib import contextmanager
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocol
import wallet_app_network as app
from test_framework.messages import CTransaction, from_hex
from test_framework.segwit_addr import encode_segwit_address

OWN = b"\x52\x20" + bytes.fromhex("11" * 32)
TARGET = b"\x52\x20" + bytes.fromhex("22" * 32)
ADDRESS = encode_segwit_address("qlud", 2, TARGET[2:])
KEYS = {"key_commitment": OWN[2:].hex()}
TIP = "ab" * 32
BLOCK = "bc" * 32
SOURCE = "01" * 32


class FakeController:
    def __init__(self):
        self.root = Path(tempfile.gettempdir()) / "qlu-wallet-unit-test-not-created"
        self.process_label = "QLUWalletApp"
        self.live = False
        self.tip = TIP
        self.height = 101
        self.stop_calls = 0
        self.broadcast_calls = 0
        self.mine_calls = 0
        self.start_error = None
        self.stop_error = None
        self.preflight_error = None
        self.broadcast_error = None
        self.confirm_error = False
        self.reject_node = None
        self.altered_node = None
        self.state = {str(i): {"pid": 100 + i, "token": str(i) * 32} for i in range(4)}
        self.coins = {(SOURCE, 0): {"value": "2.00000000", "script": OWN, "height": 1, "coinbase": False}}
        self.pending = None
        self.checked_nodes = []

    def setup(self):
        pass

    def require_binaries(self):
        pass

    def require_stopped(self):
        if self.preflight_error:
            raise self.preflight_error
        if self.live:
            raise RuntimeError("already live")

    def start(self):
        self.live = True
        if self.start_error:
            raise self.start_error

    def stop(self):
        self.stop_calls += 1
        if self.stop_error:
            raise self.stop_error
        self.live = False

    def status(self):
        return [{"status": "running" if self.live else "stopped"} for _ in range(4)]

    def read_state(self):
        return self.state

    def owned(self, index, entry):
        return self.live

    def verify_node(self, index):
        if self.altered_node == index:
            raise RuntimeError("wrong genesis")
        return {"chain": protocol.NETWORK}

    def wait_synced(self, expected=None):
        if expected and expected != self.tip:
            raise RuntimeError("different tips")
        return self.tip

    def rpc(self, index, method, *args):
        if method == "getpeerinfo":
            return [{"addr": f"127.0.0.1:{28440 + n}", "subver": f"/QLUWalletApp-{str(n) * 32}/"}
                    for n in range(4) if n != index]
        if method == "getbestblockhash":
            return self.tip
        if method == "getblockcount":
            return self.height
        if method == "scantxoutset":
            script = bytes.fromhex(args[1][0][4:-1])
            return {"success": True, "bestblock": self.tip, "height": self.height, "unspents": [
                {"txid": txid, "vout": vout, "height": coin["height"], "amount": coin["value"],
                 "scriptPubKey": coin["script"].hex(), "coinbase": coin["coinbase"]}
                for (txid, vout), coin in self.coins.items() if coin["script"] == script]}
        if method == "gettxout":
            coin = self.coins.get((args[0], args[1]))
            if coin is None or (self.confirm_error and self.tip == BLOCK and index == 3):
                return ""
            return {"bestblock": self.tip, "value": coin["value"], "scriptPubKey": {"hex": coin["script"].hex()},
                    "coinbase": coin["coinbase"], "confirmations": self.height - coin["height"] + 1}
        if method == "testmempoolaccept":
            self.checked_nodes.append(index)
            return [{"allowed": index != self.reject_node}]
        if method == "sendrawtransaction":
            self.broadcast_calls += 1
            self.pending = from_hex(CTransaction(), args[0])
            if self.broadcast_error:
                raise self.broadcast_error
            return self.pending.txid_hex
        if method == "generateblock":
            self.mine_calls += 1
            tx = from_hex(CTransaction(), args[1][0])
            self.tip, self.height = BLOCK, self.height + 1
            for txin in tx.vin:
                self.coins.pop((f"{txin.prevout.hash:064x}", txin.prevout.n))
            for vout, output in enumerate(tx.vout):
                self.coins[(tx.txid_hex, vout)] = {"value": app.format_amount(output.nValue), "script": output.scriptPubKey,
                                                "height": self.height, "coinbase": False}
            return {"hash": BLOCK}
        if method == "generatetoaddress":
            raise RuntimeError("mock reward supply exhausted")
        raise AssertionError(method)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.network = app.WalletAppNetwork()
        self.controller = FakeController()
        self.network.controller = self.controller
        self.lock_depth = 0

        @contextmanager
        def lock(root):
            self.lock_depth += 1
            try:
                yield
            finally:
                self.lock_depth -= 1
        self.patch_lock = patch.object(app, "private_port_lock", lock)
        self.patch_lock.start()
        self.network._faucet_wallet = {"disposable": True}
        self.network._faucet_keys = KEYS

    def tearDown(self):
        self.controller.stop_error = None
        self.network.stop()
        self.patch_lock.stop()
        self.assertEqual(self.lock_depth, 0)

    def begin(self):
        self.network.start()
        return self.network.prepare(KEYS, ADDRESS, "0.999")

    @staticmethod
    def session():
        session = Mock(locked=False)
        session.sign.side_effect = lambda tx, spent: tx  # Nodes are mocks here; no cryptographic success claim.
        return session

    def test_port_lock_is_held_for_entire_lifecycle_and_second_start_refused(self):
        self.network.start()
        self.assertTrue(self.network.running)
        self.assertEqual(self.lock_depth, 1)
        with self.assertRaises(app.NetworkError) as caught:
            self.network.start()
        self.assertEqual(caught.exception.code, "already_running")
        self.assertEqual(self.controller.stop_calls, 0)
        self.network.stop()
        self.assertFalse(self.network.running)
        self.assertEqual(self.lock_depth, 0)

    def test_existing_network_is_not_adopted_or_stopped(self):
        self.controller.preflight_error = RuntimeError("another process")
        with self.assertRaises(app.NetworkError):
            self.network.start()
        self.assertEqual(self.controller.stop_calls, 0)
        self.assertEqual(self.lock_depth, 0)

    def test_partial_start_cleanup_and_error_do_not_echo_details(self):
        self.controller.start_error = RuntimeError("private rpc cookie")
        with self.assertRaises(app.NetworkError) as caught:
            self.network.start()
        self.assertNotIn("cookie", str(caught.exception))
        self.assertEqual(self.controller.stop_calls, 1)
        self.assertEqual(self.lock_depth, 0)

    def test_cleanup_failure_remains_visible_and_retains_port_lock_until_retry(self):
        self.network.start()
        self.controller.stop_error = RuntimeError("private node detail")
        with self.assertRaises(app.NetworkError) as caught:
            self.network.stop()
        self.assertEqual(caught.exception.code, "cleanup_failed")
        self.assertTrue(self.network.running)
        self.assertEqual(self.lock_depth, 1)
        self.controller.stop_error = None
        self.network.stop()
        self.assertFalse(self.network.running)
        self.assertEqual(self.lock_depth, 0)

    def test_failed_start_and_failed_cleanup_are_distinct(self):
        self.controller.start_error = RuntimeError("start failure")
        self.controller.stop_error = RuntimeError("cleanup failure")
        with self.assertRaises(app.NetworkError) as caught:
            self.network.start()
        self.assertEqual(caught.exception.code, "cleanup_failed")
        self.assertEqual(self.lock_depth, 1)

    def test_balance_separates_immature_rewards(self):
        self.network.start()
        self.controller.coins[("02" * 32, 0)] = {"value": "50.00000000", "script": OWN, "height": 100, "coinbase": True}
        result = self.network.balance(OWN)
        self.assertEqual(result["balance"], "2.00000000")
        self.assertEqual(result["immature_balance"], "50.00000000")
        self.assertEqual(len(result["utxos"]), 1)

    def test_coinbase_maturity_boundary_matches_next_block_spend(self):
        self.network.start()
        self.controller.coins[(SOURCE, 0)].update(coinbase=True, height=2)
        self.assertEqual(self.network.balance(OWN)["balance"], "2.00000000")
        self.controller.coins[(SOURCE, 0)]["height"] = 3
        self.assertEqual(self.network.balance(OWN)["balance"], "0.00000000")

    def test_balance_excludes_mempool_spent_inputs(self):
        self.network.start()
        original = self.controller.rpc
        def rpc(index, method, *args):
            return "" if method == "gettxout" else original(index, method, *args)
        with patch.object(self.controller, "rpc", side_effect=rpc):
            self.assertEqual(self.network.balance(OWN)["balance"], "0.00000000")

    def test_preview_uses_integer_amounts_and_change_to_sender(self):
        payment = self.begin()
        self.assertEqual(payment.public(), {"recipient": ADDRESS, "amount": "0.99900000", "fee": "0.00100000", "total": "1.00000000"})
        self.assertEqual([out.nValue for out in payment.tx.vout], [99_900_000, 100_000_000])
        self.assertEqual(payment.tx.vout[1].scriptPubKey, OWN)

    def test_exact_balance_has_no_zero_change_output(self):
        self.network.start()
        payment = self.network.prepare(KEYS, ADDRESS, "1.999")
        self.assertEqual(len(payment.tx.vout), 1)

    def test_selection_is_sorted_and_capped_at_sixteen(self):
        self.network.start()
        self.controller.coins = {(f"{i:064x}", 0): {"value": "0.10000000", "script": OWN, "height": 1, "coinbase": False}
                                 for i in range(20, 0, -1)}
        payment = self.network.prepare(KEYS, ADDRESS, "1.599")
        self.assertEqual([entry.prevout.hash for entry in payment.tx.vin], list(range(1, 17)))
        with self.assertRaises(app.NetworkError) as caught:
            self.network.prepare(KEYS, ADDRESS, "1.600")
        self.assertEqual(caught.exception.code, "insufficient_funds")

    def test_locked_wallet_cannot_sign(self):
        payment = self.begin()
        session = self.session()
        session.locked = True
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(session, payment)
        self.assertEqual(caught.exception.code, "wallet_locked")
        session.sign.assert_not_called()
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_stale_input_after_reorg_prevents_signing(self):
        payment = self.begin()
        self.controller.coins[(SOURCE, 0)]["script"] = TARGET
        session = self.session()
        with self.assertRaises(app.NetworkError):
            self.network.send(session, payment)
        session.sign.assert_not_called()
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_immature_input_after_reorg_prevents_signing(self):
        payment = self.begin()
        self.controller.coins[(SOURCE, 0)].update(height=100, coinbase=True)
        session = self.session()
        with self.assertRaises(app.NetworkError):
            self.network.send(session, payment)
        session.sign.assert_not_called()

    def test_every_operation_checks_network_identity_before_signing(self):
        payment = self.begin()
        self.controller.altered_node = 3
        session = self.session()
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(session, payment)
        self.assertEqual(caught.exception.code, "network_identity")
        session.sign.assert_not_called()

    def test_mutating_preview_outputs_or_spent_amounts_prevents_signing(self):
        payment = self.begin()
        payment.tx.vout[0].nValue -= 1
        session = self.session()
        with self.assertRaises(app.NetworkError):
            self.network.send(session, payment)
        session.sign.assert_not_called()
        payment = self.network.prepare(KEYS, ADDRESS, "0.999")
        payment.spent[0].nValue += 1
        with self.assertRaises(app.NetworkError):
            self.network.send(session, payment)
        session.sign.assert_not_called()

    def test_previews_cannot_cross_network_restart(self):
        payment = self.begin()
        self.network.stop()
        self.network.start()
        session = self.session()
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(session, payment)
        self.assertEqual(caught.exception.code, "stale_payment")
        session.sign.assert_not_called()

    def test_signing_error_redacts_secret_details(self):
        payment = self.begin()
        session = self.session()
        session.sign.side_effect = RuntimeError("private passphrase and seed")
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(session, payment)
        self.assertEqual(caught.exception.code, "signing_failed")
        self.assertNotIn("seed", str(caught.exception))
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_all_nodes_must_accept_before_broadcast(self):
        payment = self.begin()
        self.controller.reject_node = 3
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(self.session(), payment)
        self.assertEqual(caught.exception.code, "payment_rejected")
        self.assertEqual(self.controller.checked_nodes, [0, 1, 2, 3])
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_success_verifies_payment_change_and_spent_input_on_four_nodes(self):
        payment = self.begin()
        receipt = self.network.send(self.session(), payment)
        self.assertEqual(receipt["confirmed_nodes"], 4)
        self.assertEqual(receipt["txid"], payment.tx.txid_hex)
        self.assertEqual(receipt["block"], BLOCK)
        self.assertEqual(self.controller.mine_calls, 1)
        self.assertEqual(self.network.balance(OWN)["balance"], "1.00000000")

    def test_broadcast_timeout_exposes_txid_and_forbids_blind_retry(self):
        payment = self.begin()
        self.controller.broadcast_error = TimeoutError("RPC returned no result")
        with self.assertRaises(app.PaymentPending) as caught:
            self.network.send(self.session(), payment)
        self.assertEqual(caught.exception.txid, payment.tx.txid_hex)
        self.assertEqual(caught.exception.receipt["status"], "pending")
        self.assertIn("Do not send it again", str(caught.exception))
        self.assertEqual(self.controller.broadcast_calls, 1)

    def test_missing_fourth_node_confirmation_is_pending_not_success(self):
        payment = self.begin()
        self.controller.confirm_error = True
        with self.assertRaises(app.PaymentPending) as caught:
            self.network.send(self.session(), payment)
        self.assertEqual(caught.exception.txid, payment.tx.txid_hex)
        self.assertEqual(self.controller.broadcast_calls, 1)

    def test_faucet_uses_existing_ephemeral_keys_and_normal_payment_checks(self):
        self.network.start()
        with patch.object(protocol, "sign_transaction", side_effect=lambda wallet, tx, spent: tx) as sign:
            receipt = self.network.faucet(ADDRESS)
        self.assertEqual(receipt["amount"], "1.00000000")
        self.assertEqual(receipt["confirmed_nodes"], 4)
        sign.assert_called_once()
        self.network.stop()
        self.assertIsNone(self.network._faucet_wallet)
        self.assertIsNone(self.network._faucet_keys)

    def test_faucet_mining_failure_keeps_existing_chain(self):
        self.network.start()
        self.controller.coins.clear()
        with self.assertRaises(app.NetworkError) as caught:
            self.network.faucet(ADDRESS)
        self.assertEqual(caught.exception.code, "faucet_failed")
        self.assertEqual(self.controller.tip, TIP)
        self.assertEqual(self.controller.broadcast_calls, 0)


class ParsingTests(unittest.TestCase):
    def test_strict_amounts(self):
        for value in ("0", "-1", "+1", ".1", "1.", "1e1", "NaN", "Infinity", " 1", "1 ", "01", "1.000000001", "21000000", 1, 1.0, True, None):
            with self.subTest(value=value), self.assertRaises(app.NetworkError):
                app.parse_amount(value)
        self.assertEqual(app.parse_amount("0.00000001"), 1)
        self.assertEqual(app.parse_amount("20999999.999"), app.MAX_MONEY - app.FEE)
        self.assertEqual(app.parse_amount("1.12345678"), 112345678)

    def test_only_private_witness_two_addresses(self):
        self.assertEqual(app.address_script(ADDRESS), TARGET)
        self.assertEqual(app.address_script(ADDRESS.upper()), TARGET)
        for value in (encode_segwit_address("bc", 2, TARGET[2:]), encode_segwit_address("bcrt", 2, TARGET[2:]),
                      encode_segwit_address("qlud", 1, TARGET[2:]), encode_segwit_address("qlud", 2, bytes(20)),
                      ADDRESS[:-1] + ("q" if ADDRESS[-1] != "q" else "p"), ADDRESS.capitalize(), " " + ADDRESS, None):
            with self.subTest(value=value), self.assertRaises(app.NetworkError):
                app.address_script(value)

    def test_data_directory_names_cannot_escape_or_reuse_other_controllers(self):
        for value in ("../device-tests", "qlu-private-v1", "/tmp/other", "wallet-app-../bad", "wallet-app-"):
            with self.subTest(value=value), self.assertRaises(app.NetworkError):
                app.WalletAppNetwork(data_name=value)

    def test_rpc_amounts_reject_nonfinite_negative_fractional_and_boolean(self):
        for value in ("NaN", "Infinity", -1, "0.000000001", True, None, "21000001"):
            with self.subTest(value=value), self.assertRaises(app.NetworkError):
                app._rpc_amount(value)
        self.assertEqual(app._rpc_amount(0.999), 99_900_000)


if __name__ == "__main__":
    unittest.main()
