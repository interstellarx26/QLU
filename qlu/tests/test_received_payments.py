"""Incoming receipts derive from canonical transactions and four-node undo data."""
from contextlib import contextmanager
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_wallet_app_network import OWN, TARGET, ADDRESS, KEYS, TIP, BLOCK
from test_wallet_payment_status import HistoryController, COINBASE, ORPHAN
import wallet_app_network as app
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.segwit_addr import encode_segwit_address


class ReceivedController(HistoryController):
    rpc_budget = app._AppNet.rpc_budget

    def __init__(self):
        super().__init__()
        self.transaction = CTransaction()
        self.transaction.vin = [CTxIn(COutPoint(int('12' * 32, 16), 0), b'', 0xffffffff)]
        self.transaction.vout = [CTxOut(10_000_000, TARGET), CTxOut(189_900_000, OWN)]
        self.verbose = {}
        self.install()
        self.transform = lambda index, value: value

    def install(self, *, previous=OWN):
        self.txid = self.transaction.txid_hex
        self.transactions[self.tip] = [COINBASE, self.txid]
        self.verbose[self.txid] = {
            'txid': self.txid, 'hex': self.transaction.serialize_with_witness().hex(),
            'vin': [{'txid': f'{item.prevout.hash:064x}', 'vout': item.prevout.n,
                     'prevout': {'value': '2.00000000', 'scriptPubKey': {'hex': previous.hex()}}}
                    for item in self.transaction.vin]}

    def rpc(self, index, method, *args):
        if getattr(self, '_rpc_deadline', None) is not None and app.time.monotonic() >= self._rpc_deadline:
            raise TimeoutError()
        value = super().rpc(index, method, *args)
        if method == 'getblock' and args[1] == 3:
            value = {**value, 'tx': [copy.deepcopy(self.verbose.get(txid, {'txid': txid})) for txid in value['tx']]}
            value = self.transform(index, value)
        return value


class ReceivedPaymentTests(unittest.TestCase):
    def setUp(self):
        self.network = app.WalletAppNetwork()
        self.controller = ReceivedController()
        self.network.controller = self.controller
        self.network._faucet_wallet = {'synthetic': True}
        self.network._faucet_keys = KEYS
        @contextmanager
        def lock(root):
            yield
        self.lock_patch = patch.object(app, 'private_port_lock', lock)
        self.lock_patch.start()
        self.network.start()

    def tearDown(self):
        self.network.stop()
        self.lock_patch.stop()

    def verify(self, txid=None, script=TARGET, **kwargs):
        return self.network.verify_received_payment(txid or self.controller.txid, script, **kwargs)

    def rejected(self, code, **kwargs):
        with self.assertRaises(app.NetworkError) as caught:
            self.verify(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_actual_outputs_are_summed_and_all_four_nodes_verify(self):
        self.controller.transaction.vout.insert(1, CTxOut(2_000_000, TARGET))
        self.controller.install()
        value = self.verify()
        self.assertEqual(value, {'txid': self.controller.txid, 'block': TIP, 'start_height': 101,
                                 'recipient': ADDRESS, 'amount': '0.12000000', 'confirmed_nodes': 4})
        self.assertEqual({i for i, method, args in self.controller.calls if method == 'getblock' and args[1] == 3}, {0, 1, 2, 3})
        self.assertFalse(any(method in {'gettxout', 'sendrawtransaction', 'generateblock', 'getrawtransaction'}
                             for _, method, _ in self.controller.calls))

    def test_spent_received_outputs_remain_verifiable(self):
        self.controller.coins.clear()
        self.assertEqual(self.verify()['amount'], '0.10000000')

    def test_display_metadata_cannot_supply_the_received_amount_or_address(self):
        self.controller.verbose[self.controller.txid]['vout'] = [
            {'value': '2000.00000000', 'scriptPubKey': {'address': ADDRESS, 'hex': OWN.hex()}}]
        self.assertEqual(self.verify()['amount'], '0.10000000')

    def test_invalid_transaction_ids_are_refused_before_rpc(self):
        for value in ('ABCDEF' * 10, 'A' * 64, 'gg' * 32, '00' * 31, True, '11' * 32 + ' '):
            with self.subTest(value=value):
                before = len(self.controller.calls)
                self.rejected('invalid_transaction', txid=value)
                self.assertEqual(len(self.controller.calls), before)

    def test_unknown_transaction_is_not_recorded(self):
        self.rejected('incoming_not_found', txid='ff' * 32)

    def test_wrong_recipient_is_refused(self):
        self.rejected('incoming_not_received', script=b'\x52\x20' + b'\x99' * 32)

    def test_sender_change_is_not_incoming(self):
        self.rejected('incoming_not_received', script=OWN)

    def test_self_transfer_is_not_incoming(self):
        self.controller.install(previous=TARGET)
        self.rejected('incoming_not_received')

    def test_mixed_own_and_external_inputs_are_not_incoming(self):
        self.controller.transaction.vin.append(CTxIn(COutPoint(int('13' * 32, 16), 1), b'', 0xffffffff))
        self.controller.install()
        self.controller.verbose[self.controller.txid]['vin'][1]['prevout']['scriptPubKey']['hex'] = TARGET.hex()
        self.rejected('incoming_not_received')

    def test_coinbase_is_not_incoming(self):
        self.controller.transaction.vin = [CTxIn(COutPoint(0, 0xffffffff), b'\x01\x01', 0xffffffff)]
        self.controller.install()
        self.rejected('incoming_not_received')

    def test_missing_undo_cannot_confirm(self):
        del self.controller.verbose[self.controller.txid]['vin'][0]['prevout']
        self.rejected('incoming_unavailable')

    def test_malformed_undo_amount_or_script_cannot_confirm(self):
        previous = self.controller.verbose[self.controller.txid]['vin'][0]['prevout']
        for value in (True, '-1', '0.000000001', 'NaN'):
            previous['value'] = value
            self.rejected('incoming_unavailable')
        previous['value'] = '2.00000000'
        previous['scriptPubKey']['hex'] = '00'
        self.rejected('incoming_unavailable')

    def test_input_and_output_counts_are_bounded(self):
        original = copy.deepcopy(self.controller.transaction)
        self.controller.transaction.vin *= 17
        self.controller.install()
        self.rejected('incoming_unavailable')
        self.controller.transaction = original
        self.controller.transaction.vout *= 17
        self.controller.install()
        self.rejected('incoming_unavailable')

    def test_prevout_metadata_must_match_serialized_inputs(self):
        self.controller.verbose[self.controller.txid]['vin'][0]['vout'] = 9
        self.rejected('incoming_unavailable')

    def test_wrong_raw_hash_or_trailing_data_cannot_confirm(self):
        row = self.controller.verbose[self.controller.txid]
        raw = row['hex']
        for wrong in (raw + '00', raw[:-2] + '01'):
            row['hex'] = wrong
            self.rejected('incoming_unavailable')

    def test_four_nodes_must_agree_on_undo_values_and_scripts(self):
        for field in ('value', 'scriptPubKey'):
            def transform(index, value):
                if index == 3:
                    previous = value['tx'][1]['vin'][0]['prevout']
                    previous[field] = '1.00000000' if field == 'value' else {'hex': (b'\x52\x20' + b'\x88' * 32).hex()}
                return value
            self.controller.transform = transform
            self.rejected('incoming_unavailable')

    def test_active_block_divergence_cannot_confirm(self):
        self.controller.divergent_node = 3
        self.rejected('incoming_unavailable')

    def test_tip_change_before_return_cannot_confirm(self):
        def transform(index, value):
            if index == 3:
                self.controller.tip = BLOCK
            return value
        self.controller.transform = transform
        self.rejected('incoming_unavailable')

    def test_lookup_window_is_bounded_and_saved_block_hint_still_works(self):
        with patch.object(app, 'PAYMENT_SCAN_LIMIT', 1):
            self.rejected('incoming_unavailable', txid='ff' * 32)
            self.controller.transactions[TIP].remove(self.controller.txid)
            old = self.controller.blocks[1]
            self.controller.transactions[old].append(self.controller.txid)
            self.assertEqual(self.verify(block_hint=old)['start_height'], 1)

    def test_deadline_covers_nested_identity_rpcs_and_restores_budget(self):
        with patch.object(app, 'RECEIVED_LOOKUP_SECONDS', 0):
            self.rejected('incoming_unavailable')
        self.assertIsNone(self.controller._rpc_deadline)

    def test_reconciliation_budget_keeps_tighter_outer_deadline_and_resets_on_error(self):
        deadline = app.time.monotonic() + 10
        with self.assertRaises(RuntimeError):
            with self.network.reconciliation_budget(deadline):
                with self.network.reconciliation_budget(deadline + 20):
                    self.assertEqual(self.controller._rpc_deadline, deadline)
                    self.assertEqual(self.verify()['amount'], '0.10000000')
                self.assertEqual(self.controller._rpc_deadline, deadline)
                raise RuntimeError('synthetic failure')
        self.assertIsNone(self.controller._rpc_deadline)

    def test_receive_recheck_validates_amount_and_preserves_lookup_origin(self):
        record = {**self.verify(), 'kind': 'receive', 'start_height': 50}
        self.assertEqual(self.network.payment_status(record)['start_height'], 50)
        record['amount'] = '0.20000000'
        self.assertEqual(self.network.payment_status(record, finish=True)['status'], 'pending')
        self.assertEqual(self.controller.mine_calls, 0)

    def test_receive_reorg_becomes_pending_without_mining_existing_mempool_tx(self):
        record = {**self.verify(), 'kind': 'receive'}
        self.controller.blocks[101] = ORPHAN
        self.controller.headers[ORPHAN] = 101
        self.controller.transactions[ORPHAN] = [COINBASE]
        self.controller.tip = ORPHAN
        for pool in self.controller.pools:
            pool.add(self.controller.txid)
        self.assertEqual(self.network.payment_status(record, finish=True)['status'], 'pending')
        self.assertEqual(self.controller.mine_calls, 0)
        self.assertEqual(self.controller.broadcast_calls, 0)
        self.controller.transactions[ORPHAN].append(self.controller.txid)
        confirmed = self.network.payment_status(record, finish=True)
        self.assertEqual(confirmed['status'], 'confirmed')
        self.assertEqual(confirmed['block'], ORPHAN)

    def test_preview_distinguishes_self_fee_from_external_wallet_debit(self):
        own_address = encode_segwit_address('qlud', 2, OWN[2:])
        own = self.network.prepare(KEYS, own_address, '0.1').public()
        external = self.network.prepare(KEYS, ADDRESS, '0.1').public()
        self.assertEqual((own['is_self_transfer'], own['wallet_debit']), (True, '0.00100000'))
        self.assertEqual((external['is_self_transfer'], external['wallet_debit']), (False, '0.10100000'))


if __name__ == '__main__':
    unittest.main()
