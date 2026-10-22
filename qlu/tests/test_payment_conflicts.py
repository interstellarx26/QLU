"""Conflict authority needs bound original inputs and fresh four-node proof."""
import copy
from contextlib import contextmanager, nullcontext
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_wallet_payment_status import HistoryController, COINBASE
from test_wallet_app_network import KEYS, ADDRESS, TARGET, TIP, BLOCK
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness
import wallet_app_network as app
from devnet import RpcError
from payment_conflicts import validate_transaction, validate_conflict


def original_transaction():
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(int('09' * 32, 16), 3))]
    tx.vout = [CTxOut(50_000_000, TARGET)]
    return tx


class ConflictController(HistoryController):
    def __init__(self):
        super().__init__()
        self.original = original_transaction()
        self.winner = CTransaction(self.original)
        self.winner.vout[0].nValue -= 1
        self.candidate = self.winner
        self.proof_node_error = None
        self.orphan = False
        self.deadlines = []
        self.transactions[TIP] = [COINBASE, self.winner.txid_hex]

    @contextmanager
    def rpc_budget(self, deadline):
        self.deadlines.append(deadline)
        yield

    def rpc(self, index, method, *args):
        if method == 'getblock' and args[1] == 2:
            block = super().rpc(index, 'getblock', args[0], 1)
            rows = [{'txid': COINBASE, 'vin': [{'coinbase': '00'}]}]
            if args[0] == TIP and self.candidate is not None:
                tx = self.candidate
                row = {'txid': tx.txid_hex, 'hex': tx.serialize_with_witness().hex(),
                       'vin': [{'txid': f'{i.prevout.hash:064x}', 'vout': i.prevout.n} for i in tx.vin]}
                if self.proof_node_error == index:
                    row['hex'] = self.original.serialize_with_witness().hex()
                rows.append(row)
            return {**block, 'tx': rows, 'confirmations': -1 if self.orphan else block['confirmations']}
        return super().rpc(index, method, *args)


class ConflictProofTests(unittest.TestCase):
    def setUp(self):
        self.network = app.WalletAppNetwork()
        self.controller = ConflictController()
        self.network.controller = self.controller
        self.lock = patch.object(app, 'private_port_lock', return_value=nullcontext())
        self.lock.start()
        self.network.start()
        self.network._faucet_wallet = {'synthetic': True}
        self.network._faucet_keys = KEYS
        tx = self.controller.original
        self.record = {'kind': 'send', 'txid': tx.txid_hex, 'transaction': tx.serialize_without_witness().hex(),
                       'recipient': ADDRESS, 'amount': '0.50000000', 'fee': '0.00100000', 'start_height': 101}

    def tearDown(self):
        self.network.stop()
        self.lock.stop()

    def resolved(self):
        return {**self.record, **self.network.payment_status(self.record)}

    def test_active_shared_input_resolves_only_after_all_four_prove_same_bytes(self):
        status = self.network.payment_status(self.record)
        self.assertEqual(status['status'], 'conflicted')
        self.assertEqual(status['confirmed_nodes'], 4)
        self.assertEqual(status['conflict'], {'txid': self.controller.winner.txid_hex, 'block': TIP,
                         'height': 101, 'input': {'txid': '09' * 32, 'vout': 3}})
        self.assertEqual({index for index, method, args in self.controller.calls
                          if method == 'getblock' and args[0] == TIP}, set(range(4)))
        self.assertEqual(self.controller.broadcast_calls, 0)
        self.assertEqual(self.controller.mine_calls, 0)

    def test_absence_and_legacy_records_cannot_release_guard(self):
        legacy = {k: v for k, v in self.record.items() if k != 'transaction'}
        self.assertEqual(self.network.payment_status(legacy)['status'], 'pending')
        self.controller.candidate = None
        self.controller.transactions[TIP] = [COINBASE]
        self.assertEqual(self.network.payment_status(self.record)['status'], 'pending')

    def test_wrong_outpoint_does_not_prove_conflict(self):
        self.controller.candidate.vin[0].prevout.n += 1
        self.assertEqual(self.network.payment_status(self.record)['status'], 'pending')

    def test_other_node_bad_raw_or_orphan_block_keeps_pending(self):
        self.controller.proof_node_error = 3
        self.assertEqual(self.network.payment_status(self.record)['status'], 'pending')
        self.controller.proof_node_error = None
        self.controller.orphan = True
        self.assertEqual(self.network.payment_status(self.record)['status'], 'pending')

    def test_original_transaction_is_never_its_own_conflict_even_below_lookup_origin(self):
        self.controller.candidate = self.controller.original
        witness = CTxInWitness()
        witness.scriptWitness.stack = [b'synthetic-witness-with-the-same-non-witness-txid']
        self.controller.candidate.wit.vtxinwit = [witness]
        self.controller.transactions[TIP] = [COINBASE, self.controller.original.txid_hex]
        result = self.network.payment_status({**self.record, 'start_height': 102})
        self.assertEqual(result['status'], 'confirmed')
        self.assertNotIn('conflict', result)

    def test_changed_tip_after_all_peer_proofs_refuses_resolution(self):
        original = self.network._chain_snapshot
        calls = 0
        def snapshot():
            nonlocal calls
            calls += 1
            # Initial snapshot, post-original-lookup, post-mempool, then proof.
            return (102, BLOCK) if calls >= 4 else original()
        with patch.object(self.network, '_chain_snapshot', side_effect=snapshot):
            result = self.network.payment_status(self.record)
        self.assertEqual(result['status'], 'pending')
        self.assertEqual(result['status_reason'], 'network_unavailable')

    def test_mempool_conflict_is_not_active_chain_evidence(self):
        self.controller.candidate = None
        self.controller.transactions[TIP] = [COINBASE]
        self.controller.pools = [{self.controller.winner.txid_hex} for _ in range(4)]
        self.assertEqual(self.network.payment_status(self.record, finish=True)['status'], 'pending')
        self.assertEqual(self.controller.mine_calls, 0)

    def test_reorg_resurrected_original_is_not_mined_by_generic_recovery(self):
        record = self.resolved()
        self.controller.candidate = None
        self.controller.transactions[TIP] = [COINBASE]
        self.controller.pools = [{self.record['txid']} for _ in range(4)]
        status = self.network.payment_status(record, finish=True)
        self.assertEqual(status['status'], 'pending')
        self.assertEqual(status['status_reason'], 'mempool')
        self.assertEqual(self.controller.mine_calls, 0)

    def test_valid_hint_outside_search_window_is_verified_directly(self):
        record = self.resolved()
        self.controller.height = 20_000
        self.controller.tip = BLOCK
        self.controller.blocks[20_000] = BLOCK
        self.controller.headers[BLOCK] = 20_000
        self.controller.transactions[BLOCK] = [COINBASE]
        status = self.network.payment_status(record)
        self.assertEqual(status['status'], 'conflicted')

    def test_only_missing_original_block_hint_can_fall_back_to_active_conflict_proof(self):
        record = {**self.record, 'block': '12' * 32}
        original_rpc = self.controller.rpc
        for code, expected in ((-5, 'conflicted'), (None, 'pending'), (-1, 'pending')):
            def rpc(index, method, *args):
                if method == 'getblockheader' and args[0] == record['block']:
                    raise RpcError('synthetic unavailable old header', code=code)
                return original_rpc(index, method, *args)
            with self.subTest(code=code), patch.object(self.controller, 'rpc', side_effect=rpc):
                self.assertEqual(self.network.payment_status(record)['status'], expected)
        for malformed in (None, {'hash': record['block'], 'height': True}, {'hash': 'ff' * 32, 'height': 100}):
            def rpc(index, method, *args):
                if method == 'getblockheader' and args[0] == record['block']:
                    return malformed
                return original_rpc(index, method, *args)
            with self.subTest(malformed=malformed), patch.object(self.controller, 'rpc', side_effect=rpc):
                result = self.network.payment_status(record)
                self.assertEqual(result['status'], 'pending')
                self.assertEqual(result['status_reason'], 'network_unavailable')

    def test_original_metadata_cannot_change_or_accept_witness_trailing_data(self):
        for raw in (self.record['transaction'] + '00', '00', self.record['transaction'].upper()):
            with self.subTest(raw=raw[:12]), self.assertRaises(ValueError):
                validate_transaction(raw, self.record['txid'])
        with self.assertRaises(ValueError):
            validate_transaction(self.record['transaction'], 'aa' * 32)

    def test_malformed_hints_are_not_authority(self):
        record = self.resolved()
        for changes in ({'txid': self.record['txid']}, {'height': True}, {'input': {'txid': '09'*32, 'vout': 4}},
                        {'extra': 1}, {'block': 'bad'}):
            hint = {**record['conflict'], **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_conflict(hint, record['transaction'], record['txid'])

    def test_stale_guard_refuses_before_signing(self):
        record = self.resolved()
        prepared = self.network.prepare(KEYS, ADDRESS, '0.1')
        self.controller.candidate = None
        self.controller.transactions[TIP] = [COINBASE]
        session = Mock(locked=False)
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(session, prepared, conflict_records=[record])
        self.assertEqual(caught.exception.code, 'stale_payment')
        session.sign.assert_not_called()
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_conflict_removed_after_signing_refuses_before_durable_record_and_broadcast(self):
        record = self.resolved()
        prepared = self.network.prepare(KEYS, ADDRESS, '0.1')
        def sign(tx, spent):
            self.controller.candidate = None
            self.controller.transactions[TIP] = [COINBASE]
            return tx
        callback = Mock()
        with self.assertRaises(app.NetworkError) as caught:
            self.network.send(Mock(locked=False, sign=Mock(side_effect=sign)), prepared,
                              conflict_records=[record], before_broadcast=callback)
        self.assertEqual(caught.exception.code, 'stale_payment')
        callback.assert_not_called()
        self.assertEqual(self.controller.broadcast_calls, 0)

    def test_guard_requires_same_tip_and_one_shared_budget_for_all_records(self):
        record = self.resolved()
        prior_budgets = len(self.controller.deadlines)
        with patch.object(self.network, 'payment_status', return_value={'status': 'conflicted'}), \
                patch.object(self.network, '_chain_snapshot', return_value=(102, BLOCK)):
            with self.assertRaises(app.NetworkError):
                self.network._validate_conflict_guards([record, copy.deepcopy(record)], TIP)
        self.assertEqual(len(self.controller.deadlines), prior_budgets + 1)
        with patch.object(app.time, 'monotonic', side_effect=[0, 26]), \
                patch.object(self.network, 'payment_status', return_value={'status': 'conflicted'}):
            with self.assertRaises(app.NetworkError):
                self.network._validate_conflict_guards([record], TIP)


if __name__ == '__main__':
    unittest.main()
