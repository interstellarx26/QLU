"""The drill must not mistake foreign peers or loopback leakage for isolation."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import json
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import network_resilience_smoke as drill
import devnet
from network_resilience_smoke import identify_peers, failure_location, failure_summary


class FailureDiagnosticTests(unittest.TestCase):
    def test_failure_location_omits_message_source_and_locals(self):
        secret = 'disposable credential must never be logged'
        try:
            raise ValueError(secret)
        except ValueError as error:
            result = failure_location(error)
        self.assertEqual(result['error_type'], 'ValueError')
        self.assertTrue(result['error_location'])
        self.assertNotIn(secret, json.dumps(result))
        for frame in result['error_location']:
            self.assertEqual(set(frame), {'file', 'line', 'function'})
            self.assertEqual(Path(frame['file']).name, frame['file'])

    def test_failure_summary_does_not_publish_unlisted_payloads(self):
        safe = {'attempt': '12' * 16, 'passed': False, 'checks': {'mesh': True},
                'controller_failures': [{'error_type': 'DevnetError', 'error_location': []}],
                'rpc_error_code': -5}
        report = {**safe, 'passphrase': 'private', 'setup': {'seed': 'private'},
                  'raw_error': 'private', 'stdout': 'private', 'observations': {'rpc': 'private'}}
        self.assertEqual(failure_summary(report), safe)

    def test_rpc_diagnostics_allow_only_bounded_integer_code(self):
        secret = 'private RPC message must not escape'
        result = failure_location(drill.RpcError(secret, -5))
        self.assertEqual(result['rpc_error_code'], -5)
        self.assertNotIn(secret, json.dumps(result))
        for code in (None, 'secret', True, 2 ** 32, -(2 ** 32)):
            with self.subTest(code=code):
                self.assertNotIn('rpc_error_code', failure_location(drill.RpcError(secret, code)))


class PartitionPeerTests(unittest.TestCase):
    def setUp(self):
        self.state = {str(i): {'token': str(i) * 32} for i in range(4)}
        self.label = 'QLUWalletAppResilience'

    def peer(self, index, **changes):
        return {'id': index, 'addr': f'127.0.0.1:{28440 + index}',
                'subver': f"/QLU:0.1({self.label}-{self.state[str(index)]['token']})/", **changes}

    def identify(self, peers, **kwargs):
        return identify_peers(peers, self.state, self.label, 0, **kwargs)

    def test_known_peer_tokens_map_to_exact_owned_node(self):
        self.assertEqual(self.identify([self.peer(1), self.peer(2)]), {1: 1, 2: 2})

    def test_foreign_or_non_loopback_is_not_silently_ignored(self):
        for peer in (self.peer(1, addr='192.0.2.1:28441'), self.peer(1, subver='/foreign/'),
                     self.peer(1, addr='127.0.0.1:bad'), self.peer(1, id=True)):
            with self.assertRaises(AssertionError):
                self.identify([peer], allow_incomplete=True)

    def test_empty_handshake_can_only_be_ignored_during_transition(self):
        peer = self.peer(1, subver='')
        with self.assertRaises(AssertionError):
            self.identify([peer])
        self.assertEqual(self.identify([peer], allow_incomplete=True), {})

    def test_self_or_ambiguous_identity_fails(self):
        for peer in (self.peer(0), self.peer(1, subver=self.peer(1)['subver'] + self.peer(2)['subver'])):
            with self.assertRaises(AssertionError):
                self.identify([peer])

    def test_optimized_python_refuses_before_fixture_creation(self):
        root = Path(__file__).resolve().parents[2]
        code = ('from pathlib import Path; import sys; '
                'from qlu import network_resilience_smoke as drill; '
                'drill.protocol.ROOT = Path(sys.argv[1]); drill.run()')
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-B', '-O', '-c', code, directory],
                                    cwd=root, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'refuses optimized Python', result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_optimized_worker_refuses_before_reading_setup_or_paths(self):
        root = Path(__file__).resolve().parents[2]
        code = ('from pathlib import Path; import sys; '
                'from qlu import network_resilience_smoke as drill; '
                'drill.protocol.ROOT = Path(sys.argv[1]); drill.reopen_worker()')
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-B', '-O', '-c', code, directory],
                                    cwd=root, input=b'not even JSON\n', capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'refuses optimized Python', result.stderr)
            self.assertNotIn(b'JSONDecodeError', result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])


class PartitionConvergenceTests(unittest.TestCase):
    """RPC snapshots may change while owned connections finish handshaking."""
    def setUp(self):
        self.state = {str(i): {'token': str(i) * 32} for i in range(4)}
        self.controller = object.__new__(drill.PartitionController)
        self.controller.p2p_base = 28440
        self.controller.process_label = 'QLUWalletAppResilience'
        self.controller.read_state = lambda: self.state
        self.controller.verify_node = lambda index: None
        self.clock = 0.0
        self.reads = 0
        self.crossed = False
        self.disconnects = []
        self.mode = 'stable'
        self.arrival = 5  # Between the first scan and its confirming snapshot.
        self.controller.rpc = self.rpc

    def peer(self, index, **changes):
        label = self.controller.process_label
        return {'id': index, 'addr': f'127.0.0.1:{28440 + index}',
                'subver': f"/QLU:0.1({label}-{self.state[str(index)]['token']})/", **changes}

    def rpc(self, index, method, *args):
        if method == 'addnode':
            self.assertEqual(args[1], 'remove')
            return ''
        if method == 'disconnectnode':
            self.disconnects.append((index, args[1]))
            if self.mode != 'permanent':
                self.crossed = False
            return ''
        self.assertEqual(method, 'getpeerinfo')
        self.reads += 1
        rows = [self.peer(index ^ 1)]
        if self.reads == self.arrival or self.mode == 'permanent':
            self.crossed = self.mode != 'stable'
        if self.crossed and index in (0, 2):
            other = 2 if index == 0 else 0
            changes = {}
            if self.mode == 'incomplete' and self.reads < self.arrival + 4:
                changes['subver'] = ''
            elif self.mode == 'foreign':
                changes['subver'] = '/foreign/'
            elif self.mode == 'non-loopback':
                changes['addr'] = '192.0.2.1:28442'
            elif self.mode == 'malformed':
                changes['id'] = True
            rows.append(self.peer(other, **changes))
        return rows

    def sleep(self, seconds):
        self.clock += seconds

    def partition(self):
        with patch.object(drill.time, 'monotonic', side_effect=lambda: self.clock), \
                patch.object(drill.time, 'sleep', side_effect=self.sleep):
            self.controller.partition()

    def test_stable_exact_partition_needs_no_retry(self):
        self.partition()
        self.assertEqual(self.clock, 0)
        self.assertEqual(self.disconnects, [])
        self.assertTrue(self.controller.assert_partition())

    def test_late_owned_connection_is_disconnected_within_original_budget(self):
        self.mode = 'owned'
        self.partition()
        self.assertEqual(self.disconnects, [(0, 2)])
        self.assertFalse(self.crossed)
        self.assertGreater(self.clock, 0)
        self.assertLess(self.clock, 10)
        self.assertTrue(self.controller.assert_partition())

    def test_late_incomplete_handshake_must_resolve_before_success(self):
        self.mode = 'incomplete'
        self.partition()
        self.assertGreaterEqual(self.reads, self.arrival + 4)
        self.assertEqual(self.disconnects, [(0, 2)])
        self.assertFalse(self.crossed)
        self.assertLess(self.clock, 10)
        self.assertTrue(self.controller.assert_partition())

    def test_unsafe_peer_in_confirming_snapshot_is_never_retried(self):
        for mode in ('foreign', 'non-loopback', 'malformed'):
            with self.subTest(mode=mode):
                self.setUp()
                self.mode = mode
                with self.assertRaises(AssertionError):
                    self.partition()
                self.assertEqual(self.reads, self.arrival)
                self.assertEqual(self.clock, 0)
                self.assertEqual(self.disconnects, [])

    def test_never_converging_owned_connections_keep_existing_deadline(self):
        self.mode = 'permanent'
        with self.assertRaisesRegex(AssertionError, r'Exact 2\+2 partition was not established'):
            self.partition()
        self.assertGreaterEqual(self.clock, 10)
        self.assertLess(self.clock, 10.2)
        self.assertTrue(self.disconnects)

    def test_assert_partition_still_refuses_extra_or_incomplete_connections(self):
        for mode in ('owned', 'incomplete'):
            with self.subTest(mode=mode):
                self.setUp()
                self.mode, self.arrival = mode, 1
                with self.assertRaises(AssertionError):
                    self.controller.assert_partition()


class LosingHeaderFixtureTests(unittest.TestCase):
    """Peers may correctly converge without advertising the shorter fork."""
    def setUp(self):
        header = drill.CBlockHeader()
        header.hashPrevBlock = 1234
        header.hashMerkleRoot = 5678
        header.nBits = 0x207fffff
        header.nTime = 1792368100
        self.raw, self.loser = header.serialize().hex(), header.hash_hex
        self.parent, self.winner = f'{1234:064x}', 'ab' * 32
        self.losing_work, self.winning_work, self.height = 4, 6, 2
        self.calls, self.known, self.invalidated = [], {0, 1}, []
        self.mode = 'valid'
        self.submit_rpc = None

    def rpc(self, index, method, *args):
        self.calls.append((index, method, args))
        after_submit = any(row[1] == 'submitheader' for row in self.calls)
        if method == 'getblockchaininfo':
            tip = self.winner
            work = self.winning_work
            if self.mode == 'initial-winner' or self.mode == 'changed-winner' and after_submit:
                tip = self.loser
            if self.mode == 'changed-winning-work' and after_submit:
                work += 2
            return {'bestblockhash': tip, 'chainwork': f'{work:x}'}
        if method == 'submitheader':
            self.assertEqual(args, (self.raw,))
            if self.mode == 'rpc-error':
                raise drill.RpcError('synthetic failure message', -8)
            if self.mode != 'forgot-header':
                self.known.add(index)
            if self.submit_rpc is not None:
                return self.submit_rpc(index, method, *args)
            if self.mode == 'wrong-null-transport':
                return None
            return 'duplicate' if self.mode == 'wrong-submit-result' else ''
        if method == 'getblockheader':
            self.assertEqual(args[0], self.loser)
            if index not in self.known:
                raise drill.RpcError('synthetic unknown header', -5)
            if len(args) == 2:
                self.assertIs(args[1], False)
                return self.raw + '00' if self.mode == 'wrong-bytes' else self.raw
            value = {'hash': self.loser, 'previousblockhash': self.parent, 'height': self.height,
                     'confirmations': -1, 'chainwork': f'{self.losing_work:x}'}
            mutations = {'wrong-hash': ('hash', self.winner), 'wrong-parent': ('previousblockhash', self.winner),
                         'wrong-height': ('height', self.height + 1), 'active-loser': ('confirmations', 1),
                         'wrong-losing-work': ('chainwork', f'{self.winning_work:x}')}
            if self.mode in mutations:
                key, changed = mutations[self.mode]
                value[key] = changed
            return value
        if method == 'invalidateblock':
            self.assertEqual(args, (self.loser,))
            if index not in self.known:
                raise drill.RpcError('synthetic unknown header', -5)
            self.invalidated.append(index)
            return None
        raise AssertionError('Unexpected RPC in header-only fixture preparation')

    def share(self, **overrides):
        params = {'losing_hash': self.loser, 'losing_raw': self.raw, 'winner_hash': self.winner,
                  'losing_work': self.losing_work, 'winning_work': self.winning_work,
                  'expected_parent': self.parent, 'expected_height': self.height}
        params.update(overrides)
        return drill.share_known_losing_header(self, **params)

    def test_prior_invalidation_assumption_fails_for_unknown_losing_header(self):
        # This reproduces the missing-header precondition, not the unavailable
        # numeric RPC diagnosis of the original hosted failure.
        with self.assertRaises(drill.RpcError) as caught:
            for index in range(4):
                self.rpc(index, 'invalidateblock', self.loser)
        self.assertEqual(caught.exception.code, -5)
        self.assertEqual(self.invalidated, [0, 1])

    def test_header_preparation_makes_invalidation_known_on_all_four_nodes(self):
        result = self.share()
        self.assertEqual(self.known, set(range(4)))
        self.assertEqual([row['node'] for row in result['nodes']], list(range(4)))
        self.assertEqual([i for i, method, _ in self.calls if method == 'submitheader'], list(range(4)))
        self.assertTrue(all(row['winning_tip_unchanged'] and row['stored_header_verified'] for row in result['nodes']))
        self.assertFalse(any(method in {'submitblock', 'getblock', 'invalidateblock'} for _, method, _ in self.calls))
        for index in range(4):
            self.rpc(index, 'invalidateblock', self.loser)
        self.assertEqual(self.invalidated, list(range(4)))

    def test_successful_cli_json_null_is_empty_string_through_real_controller(self):
        # bitcoin-cli ParseResult prints nothing for JSON null. Exercise the
        # actual controller decoding instead of modelling it as Python None.
        with tempfile.TemporaryDirectory() as directory:
            controller = devnet.Devnet(Path(directory))
            self.submit_rpc = controller.rpc
            completed = subprocess.CompletedProcess([], 0, stdout='', stderr='')
            with patch.object(devnet.subprocess, 'run', return_value=completed) as run:
                result = self.share()
            self.assertEqual(len(result['nodes']), 4)
            self.assertEqual(run.call_count, 4)
            for call in run.call_args_list:
                self.assertEqual(call.args[0][-1], 'submitheader')
                self.assertEqual(call.kwargs['input'], self.raw + '\n')

    def test_wrong_header_identity_shape_parent_or_work_refused_before_rpc(self):
        changes = ({'losing_hash': self.winner}, {'losing_raw': self.raw + '00'}, {'losing_raw': self.raw[:-2]},
                   {'losing_raw': 'zz' * 80}, {'expected_parent': self.winner}, {'winning_work': self.losing_work},
                   {'winning_work': True}, {'losing_work': 0}, {'expected_height': True})
        for changed in changes:
            with self.subTest(changed=list(changed)), self.assertRaises(AssertionError):
                self.share(**changed)
            self.assertEqual(self.calls, [])

    def test_wrong_stored_header_metadata_result_or_tip_is_not_accepted(self):
        for mode in ('initial-winner', 'changed-winner', 'changed-winning-work', 'wrong-submit-result', 'wrong-null-transport',
                     'wrong-bytes', 'wrong-hash', 'wrong-parent', 'wrong-height', 'active-loser', 'wrong-losing-work'):
            with self.subTest(mode=mode):
                self.setUp()
                self.mode = mode
                with self.assertRaises(AssertionError):
                    self.share()
                self.assertEqual(self.invalidated, [])

    def test_rpc_failures_and_absent_header_are_not_swallowed_or_retried(self):
        for mode, expected_code in (('rpc-error', -8), ('forgot-header', -5)):
            with self.subTest(mode=mode):
                self.setUp()
                self.mode = mode
                with self.assertRaises(drill.RpcError) as caught:
                    self.share()
                self.assertEqual(caught.exception.code, expected_code)
                submitted = [i for i, method, _ in self.calls if method == 'submitheader']
                self.assertEqual(submitted, [0] if mode == 'rpc-error' else [0, 1, 2])
                self.assertEqual(self.invalidated, [])


if __name__ == '__main__':
    unittest.main()
