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
                'controller_failures': [{'error_type': 'DevnetError', 'error_location': []}]}
        report = {**safe, 'passphrase': 'private', 'setup': {'seed': 'private'},
                  'raw_error': 'private', 'stdout': 'private', 'observations': {'rpc': 'private'}}
        self.assertEqual(failure_summary(report), safe)


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


if __name__ == '__main__':
    unittest.main()
