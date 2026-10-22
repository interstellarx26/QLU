"""The drill must not mistake foreign peers or loopback leakage for isolation."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from network_resilience_smoke import identify_peers


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


if __name__ == '__main__':
    unittest.main()
