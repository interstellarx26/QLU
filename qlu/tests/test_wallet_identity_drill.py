"""Safety boundaries of the fresh-wallet identity acceptance harness."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wallet_identity_smoke as drill


class IdentityDrillTests(unittest.TestCase):
    def test_worker_setup_is_exact_and_bounded_to_fixture_ids(self):
        good = {'identifier': 'ab' * 16, 'wallet_id': 'cd' * 32, 'action': 'hold'}
        self.assertEqual(drill.worker_setup(good), good)
        for value in ({**good, 'identifier': '../wallet-app'}, {**good, 'wallet_id': True},
                      {**good, 'identifier': 'AB' * 16}, {**good, 'action': 'delete'},
                      {**good, 'path': '/tmp/unrelated'}, None):
            with self.assertRaises(ValueError):
                drill.worker_setup(value)

    def test_optimized_entry_points_refuse_before_input_or_filesystem_access(self):
        root = Path(__file__).resolve().parents[2]
        for function in ('run', 'journal_worker'):
            with self.subTest(function=function), tempfile.TemporaryDirectory() as directory:
                code = ('from pathlib import Path; import sys; from qlu import wallet_identity_smoke as drill; '
                        f'drill.protocol.ROOT=Path(sys.argv[1]); drill.{function}()')
                value = subprocess.run([sys.executable, '-B', '-O', '-c', code, directory],
                                       cwd=root, input=b'invalid JSON\n', capture_output=True, timeout=15)
                self.assertNotEqual(value.returncode, 0)
                self.assertIn(b'refuses optimized Python', value.stderr)
                self.assertNotIn(b'JSONDecodeError', value.stderr)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_replacement_refuses_non_fixture_paths_without_changing_them(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(drill.protocol, 'ROOT', Path(directory)):
            root = Path(directory)
            path = root / 'untouched.vault.json'
            path.write_bytes(b'original')
            for app in (root / '.local/wallet-app', root / 'wallet-app-identity-' / ('ab' * 16)):
                with self.assertRaises(ValueError):
                    drill.replace_fixture_vault(path, b'replacement', app)
            self.assertEqual(path.read_bytes(), b'original')

    def test_fixture_replacement_is_complete_and_rejects_symlink_destination(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(drill.protocol, 'ROOT', Path(directory)):
            app = Path(directory) / '.local' / ('wallet-app-identity-' + 'ab' * 16)
            folder = app / 'wallets'
            folder.mkdir(parents=True)
            path = folder / ('cd' * 16 + '.vault.json')
            path.write_bytes(b'old fixture bytes')
            drill.replace_fixture_vault(path, b'complete new fixture bytes', app)
            self.assertEqual(path.read_bytes(), b'complete new fixture bytes')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(folder.iterdir()), [path])
            other = Path(directory) / 'outside'
            other.write_bytes(b'preserved')
            path.unlink()
            path.symlink_to(other)
            with self.assertRaises(ValueError):
                drill.replace_fixture_vault(path, b'replacement', app)
            self.assertEqual(other.read_bytes(), b'preserved')


if __name__ == '__main__':
    unittest.main()
