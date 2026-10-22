"""Safety boundaries for the isolated subprocess payment-resume drill."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import payment_resume_smoke as drill


class ResumeDrillTests(unittest.TestCase):
    def test_fixture_identifier_is_exact_and_paths_stay_in_fixture_namespace(self):
        value = 'ab' * 16
        self.assertEqual(drill.fixture_identifier(value), value)
        app, data = drill.fixture_paths(value)
        self.assertEqual(app, drill.protocol.ROOT / '.local' / ('wallet-app-resume-' + value))
        self.assertEqual(data, 'wallet-app-resume-net-' + value)
        for invalid in (None, True, '../wallet-app', 'AB' * 16, value + '/', value[:-1]):
            with self.assertRaises(ValueError):
                drill.fixture_paths(invalid)

    def test_both_optimized_entries_refuse_before_input_or_files(self):
        root = Path(__file__).resolve().parents[2]
        for function in ('run', 'worker'):
            with self.subTest(function=function), tempfile.TemporaryDirectory() as directory:
                code = ('from pathlib import Path; import sys; from qlu import payment_resume_smoke as drill; '
                        f'drill.protocol.ROOT=Path(sys.argv[1]); drill.{function}()')
                result = subprocess.run([sys.executable, '-B', '-O', '-c', code, directory],
                                        cwd=root, input=b'invalid JSON\n', capture_output=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'refuses optimized Python', result.stderr)
                self.assertNotIn(b'JSONDecodeError', result.stderr)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_mutation_refuses_symlink_journal_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(drill.protocol, 'ROOT', Path(directory)):
            identifier, operation = 'ab' * 16, 'cd' * 16
            folder = drill.fixture_paths(identifier)[0] / 'payment-history'
            folder.mkdir(parents=True)
            outside = Path(directory) / 'preserved.json'
            outside.write_bytes(b'unchanged')
            (folder / ('ef' * 32 + '.json')).symlink_to(outside)
            with self.assertRaises(ValueError):
                drill.mutate_fixture_history(identifier, operation, 'raw')
            self.assertEqual(outside.read_bytes(), b'unchanged')

    def test_legacy_mutation_changes_only_designated_fixture_journal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(drill.protocol, 'ROOT', Path(directory)):
            identifier, operation = 'ab' * 16, 'cd' * 16
            folder = drill.fixture_paths(identifier)[0] / 'payment-history'
            folder.mkdir(parents=True)
            path = folder / ('ef' * 32 + '.json')
            data = {'version': 4, 'records': [{'operation_id': operation, 'status': 'pending',
                                             'transaction': '00', 'signed_transaction': '01',
                                             'spent_outputs': [{'value': 1, 'script': '00'}]}]}
            path.write_text(json.dumps(data))
            os.chmod(path, 0o600)
            outside = Path(directory) / 'unrelated.json'
            outside.write_bytes(b'unchanged')
            drill.mutate_fixture_history(identifier, operation, 'legacy')
            changed = json.loads(path.read_text())
            self.assertEqual(changed['version'], 3)
            self.assertEqual(changed['records'], [{'operation_id': operation, 'status': 'pending', 'transaction': '00'}])
            self.assertEqual(outside.read_bytes(), b'unchanged')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                drill.mutate_fixture_history(identifier, '12' * 16, 'amount')
            self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
