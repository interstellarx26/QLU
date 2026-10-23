"""Safety boundaries of the disposable password-helper acceptance drill."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kdf_timeout_smoke as drill


class KDFTimeoutDrillTests(unittest.TestCase):
    def test_identifier_cannot_select_user_wallet_or_unrelated_paths(self):
        identifier = "ab" * 16
        app, evidence, network = drill.fixture_paths(identifier)
        self.assertEqual(app, drill.protocol.ROOT / ".local" / ("wallet-app-kdf-" + identifier))
        self.assertEqual(evidence, drill.protocol.ROOT / ".local/kdf-timeout-drills" / identifier)
        self.assertEqual(network, "wallet-app-kdf-net-" + identifier)
        for value in (None, True, "../wallet-app", "AB" * 16, identifier + "/", identifier[:-1]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                drill.fixture_paths(value)

    def test_optimized_drill_refuses_before_creating_fixture_files(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            code = ("from pathlib import Path; import sys; from qlu import kdf_timeout_smoke as drill; "
                    "drill.protocol.ROOT=Path(sys.argv[1]); drill.run()")
            result = subprocess.run([sys.executable, "-B", "-O", "-c", code, directory],
                                    cwd=root, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"refuses optimized Python", result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_fault_helper_retains_only_pid_and_never_outputs_its_pipe_input(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            helper = drill.write_hung_helper(directory)
            marker = Path(directory) / "ready.pid"
            process = subprocess.Popen([sys.executable, "-I", str(helper), str(marker)],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdin.write(b"synthetic secret input is never retained")
                process.stdin.close()
                deadline = time.monotonic() + 5
                while process.poll() is None and time.monotonic() < deadline:
                    if marker.is_file() and marker.read_text() == str(process.pid):
                        break
                    time.sleep(0.01)
                self.assertTrue(marker.is_file())
                self.assertEqual(marker.read_text(), str(process.pid))
                self.assertIsNone(process.poll())
                self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
                self.assertEqual(set(Path(directory).iterdir()), {helper, marker})
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            self.assertEqual(process.stdout.read(), b"")
            self.assertEqual(process.stderr.read(), b"")
            process.stdout.close()
            process.stderr.close()
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)

    def test_fault_helper_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory).resolve()
            helper = Path(directory) / "hung-password-helper.py"
            helper.write_bytes(b"preserved")
            with self.assertRaises(FileExistsError):
                drill.write_hung_helper(directory)
            self.assertEqual(helper.read_bytes(), b"preserved")


if __name__ == "__main__":
    unittest.main()
