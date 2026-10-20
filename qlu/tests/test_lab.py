"""Port lease safety tests; all paths are temporary and no nodes are started."""
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab
from devnet import DevnetError


class PrivatePortLockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.directory = self.root / ".local"
        self.lock = self.directory / lab.LOCK_NAME

    def tearDown(self):
        self.temporary.cleanup()

    def create_lock_file(self, mode=0o600):
        self.directory.mkdir(mode=0o700)
        self.lock.write_text("preserve this lock inode")
        self.lock.chmod(mode)

    def test_private_permissions_and_same_inode_preserved_after_release(self):
        with lab.private_port_lock(self.root):
            self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(self.lock.stat().st_mode), 0o600)
            self.assertEqual(self.lock.stat().st_nlink, 1)
            inode = self.lock.stat().st_ino
        with lab.private_port_lock(self.root):
            self.assertEqual(self.lock.stat().st_ino, inode)

    def test_second_acquisition_fails_without_waiting_and_keeps_contents(self):
        self.create_lock_file()
        with lab.private_port_lock(self.root):
            with self.assertRaisesRegex(DevnetError, "in progress"):
                with lab.private_port_lock(self.root):
                    self.fail("A concurrent coordinator acquired the same ports")
            self.assertEqual(self.lock.read_text(), "preserve this lock inode")

    def test_separate_process_cannot_acquire_held_lock(self):
        command = [sys.executable, "-c", "from pathlib import Path; import sys; from lab import private_port_lock; from devnet import DevnetError\ntry:\n with private_port_lock(Path(sys.argv[1])): pass\nexcept DevnetError as error:\n print(str(error)); sys.exit(7)", str(self.root)]
        environment = dict(os.environ, PYTHONPATH=str(Path(lab.__file__).parent))
        with lab.private_port_lock(self.root):
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, env=environment)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("in progress", result.stdout)
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_body_exception_releases_lock_and_propagates(self):
        with self.assertRaisesRegex(RuntimeError, "body failed"):
            with lab.private_port_lock(self.root):
                raise RuntimeError("body failed")
        with lab.private_port_lock(self.root):
            pass

    def test_directory_symlink_refused_without_modifying_target(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o755)
        self.directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(DevnetError), lab.private_port_lock(self.root):
            self.fail("symlink directory accepted")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)

    def test_lock_symlink_refused_without_modifying_target(self):
        outside = self.root / "outside"
        outside.write_text("unchanged")
        outside.chmod(0o644)
        self.directory.mkdir(mode=0o700)
        self.lock.symlink_to(outside)
        with self.assertRaises(DevnetError), lab.private_port_lock(self.root):
            self.fail("symlink lock accepted")
        self.assertEqual(outside.read_text(), "unchanged")
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def test_hard_link_refused_before_permission_or_content_changes(self):
        self.create_lock_file()
        outside = self.root / "outside"
        os.link(self.lock, outside)
        outside.chmod(0o644)
        with self.assertRaisesRegex(DevnetError, "singly linked"), lab.private_port_lock(self.root):
            self.fail("hard link accepted")
        self.assertEqual(outside.read_text(), "preserve this lock inode")
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o644)

    def test_non_regular_lock_refused_without_blocking(self):
        self.directory.mkdir(mode=0o700)
        os.mkfifo(self.lock, mode=0o600)
        with self.assertRaisesRegex(DevnetError, "regular"), lab.private_port_lock(self.root):
            self.fail("FIFO accepted")

    def test_existing_lock_with_broad_permissions_is_refused(self):
        self.create_lock_file(0o644)
        with self.assertRaisesRegex(DevnetError, "0600"), lab.private_port_lock(self.root):
            self.fail("broad permissions accepted")
        self.assertEqual(stat.S_IMODE(self.lock.stat().st_mode), 0o644)

    def test_foreign_owner_directory_and_file_are_refused(self):
        self.create_lock_file()
        original_fstat = os.fstat
        for foreign_directory in (True, False):
            def changed_owner(fd):
                actual = original_fstat(fd)
                if stat.S_ISDIR(actual.st_mode) == foreign_directory:
                    fields = list(actual)
                    fields[4] = os.getuid() + 1
                    return os.stat_result(fields)
                return actual
            with self.subTest(directory=foreign_directory), patch.object(lab.os, "fstat", side_effect=changed_owner):
                with self.assertRaisesRegex(DevnetError, "current user"), lab.private_port_lock(self.root):
                    self.fail("foreign owner accepted")

    def test_private_cli_holds_shared_lease_during_operation(self):
        import private_net
        controller = private_net.QLUPrivateNet(self.root)
        def operation():
            with self.assertRaisesRegex(DevnetError, "in progress"), lab.private_port_lock(self.root):
                self.fail("private CLI did not hold the shared lock")
            return {"checked": True}
        with patch.object(private_net, "QLUPrivateNet", return_value=controller), \
                patch.object(controller, "setup", side_effect=operation), \
                patch.object(sys, "argv", ["private_net.py", "setup"]), \
                patch.object(sys, "stdout", io.StringIO()):
            previous_umask = os.umask(0o077)
            try:
                private_net.main()
            finally:
                os.umask(previous_umask)
        with lab.private_port_lock(self.root):
            pass


if __name__ == "__main__":
    unittest.main()
