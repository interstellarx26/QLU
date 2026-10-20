"""Guided wallet tests use injected terminal IO, never a real secret-displaying PTY."""
from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import warnings

from qlu import wallet

PASS = "test passphrase with enough length"
NEW_PASS = "different long recovery passphrase"
SHOWN_CODE = object()


class ScriptedIO:
    """An explicit test-only seam, with distinct ordinary and secret channels."""
    def __init__(self, answers, hidden, callback=None):
        self.answers = iter(answers)
        self.hidden = iter(hidden)
        self.callback = callback
        self.messages = []
        self.prompts = []
        self.codes = []

    def __enter__(self): return self
    def __exit__(self, *_): pass
    def message(self, message): self.messages.append(message)
    def prompt(self, text):
        self.prompts.append(text)
        if self.callback: self.callback(text)
        try: result = next(self.answers)
        except StopIteration: raise EOFError from None
        if isinstance(result, BaseException): raise result
        return result
    def secret(self, text):
        self.prompts.append(text)
        try: result = next(self.hidden)
        except StopIteration: raise EOFError from None
        if isinstance(result, BaseException): raise result
        return self.codes[-1] if result is SHOWN_CODE else result
    def show_recovery_code(self, code): self.codes.append(code)


def fake_sessions():
    class Session:
        created = []
        opened = []
        restored = []
        passphrases = {}
        all_sessions = []

        def __init__(self, path, *, idle_seconds=300):
            self.path = Path(path)
            self.idle_seconds = idle_seconds
            self.locked = True
            self.address_calls = 0
            self.lock_calls = 0
            self.verified_blobs = []
            self.unlocks = []
            self.code = wallet.recovery.generate_recovery_code()
            self.backup_blob = b'{"encrypted":"disposable fake backup"}'
            type(self).opened.append(self)
            type(self).all_sessions.append(self)

        @classmethod
        def create(cls, path, passphrase, *, idle_seconds=300):
            wallet.recovery.write_private(path, b"encrypted vault test fixture")
            session = cls(path, idle_seconds=idle_seconds)
            cls.passphrases[str(path)] = passphrase
            session.locked = False
            cls.created.append(session)
            return session

        @classmethod
        def restore(cls, path, backup_blob, code, passphrase, *, idle_seconds=300):
            if backup_blob != b"portable backup fixture" or code != "separate offline fixture code":
                raise wallet.vault.VaultError("Restore failed")
            session = cls.create(path, passphrase, idle_seconds=idle_seconds)
            cls.restored.append(session)
            return session

        def lock(self):
            self.locked = True
            self.lock_calls += 1

        def unlock(self, passphrase):
            self.unlocks.append(passphrase)
            if passphrase != self.passphrases.get(str(self.path)):
                raise wallet.vault.VaultError("Wrong passphrase")
            self.locked = False

        def address(self):
            if self.locked: raise wallet.vault.VaultError("Locked")
            self.address_calls += 1
            return "qlud1-test-public-address"

        def backup(self):
            if self.locked: raise wallet.vault.VaultError("Locked")
            return self.backup_blob, self.code

        def verify_backup(self, blob, code):
            self.verified_blobs.append(blob)
            if self.locked or blob != self.backup_blob or code != self.code:
                raise wallet.vault.VaultError("Backup check failed")
            return True
    return Session


class WalletWizardTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        self.temp = tempfile.TemporaryDirectory(prefix="wallet-ui-tests-", dir=root / ".local")
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "wallet.vault.json"
        self.backup = self.root / "backup.json"
        self.sessions = fake_sessions()

    def tearDown(self): self.temp.cleanup()

    def run_ui(self, terminal, session_type=None):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            result = wallet.main(["--wallet", str(self.path)], io_factory=lambda: terminal,
                                 session_type=self.sessions if session_type is None else session_type)
        return result, output.getvalue(), error.getvalue()

    def test_create_checks_saved_backup_before_address_and_always_locks(self):
        terminal = ScriptedIO(["1", str(self.backup), "yes", "0"], [PASS, PASS, SHOWN_CODE])
        result, stdout, stderr = self.run_ui(terminal)
        self.assertEqual(result, 0)
        session = self.sessions.created[0]
        self.assertEqual(session.verified_blobs, [self.backup.read_bytes()])
        self.assertEqual(session.address_calls, 1)
        self.assertTrue(session.locked)
        self.assertEqual(session.idle_seconds, 300)
        check_index = next(i for i, text in enumerate(terminal.messages) if text.startswith("Backup checked:"))
        ready_index = next(i for i, text in enumerate(terminal.messages) if text.startswith("Wallet ready"))
        self.assertLess(check_index, ready_index)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o600)
        for secret in (PASS, session.code):
            self.assertNotIn(secret, stdout + stderr + "\n".join(terminal.messages + terminal.prompts))
        self.assertEqual(terminal.codes, [session.code])
        self.assertEqual({p.name for p in self.root.iterdir()}, {"wallet.vault.json", "backup.json"})

    def test_mismatched_passphrases_never_create_a_vault(self):
        terminal = ScriptedIO(["1"], [PASS, NEW_PASS])
        result, _, _ = self.run_ui(terminal)
        self.assertEqual(result, 1)
        self.assertFalse(self.path.exists())
        self.assertFalse(self.sessions.created)

    def test_cancel_before_creation_does_not_write_secrets(self):
        terminal = ScriptedIO(["1"], [PASS, KeyboardInterrupt()])
        result, stdout, stderr = self.run_ui(terminal)
        self.assertEqual(result, 1)
        self.assertFalse(self.path.exists())
        self.assertNotIn(PASS, stdout + stderr + "\n".join(terminal.messages))

    def test_cancel_after_vault_creation_preserves_locked_vault_without_address(self):
        terminal = ScriptedIO(["1", KeyboardInterrupt()], [PASS, PASS])
        result, _, _ = self.run_ui(terminal)
        self.assertEqual(result, 1)
        session = self.sessions.created[0]
        self.assertTrue(session.locked)
        self.assertTrue(self.path.exists())
        self.assertEqual(session.address_calls, 0)
        self.assertFalse(any("Wallet ready" in text for text in terminal.messages))
        self.assertTrue(any("setup is incomplete" in text for text in terminal.messages))

    def test_refused_offline_confirmation_leaves_setup_incomplete(self):
        terminal = ScriptedIO(["1", str(self.backup), "no"], [PASS, PASS])
        result, _, _ = self.run_ui(terminal)
        self.assertEqual(result, 1)
        session = self.sessions.created[0]
        self.assertTrue(session.locked)
        self.assertEqual(session.address_calls, 0)
        self.assertTrue(self.path.exists() and self.backup.exists())

    def test_wrong_backup_code_never_shows_ready_or_address(self):
        terminal = ScriptedIO(["1", str(self.backup), "yes"], [PASS, PASS, "wrong recovery code"])
        result, stdout, stderr = self.run_ui(terminal)
        self.assertEqual(result, 1)
        session = self.sessions.created[0]
        self.assertTrue(session.locked)
        self.assertEqual(session.address_calls, 0)
        self.assertNotIn(session.code, stdout + stderr + "\n".join(terminal.messages))

    def test_backup_check_reads_disk_after_display_not_original_buffer(self):
        def mutate(text):
            if text.startswith("Have you stored"):
                self.backup.write_bytes(b"tampered persisted backup")
        terminal = ScriptedIO(["1", str(self.backup), "yes"], [PASS, PASS, SHOWN_CODE], callback=mutate)
        result, _, _ = self.run_ui(terminal)
        session = self.sessions.created[0]
        self.assertEqual(result, 1)
        self.assertEqual(session.verified_blobs, [b"tampered persisted backup"])
        self.assertEqual(session.address_calls, 0)
        self.assertTrue(session.locked)

    def test_idle_lock_while_storing_code_unlocks_and_checks_same_backup(self):
        def expire(text):
            if text.startswith("Have you stored"):
                self.sessions.created[0].lock()
        terminal = ScriptedIO(["1", str(self.backup), "yes", "0"], [PASS, PASS, SHOWN_CODE, PASS], callback=expire)
        result, _, _ = self.run_ui(terminal)
        session = self.sessions.created[0]
        self.assertEqual(result, 0)
        self.assertEqual(session.unlocks, [PASS])
        self.assertEqual(session.verified_blobs, [self.backup.read_bytes()])
        self.assertEqual(session.address_calls, 1)
        self.assertTrue(session.locked)

    def test_existing_vault_and_backup_are_never_overwritten(self):
        wallet.recovery.write_private(self.path, b"existing encrypted wallet")
        terminal = ScriptedIO(["1"], [PASS, PASS])
        self.assertEqual(self.run_ui(terminal)[0], 1)
        self.assertEqual(self.path.read_bytes(), b"existing encrypted wallet")
        self.path.unlink()
        wallet.recovery.write_private(self.backup, b"existing encrypted backup")
        terminal = ScriptedIO(["1", str(self.backup)], [PASS, PASS])
        self.assertEqual(self.run_ui(terminal)[0], 1)
        self.assertEqual(self.backup.read_bytes(), b"existing encrypted backup")
        self.assertTrue(self.sessions.created[0].locked)
        self.assertFalse(terminal.codes)

    def test_existing_open_reminds_backup_and_locked_address_is_not_derived(self):
        self.sessions.create(self.path, PASS).lock()
        terminal = ScriptedIO(["2", "4", "2", "5", "2", "0"], [PASS, PASS])
        result, _, _ = self.run_ui(terminal)
        session = self.sessions.all_sessions[-1]
        self.assertEqual(result, 0)
        self.assertEqual(session.address_calls, 1)
        self.assertTrue(session.locked)
        self.assertTrue(any("Unlock the wallet first" in text for text in terminal.messages))
        self.assertTrue(any("Check a portable backup" in text for text in terminal.messages))

    def test_wrong_unlock_locks_and_does_not_leak_entered_passphrase(self):
        self.sessions.create(self.path, PASS).lock()
        terminal = ScriptedIO(["2"], [NEW_PASS])
        result, stdout, stderr = self.run_ui(terminal)
        self.assertEqual(result, 1)
        self.assertTrue(self.sessions.all_sessions[-1].locked)
        self.assertNotIn(NEW_PASS, stdout + stderr + "\n".join(terminal.messages))

    def test_recovery_creates_encrypted_destination_then_proves_new_unlock(self):
        wallet.recovery.write_private(self.backup, b"portable backup fixture")
        terminal = ScriptedIO(["3", str(self.backup), "0"],
                              ["separate offline fixture code", NEW_PASS, NEW_PASS, NEW_PASS])
        with mock.patch.object(wallet.recovery, "save_wallet") as plaintext_save:
            result, _, _ = self.run_ui(terminal)
        self.assertEqual(result, 0)
        session = self.sessions.restored[0]
        self.assertGreaterEqual(session.lock_calls, 2)
        self.assertEqual(session.unlocks, [NEW_PASS])
        self.assertTrue(session.locked)
        plaintext_save.assert_not_called()
        self.assertTrue(any("does not revoke" in text for text in terminal.messages))

    def test_failed_new_unlock_preserves_recovered_vault_without_address(self):
        wallet.recovery.write_private(self.backup, b"portable backup fixture")
        terminal = ScriptedIO(["3", str(self.backup)],
                              ["separate offline fixture code", NEW_PASS, NEW_PASS, PASS])
        result, _, _ = self.run_ui(terminal)
        self.assertEqual(result, 1)
        session = self.sessions.restored[0]
        self.assertTrue(self.path.exists() and session.locked)
        self.assertEqual(session.address_calls, 0)

    def test_default_recovery_guides_to_new_destination_and_preserves_original(self):
        wallet.recovery.write_private(self.path, b"existing encrypted vault")
        wallet.recovery.write_private(self.backup, b"portable backup fixture")
        terminal = ScriptedIO(["3", "", str(self.backup), "0"],
                              ["separate offline fixture code", NEW_PASS, NEW_PASS, NEW_PASS])
        with mock.patch.object(wallet, "DEFAULT_WALLET", self.path), mock.patch.object(wallet, "_prepare_default_parent"):
            result = wallet.main([], io_factory=lambda: terminal, session_type=self.sessions)
        self.assertEqual(result, 0)
        self.assertEqual(self.path.read_bytes(), b"existing encrypted vault")
        recovered = self.sessions.restored[0]
        self.assertNotEqual(recovered.path, self.path)
        self.assertEqual(recovered.path.parent, self.path.parent)
        self.assertTrue(recovered.path.exists() and recovered.locked)
        self.assertTrue(any(str(recovered.path) in message for message in terminal.messages))

    def test_explicit_existing_recovery_destination_cannot_replace_vault(self):
        wallet.recovery.write_private(self.path, b"existing encrypted vault")
        wallet.recovery.write_private(self.backup, b"portable backup fixture")
        terminal = ScriptedIO(["3", str(self.backup)], ["separate offline fixture code", NEW_PASS, NEW_PASS])
        self.assertEqual(self.run_ui(terminal)[0], 1)
        self.assertEqual(self.path.read_bytes(), b"existing encrypted vault")
        self.assertFalse(self.sessions.restored)

    def test_passphrase_spaces_and_unicode_are_preserved_exactly(self):
        phrase = "  coffee café river three moons  "
        terminal = ScriptedIO(["1", str(self.backup), "yes", "0"], [phrase, phrase, SHOWN_CODE])
        self.assertEqual(self.run_ui(terminal)[0], 0)
        self.assertEqual(self.sessions.passphrases[str(self.path)], phrase)

    def test_real_vault_creation_backup_and_restore_through_wizard(self):
        terminal = ScriptedIO(["1", str(self.backup), "yes", "0"], [PASS, PASS, SHOWN_CODE])
        self.assertEqual(self.run_ui(terminal, wallet.vault.WalletSession)[0], 0)
        original = wallet.vault.WalletSession(self.path)
        original.unlock(PASS)
        keys = original.public_keys()
        original.lock()
        contents = self.path.read_bytes()
        self.assertNotIn(PASS.encode(), contents)
        self.assertNotIn(terminal.codes[-1].encode(), contents)
        self.path = self.root / "restored.vault.json"
        restored = ScriptedIO(["3", str(self.backup), "0"], [terminal.codes[-1], NEW_PASS, NEW_PASS, NEW_PASS])
        self.assertEqual(self.run_ui(restored, wallet.vault.WalletSession)[0], 0)
        session = wallet.vault.WalletSession(self.path)
        session.unlock(NEW_PASS)
        self.assertEqual(session.public_keys(), keys)
        session.lock()
        self.assertEqual({p.name for p in self.root.iterdir()}, {"wallet.vault.json", "restored.vault.json", "backup.json"})


class TerminalBoundaryTests(unittest.TestCase):
    def test_nonseekable_terminal_descriptor_opens_without_secret_input(self):
        # Exercise the real terminal stream type, but no wizard or secret input.
        import pty
        master, slave = pty.openpty()
        streams = {name: mock.Mock(isatty=mock.Mock(return_value=True)) for name in ("stdin", "stdout", "stderr")}
        try:
            with mock.patch.multiple(wallet.sys, **streams), mock.patch.object(wallet.os, "open", return_value=os.dup(slave)):
                with wallet.TerminalIO() as terminal:
                    terminal.message("public terminal stream test")
                    self.assertIn(b"public terminal stream test", os.read(master, 1024))
        finally:
            os.close(master)
            os.close(slave)

    def test_unknown_secret_bearing_arguments_are_not_echoed(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as stopped:
                wallet.main(["--passphrase", "accidentally supplied secret"])
        self.assertEqual(stopped.exception.code, 2)
        self.assertNotIn("accidentally supplied secret", stdout.getvalue() + stderr.getvalue())

    def test_hidden_input_is_bounded_after_read_without_printing_it(self):
        terminal = wallet.TerminalIO()
        terminal._tty = io.StringIO()
        with mock.patch.object(wallet.getpass, "getpass", return_value="x" * 1025):
            with self.assertRaises(wallet.WalletUIError): terminal.secret("Hidden: ")
        self.assertEqual(terminal._tty.getvalue(), "")

    def test_redirected_io_refused_before_any_session_action(self):
        output, error = io.StringIO(), io.StringIO()
        with mock.patch.object(wallet.sys, "stdin", io.StringIO("1\n")), redirect_stdout(output), redirect_stderr(error):
            with mock.patch.object(wallet.vault.WalletSession, "create") as create:
                self.assertEqual(wallet.main([]), 1)
                create.assert_not_called()
        self.assertEqual(output.getvalue(), "")
        self.assertIn("interactive terminal", error.getvalue())

    def test_each_standard_stream_must_be_a_terminal(self):
        for failed in range(3):
            streams = [mock.Mock(), mock.Mock(), mock.Mock()]
            for index, stream in enumerate(streams): stream.isatty.return_value = index != failed
            with self.subTest(failed=failed), mock.patch.multiple(wallet.sys, stdin=streams[0], stdout=streams[1], stderr=streams[2]):
                with mock.patch.object(wallet.os, "open") as opened:
                    with self.assertRaises(wallet.WalletUIError): wallet.TerminalIO().__enter__()
                    opened.assert_not_called()

    def test_missing_terminal_echo_control_closes_descriptor_and_fails(self):
        streams = {name: mock.Mock(isatty=mock.Mock(return_value=True)) for name in ("stdin", "stdout", "stderr")}
        with mock.patch.multiple(wallet.sys, **streams), mock.patch.object(wallet.os, "open", return_value=123), \
             mock.patch.object(wallet.os, "isatty", return_value=True), mock.patch.object(wallet.os, "close") as close, \
             mock.patch.object(wallet.termios, "tcgetattr", side_effect=wallet.termios.error("test")):
            with self.assertRaises(wallet.termios.error): wallet.TerminalIO().__enter__()
            close.assert_called_once_with(123)

    def test_getpass_warning_prevents_echoing_fallback(self):
        terminal = wallet.TerminalIO()
        terminal._tty = io.StringIO()
        fallback_reached = []
        def warning_then_read(*_, **__):
            warnings.warn("cannot disable echo", wallet.getpass.GetPassWarning)
            fallback_reached.append(True)
            return "must never be read"
        with mock.patch.object(wallet.getpass, "getpass", side_effect=warning_then_read):
            with self.assertRaises(wallet.WalletUIError): terminal.secret("Hidden: ")
        self.assertFalse(fallback_reached)

    def test_recovery_code_display_uses_only_owned_terminal_stream(self):
        terminal = wallet.TerminalIO()
        terminal._tty = io.StringIO()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            terminal.show_recovery_code("disposable test-only recovery code")
        self.assertIn("disposable test-only recovery code", terminal._tty.getvalue())
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
