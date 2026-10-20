"""Disposable encrypted-wallet trials; no physical-device pass is simulated."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock

from qlu import wallet_device as target
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut

PASS = "disposable device trial password"


class TestIO:
    def __init__(self, answers=(), hidden=(), on_secret=None):
        self.answers, self.hidden = iter(answers), iter(hidden)
        self.messages, self.prompts = [], []
        self.on_secret = on_secret

    def __enter__(self): return self
    def __exit__(self, *_): pass
    def message(self, value): self.messages.append(value)
    def prompt(self, value):
        self.prompts.append(value)
        try: result = next(self.answers)
        except StopIteration: raise EOFError from None
        if isinstance(result, BaseException): raise result
        return result
    def secret(self, value):
        self.prompts.append(value)
        if self.on_secret: self.on_secret(value)
        try: result = next(self.hidden)
        except StopIteration: raise EOFError from None
        if isinstance(result, BaseException): raise result
        return result


class WalletDeviceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wallet = target.recovery.generate_wallet(target.protocol.NETWORK, target.protocol.GENESIS)
        cls.keys = target.protocol.keytool(cls.wallet)
        cls.backup, cls.code = target.recovery.make_backup(cls.wallet)
        cls.tx = CTransaction()
        cls.tx.vin = [CTxIn(COutPoint(int("12" * 32, 16), 3), nSequence=0xffffffff)]
        cls.tx.vout = [CTxOut(99900000, b"\x52\x20" + bytes.fromhex("34" * 32))]
        previous = CTxOut(100000000, target.protocol.script_for(cls.keys))
        cls.challenge = target.device.make_challenge(cls.tx, previous, cls.keys["key_commitment"])
        with tempfile.TemporaryDirectory(prefix="wallet-device-fixture-", dir=target.ROOT / ".local") as directory:
            cls.result = target.recover_sign(cls.backup, cls.code, PASS, cls.challenge, Path(directory).resolve() / "vault.json")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wallet-device-tests-", dir=target.ROOT / ".local")
        self.directory = Path(self.temp.name).resolve()
        self.vault_path = self.directory / "vault.json"
        self.backup_path = self.directory / "backup.json"
        self.challenge_path = self.directory / "challenge.json"
        self.response_path = self.directory / "wallet-response.json"
        target.recovery.write_private(self.backup_path, self.backup)
        target.device.write_document(self.challenge_path, self.challenge)

    def tearDown(self): self.temp.cleanup()

    def tracked_sessions(self):
        class Tracked(target.vault.WalletSession):
            instances = []
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.instances.append(self)
        return Tracked

    def run_ui(self, terminal, **kwargs):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            result = target.run(terminal, self.backup_path, self.challenge_path, self.vault_path,
                                self.response_path, **kwargs)
        self.assertEqual(output.getvalue() + error.getvalue(), "")
        for secret in (PASS, self.code, self.wallet["master_seed"]):
            self.assertNotIn(secret, "\n".join(terminal.messages + terminal.prompts))
        return result

    def test_real_rehearsal_has_exact_transaction_all_checks_and_no_secrets(self):
        signed = target.validate_result(self.result, self.challenge)
        self.assertEqual(signed.serialize_without_witness(), self.tx.serialize_without_witness())
        self.assertEqual([len(x) for x in signed.wit.vtxinwit[0].scriptWitness.stack], [1952, 32, 3309, 64])
        self.assertEqual(self.result["response"]["mode"], "rehearsal")
        self.assertEqual(self.result["wallet_test"]["checks"], dict.fromkeys(target.CHECKS, True))
        self.assertEqual(self.result["wallet_test"]["tooling"], target.wallet_tooling())
        self.assertGreaterEqual(self.result["wallet_test"]["observed_idle_seconds"], .05)
        for secret in (PASS, self.code, self.wallet["master_seed"]):
            self.assertNotIn(secret, json.dumps(self.result))

    def test_real_interactive_rehearsal_reopens_saved_encrypted_wallet_and_locks(self):
        sessions = self.tracked_sessions()
        terminal = TestIO(["yes"], [self.code, PASS, PASS, PASS, PASS])
        with mock.patch.object(target.vault, "WalletSession", sessions):
            self.assertEqual(self.run_ui(terminal, mode="rehearsal"), 0)
        self.assertEqual(len(sessions.instances), 2)
        self.assertTrue(all(session.locked and session._wallet is None for session in sessions.instances))
        stored = self.vault_path.read_bytes()
        self.assertEqual(json.loads(stored)["format"], "qlu-local-vault")
        self.assertNotIn(self.wallet["master_seed"].encode(), stored)
        self.assertEqual(stat.S_IMODE(self.vault_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.response_path.stat().st_mode), 0o600)
        target.validate_result(target.device.read_document(self.response_path), self.challenge)
        self.assertTrue(any("REHEARSAL ONLY" in message for message in terminal.messages))

    def test_automated_api_cannot_claim_physical_test(self):
        with mock.patch.object(target.vault.WalletSession, "restore") as restore:
            with self.assertRaises(target.WalletDeviceError):
                target.recover_sign(self.backup, self.code, PASS, self.challenge, self.vault_path,
                                    mode="physical-device", idle_seconds=300)
            restore.assert_not_called()
        self.assertFalse(self.vault_path.exists())

    def test_physical_timer_cannot_be_shortened_and_attestation_is_required(self):
        for seconds in (.05, 299, 301, True, 0, float("nan")):
            terminal = TestIO()
            self.assertEqual(self.run_ui(terminal, mode="physical-device", idle_seconds=seconds), 1)
            self.assertFalse(terminal.prompts)
        terminal = TestIO(["no"])
        self.assertEqual(self.run_ui(terminal), 1)
        self.assertEqual(len(terminal.prompts), 1)
        self.assertFalse(self.vault_path.exists())

    def test_shortened_wait_never_produces_response_and_always_locks(self):
        sessions = self.tracked_sessions()
        with mock.patch.object(target.vault, "WalletSession", sessions):
            with self.assertRaises(target.WalletDeviceError):
                target.recover_sign(self.backup, self.code, PASS, self.challenge, self.vault_path,
                                    wait_for_idle=lambda _: None)
        self.assertTrue(all(session.locked and session._wallet is None for session in sessions.instances))
        self.assertTrue(self.vault_path.exists())
        self.assertFalse(self.response_path.exists())

    def test_idle_interval_has_no_key_operations_or_status_polling(self):
        sessions = self.tracked_sessions()
        def wait(seconds):
            session = sessions.instances[-1]
            generation = session._generation
            deadline = session._deadline
            time.sleep(seconds / 3)
            self.assertEqual(session._generation, generation)
            self.assertEqual(session._deadline, deadline)
            time.sleep(seconds)
            # Timer independently clears the reference before locked property is read.
            self.assertIsNone(session._wallet)
        with mock.patch.object(target.vault, "WalletSession", sessions):
            result = target.recover_sign(self.backup, self.code, PASS, self.challenge, self.vault_path,
                                         idle_seconds=.1, wait_for_idle=wait)
        target.validate_result(result, self.challenge)

    def test_wrong_code_or_mismatched_passphrase_never_creates_vault(self):
        for hidden in ([target.recovery.generate_recovery_code(), PASS, PASS],
                       [self.code, PASS, "a different long passphrase"]):
            terminal = TestIO([], hidden)
            self.assertEqual(self.run_ui(terminal, mode="rehearsal"), 1)
            self.assertFalse(self.vault_path.exists())
            self.assertFalse(self.response_path.exists())

    def test_wrong_new_passphrase_on_reopen_leaves_saved_vault_locked(self):
        sessions = self.tracked_sessions()
        terminal = TestIO([], [self.code, PASS, PASS, "another wrong long passphrase"])
        with mock.patch.object(target.vault, "WalletSession", sessions):
            self.assertEqual(self.run_ui(terminal, mode="rehearsal"), 1)
        self.assertTrue(self.vault_path.exists())
        self.assertTrue(all(session.locked for session in sessions.instances))
        self.assertFalse(self.response_path.exists())

    def test_cancel_or_decline_after_recovery_retains_locked_vault_no_response(self):
        for action in ("no", KeyboardInterrupt()):
            with self.subTest(action=type(action).__name__):
                sessions = self.tracked_sessions()
                terminal = TestIO([action], [self.code, PASS, PASS, PASS, PASS])
                with mock.patch.object(target.vault, "WalletSession", sessions):
                    self.assertEqual(self.run_ui(terminal, mode="rehearsal"), 1)
                self.assertTrue(all(session.locked for session in sessions.instances))
                self.assertFalse(self.response_path.exists())
                self.vault_path.unlink()  # Only this test's disposable fixture.

    def test_saved_backup_is_read_again_before_verification(self):
        def change_backup(prompt):
            if prompt.startswith("Re-enter"):
                self.backup_path.write_bytes(b"damaged saved backup")
        sessions = self.tracked_sessions()
        terminal = TestIO([], [self.code, PASS, PASS, PASS], on_secret=change_backup)
        with mock.patch.object(target.vault, "WalletSession", sessions):
            self.assertEqual(self.run_ui(terminal, mode="rehearsal"), 1)
        self.assertTrue(all(session.locked for session in sessions.instances))
        self.assertFalse(self.response_path.exists())

    def test_existing_vault_response_and_symlink_refused_before_secret_prompts(self):
        for path in (self.vault_path, self.response_path):
            target.recovery.write_private(path, b"preserved existing file")
            terminal = TestIO()
            self.assertEqual(self.run_ui(terminal, mode="rehearsal"), 1)
            self.assertFalse(terminal.prompts)
            self.assertEqual(path.read_bytes(), b"preserved existing file")
            path.unlink()
        self.vault_path.symlink_to(self.directory / "missing")
        terminal = TestIO()
        self.assertEqual(self.run_ui(terminal, mode="rehearsal"), 1)
        self.assertFalse(terminal.prompts)
        self.assertTrue(self.vault_path.is_symlink())

    def test_bad_challenge_refused_before_restore(self):
        changed = {**self.challenge, "network_id": "main"}
        with mock.patch.object(target.vault.WalletSession, "restore") as restore:
            with self.assertRaises(target.device.DeviceRecoveryError):
                target.recover_sign(self.backup, self.code, PASS, changed, self.vault_path)
            restore.assert_not_called()

    def test_result_validator_rejects_missing_false_unknown_and_malformed_evidence(self):
        changes = []
        for name in target.CHECKS:
            changed = copy.deepcopy(self.result)
            changed["wallet_test"]["checks"][name] = False
            changes.append(changed)
        for value in (True, 0, -.1, float("nan"), float("inf"), 1 << 10000):
            changed = copy.deepcopy(self.result)
            changed["wallet_test"]["observed_idle_seconds"] = value
            changes.append(changed)
        for mutate in (lambda x: x.update(extra=0), lambda x: x.update(version=True),
                       lambda x: x["wallet_test"]["checks"].pop("restored_encrypted"),
                       lambda x: x["wallet_test"]["checks"].update(restored_encrypted=1),
                       lambda x: x["wallet_test"]["tooling"].update(vault_sha256="A" * 64),
                       lambda x: x["response"].update(signed_tx=self.challenge["unsigned_tx"]),
                       lambda x: x["wallet_test"].update(observed_idle_seconds=.001)):
            changed = copy.deepcopy(self.result)
            mutate(changed)
            changes.append(changed)
        for changed in changes:
            with self.assertRaises(target.device.DeviceRecoveryError):
                target.validate_result(changed, self.challenge)

    def test_physical_evidence_requires_exact_full_interval_but_remains_self_reported(self):
        claimed = copy.deepcopy(self.result)
        claimed["response"]["mode"] = "physical-device"
        with self.assertRaises(target.WalletDeviceError):
            target.validate_result(claimed, self.challenge)
        claimed["wallet_test"].update(idle_seconds=300, observed_idle_seconds=300.01)
        # Format validity is deliberately NOT proof of physical hardware or timing.
        target.validate_result(claimed, self.challenge)
        for value in (299.99, 3601, True):
            claimed["wallet_test"]["observed_idle_seconds"] = value
            with self.assertRaises(target.WalletDeviceError):
                target.validate_result(claimed, self.challenge)

    def test_cli_has_no_secret_or_timer_options_and_never_echoes_unknown_arguments(self):
        for arguments in (["--passphrase", PASS], ["--code-file", self.code], ["--idle-seconds", "1"]):
            error = io.StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit) as stop:
                target.main(arguments)
            self.assertEqual(stop.exception.code, 2)
            self.assertNotIn(PASS, error.getvalue())
            self.assertNotIn(self.code, error.getvalue())

    def test_non_terminal_cli_fails_without_collecting_secrets(self):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(target.main([]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("interactive human terminal", error.getvalue())


if __name__ == "__main__":
    unittest.main()
