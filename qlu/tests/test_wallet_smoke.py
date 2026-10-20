"""Failure boundaries for the disposable encrypted-wallet recovery worker."""
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocol
import recovery
import wallet_smoke
from vault import VaultError


class WorkerTests(unittest.TestCase):
    def run_bad_request(self, payload):
        output, errors = io.StringIO(), io.StringIO()
        stream = Mock(buffer=io.BytesIO(payload))
        with patch.object(wallet_smoke.sys, "stdin", stream), \
                patch.object(wallet_smoke.WalletSession, "restore") as restore, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(wallet_smoke.restore_worker(), 1)
            restore.assert_not_called()
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "Encrypted recovery worker failed.\n")

    def test_malformed_request_does_not_echo_secret(self):
        self.run_bad_request(b'{"code":"disposable-secret-never-in-errors",')

    def test_oversized_input_is_rejected_before_restoration(self):
        self.run_bad_request(b" " * (recovery.MAX_BACKUP_BYTES + 1))

    def test_unknown_field_is_rejected_before_restoration(self):
        self.run_bad_request(recovery._canonical({"code": "disposable", "unexpected": True}))

    def test_invalid_challenge_is_rejected_before_restoration(self):
        self.run_bad_request(recovery._canonical({
            "vault": "unused.vault.json", "backup": "unused.backup.json",
            "code": "disposable", "passphrase": "disposable secret passphrase",
            "challenge": {"network_id": protocol.NETWORK, "genesis_hash": "00" * 32}}))

    def test_locked_assertion_requires_actual_signing_refusal(self):
        session = Mock()
        with self.assertRaises(wallet_smoke.DevnetError):
            wallet_smoke.expect_locked(session, Mock(), Mock())
        session.sign.side_effect = VaultError("Wallet is locked")
        wallet_smoke.expect_locked(session, Mock(), Mock())


if __name__ == "__main__":
    unittest.main()
