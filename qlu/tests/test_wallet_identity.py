"""Wallet selection continuity with disposable encrypted vaults and a fake network."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from qlu import wallet_app
from qlu.tests import test_wallet_app as bridge_tests


class WalletIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.network = bridge_tests.Network()
        self.app = wallet_app.WalletApp(self.root, self.network)
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(self.app.close)
        self.sequence = 0

    def request(self, command, **params):
        self.sequence += 1
        return self.app.handle({"id": self.sequence, "command": command, "params": params})

    def success(self, command, **params):
        response = self.request(command, **params)
        self.assertTrue(response["ok"], response)
        return response["result"]

    def verified(self):
        self.success("create", passphrase=bridge_tests.PASS, confirmation=bridge_tests.PASS)
        backup = self.root / (uuid.uuid4().hex + ".json")
        code = self.success("backup_create", backup_path=str(backup))["code"]
        self.success("backup_verify", backup_path=str(backup), code=code)
        return backup, code

    def replacement(self, passphrase=bridge_tests.PASS, *, backup=None, code=None):
        path = self.root / (uuid.uuid4().hex + ".vault.json")
        if backup is None:
            session = wallet_app.vault.WalletSession.create(path, passphrase)
        else:
            session = wallet_app.vault.WalletSession.restore(path, backup.read_bytes(), code, passphrase)
        self.addCleanup(session.lock)
        keys = session.public_keys()
        session.lock()
        return path, keys

    def assert_authentication_cleared(self, *, selected, app=None):
        app = app or self.app
        state = app.state()
        self.assertEqual(state["wallet_open"], selected)
        self.assertTrue(state["locked"])
        self.assertFalse(state["backup_verified"])
        self.assertFalse(state["network_healthy"])
        self.assertIsNone(state["address"])
        self.assertIsNone(state["balance"])
        self.assertIsNone(state["immature_balance"])
        self.assertIsNone(state["recent_payment"])
        self.assertFalse(state["history_loaded"])
        self.assertEqual(state["payment_history"], [])
        self.assertIsNone(app.keys)
        self.assertIsNone(app.history)
        self.assertIsNone(app._preview)
        if not selected:
            self.assertIsNone(app.session)
            self.assertIsNone(app.wallet_path)

    def test_replaced_wallet_same_passphrase_requires_explicit_open(self):
        self.verified()
        self.success("network_start")
        old_path = self.app.wallet_path
        replacement, _ = self.replacement()
        self.success("lock")
        os.replace(replacement, old_path)
        response = self.request("unlock", passphrase=bridge_tests.PASS)
        self.assertFalse(response["ok"], "A different wallet must not silently replace the selected identity")
        self.assertEqual(response["error"]["code"], "wallet_changed")
        self.assert_authentication_cleared(selected=False)

    def test_replaced_wallet_different_passphrase_reports_changed_not_wrong_password(self):
        self.verified()
        old_path = self.app.wallet_path
        replacement, _ = self.replacement(bridge_tests.OTHER_PASS)
        self.success("lock")
        os.replace(replacement, old_path)
        response = self.request("unlock", passphrase=bridge_tests.PASS)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "wallet_changed")
        self.assert_authentication_cleared(selected=False)

    def test_same_seed_reencrypted_vault_requires_explicit_open(self):
        backup, code = self.verified()
        old_path, old_keys = self.app.wallet_path, dict(self.app.keys)
        replacement, replacement_keys = self.replacement(backup=backup, code=code)
        self.assertEqual(replacement_keys, old_keys)
        self.assertNotEqual(replacement.read_bytes(), old_path.read_bytes())
        self.success("lock")
        os.replace(replacement, old_path)
        response = self.request("unlock", passphrase=bridge_tests.PASS)
        self.assertFalse(response["ok"], "New ciphertext must be explicitly selected even with the same seed")
        self.assertEqual(response["error"]["code"], "wallet_changed")
        self.assert_authentication_cleared(selected=False)

    def test_wrong_passphrase_clears_cached_identity_and_approval_but_allows_retry(self):
        self.verified()
        self.success("network_start")
        address = self.app.state()["address"]
        preview = self.success("prepare_send", recipient=address, amount="1.00000000")
        selected_path = self.app.wallet_path
        response = self.request("unlock", passphrase=bridge_tests.OTHER_PASS)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "wallet_failed")
        self.assert_authentication_cleared(selected=True)
        self.assertEqual(self.app.wallet_path, selected_path)
        state = self.success("unlock", passphrase=bridge_tests.PASS)
        self.assertEqual(state["address"], address)
        self.assertTrue(state["backup_verified"])
        self.assertEqual(self.request("confirm_send", preview_id=preview["preview_id"])["error"]["code"], "preview_invalid")
        self.assertEqual(self.network.sent, [])

    def pending(self, app=None, txid="b7" * 32):
        app = app or self.app
        recipient = wallet_app.protocol.address_for(app.keys)
        operation = app.history.begin("send", recipient=recipient, amount="0.1", fee="0.001")
        app.history.before_broadcast(operation, {
            "txid": txid, "recipient": recipient, "amount": "0.1", "fee": "0.001", "start_height": 1,
        })
        return operation

    def test_open_pins_file_before_first_unlock(self):
        self.verified()
        path = self.app.wallet_path
        self.success("open", path=str(path))
        replacement, _ = self.replacement()
        os.replace(replacement, path)
        self.assertEqual(self.request("unlock", passphrase=bridge_tests.PASS)["error"]["code"], "wallet_changed")
        self.assert_authentication_cleared(selected=False)

    def test_identical_ciphertext_replacement_keeps_identity_and_pending_guard(self):
        self.verified()
        operation = self.pending()
        path, keys = self.app.wallet_path, dict(self.app.keys)
        identical = self.root / "identical.vault.json"
        wallet_app.recovery.write_private(identical, path.read_bytes())
        self.success("lock")
        os.replace(identical, path)
        state = self.success("unlock", passphrase=bridge_tests.PASS)
        self.assertEqual(self.app.keys, keys)
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["payment_history"][0]["operation_id"], operation)
        self.assertTrue(state["backup_verified"])

    def test_explicit_open_replacement_binds_b_history_and_preserves_a_history(self):
        self.verified()
        path_a, keys_a = self.app.wallet_path, dict(self.app.keys)
        operation_a = self.pending(txid="a7" * 32)
        preserved_a = self.root / "preserved-a.vault.json"
        wallet_app.recovery.write_private(preserved_a, path_a.read_bytes())
        other = wallet_app.WalletApp(self.root, bridge_tests.Network())
        self.addCleanup(other.close)
        other.execute("create", {"passphrase": bridge_tests.OTHER_PASS, "confirmation": bridge_tests.OTHER_PASS})
        path_b, keys_b = other.wallet_path, dict(other.keys)
        backup_b = self.root / "backup-b.json"
        code_b = other.execute("backup_create", {"backup_path": str(backup_b)})["code"]
        other.execute("backup_verify", {"backup_path": str(backup_b), "code": code_b})
        operation_b = self.pending(other, txid="b8" * 32)
        other.close()
        self.success("lock")
        os.replace(path_b, path_a)
        self.assertEqual(self.request("unlock", passphrase=bridge_tests.OTHER_PASS)["error"]["code"], "wallet_changed")
        self.success("open", path=str(path_a))
        state = self.success("unlock", passphrase=bridge_tests.OTHER_PASS)
        self.assertEqual(self.app.history.wallet_id, keys_b["key_commitment"])
        self.assertEqual(state["address"], wallet_app.protocol.address_for(keys_b))
        self.assertTrue(state["backup_verified"])
        self.assertTrue(state["payment_blocked"])
        self.assertEqual([row["operation_id"] for row in state["payment_history"]], [operation_b])
        self.success("network_start")
        for command, params in (("prepare_send", {"recipient": state["address"], "amount": "0.1"}),
                                ("faucet", {"operation_id": uuid.uuid4().hex})):
            self.assertEqual(self.request(command, **params)["error"]["code"], "payment_pending")
        self.assertEqual(self.network.sent, [])
        self.assertEqual(self.network.funded, [])
        self.success("open", path=str(preserved_a))
        restored_a = self.success("unlock", passphrase=bridge_tests.PASS)
        self.assertEqual(self.app.history.wallet_id, keys_a["key_commitment"])
        self.assertEqual([row["operation_id"] for row in restored_a["payment_history"]], [operation_a])
        self.assertTrue(restored_a["payment_blocked"])

    def test_explicit_open_reencrypted_same_seed_preserves_pending_but_needs_new_receipt(self):
        backup, code = self.verified()
        path = self.app.wallet_path
        operation = self.pending()
        replacement, keys = self.replacement(backup=backup, code=code)
        self.success("lock")
        os.replace(replacement, path)
        self.assertEqual(self.request("unlock", passphrase=bridge_tests.PASS)["error"]["code"], "wallet_changed")
        self.success("open", path=str(path))
        state = self.success("unlock", passphrase=bridge_tests.PASS)
        self.assertEqual(self.app.history.wallet_id, keys["key_commitment"])
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["payment_history"][0]["operation_id"], operation)
        self.assertFalse(state["backup_verified"])
        self.assertEqual(state["backup_verification_status"], "required")
        state = self.success("backup_verify", backup_path=str(backup), code=code)
        self.assertTrue(state["backup_verified"])
        self.assertTrue(state["payment_blocked"])

    def test_competing_instance_cannot_unlock_until_owner_releases_history(self):
        self.verified()
        path = self.app.wallet_path
        operation = self.pending()
        competitor = wallet_app.WalletApp(self.root, bridge_tests.Network())
        self.addCleanup(competitor.close)
        competitor.execute("open", {"path": str(path)})
        response = competitor.handle({"id": 1, "command": "unlock", "params": {"passphrase": bridge_tests.PASS}})
        self.assertEqual(response["error"]["code"], "history_unavailable")
        self.assertIsNone(competitor.keys)
        self.assertIsNone(competitor.history)
        self.assertTrue(competitor.session.locked)
        self.assertFalse(competitor.backup_verified)
        self.assertIsNone(competitor.state()["address"])
        self.assertEqual(self.app.history.records()[0]["operation_id"], operation)
        self.assertEqual(self.request("unlock", passphrase=bridge_tests.OTHER_PASS)["error"]["code"], "wallet_failed")
        acquired = competitor.execute("unlock", {"passphrase": bridge_tests.PASS})
        self.assertTrue(acquired["payment_blocked"])
        self.assertEqual(acquired["payment_history"][0]["operation_id"], operation)
        self.assertEqual(self.request("unlock", passphrase=bridge_tests.PASS)["error"]["code"], "history_unavailable")
        self.assert_authentication_cleared(selected=True)
        competitor.close()
        state = self.success("unlock", passphrase=bridge_tests.PASS)
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["payment_history"][0]["operation_id"], operation)

    def test_mismatched_in_memory_history_fails_before_reconciliation_or_payment(self):
        self.verified()
        self.success("network_start")
        preview = self.success("prepare_send", recipient=self.app.state()["address"], amount="0.1")
        self.app.history.close()
        foreign_path, foreign_keys = self.replacement()
        self.app.history = wallet_app.PaymentHistory(self.app.app_dir / "payment-history", foreign_keys["key_commitment"])
        with mock.patch.object(self.network, "payment_status", side_effect=AssertionError("No foreign reconciliation")), \
                mock.patch.object(self.network, "send", side_effect=AssertionError("No signing")):
            response = self.request("confirm_send", preview_id=preview["preview_id"])
        self.assertEqual(response["error"]["code"], "wallet_changed")
        self.assert_authentication_cleared(selected=False)

    def test_create_history_acquisition_failure_clears_authority_but_preserves_encrypted_file(self):
        created = []
        create = wallet_app.vault.WalletSession.create
        def capture_create(*args, **kwargs):
            session = create(*args, **kwargs)
            created.append(session)
            self.addCleanup(session.lock)
            return session
        with mock.patch.object(wallet_app.vault.WalletSession, "create", side_effect=capture_create), \
                mock.patch.object(wallet_app, "PaymentHistory", side_effect=wallet_app.HistoryError()):
            response = self.request("create", passphrase=bridge_tests.PASS, confirmation=bridge_tests.PASS)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "history_unavailable")
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].locked)
        self.assert_authentication_cleared(selected=False)
        artifacts = list((self.app.app_dir / "wallets").glob("*.vault.json"))
        self.assertEqual(len(artifacts), 1)
        artifact = artifacts[0]
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(bridge_tests.PASS.encode(), artifact.read_bytes())
        self.assertNotIn(b"master_seed", artifact.read_bytes())
        # The retained encrypted artifact is usable only through a new explicit
        # selection and passphrase, after history ownership can be acquired.
        self.success("open", path=str(artifact))
        state = self.success("unlock", passphrase=bridge_tests.PASS)
        self.assertFalse(state["locked"])
        self.assertTrue(state["history_loaded"])
        self.assertFalse(state["backup_verified"])
        self.assertEqual(self.network.sent, [])
        self.assertEqual(self.network.funded, [])

    def test_restore_history_contention_clears_new_session_preserves_files_and_owner(self):
        backup, code = self.verified()
        operation = self.pending()
        owner_path, owner_keys = self.app.wallet_path, dict(self.app.keys)
        original_bytes, backup_bytes = owner_path.read_bytes(), backup.read_bytes()
        journal = self.app.app_dir / "payment-history" / (owner_keys["key_commitment"] + ".json")
        journal_bytes = journal.read_bytes()
        before = set((self.app.app_dir / "wallets").glob("*.vault.json"))
        competitor = wallet_app.WalletApp(self.root, bridge_tests.Network())
        self.addCleanup(competitor.close)
        restored = []
        restore = wallet_app.vault.WalletSession.restore
        def capture_restore(*args, **kwargs):
            session = restore(*args, **kwargs)
            restored.append(session)
            self.addCleanup(session.lock)
            return session
        with mock.patch.object(wallet_app.vault.WalletSession, "restore", side_effect=capture_restore):
            response = competitor.handle({"id": 1, "command": "restore", "params": {
                "backup_path": str(backup), "code": code,
                "passphrase": bridge_tests.OTHER_PASS, "confirmation": bridge_tests.OTHER_PASS,
            }})
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "history_unavailable")
        self.assertEqual(len(restored), 1)
        self.assertTrue(restored[0].locked)
        self.assert_authentication_cleared(selected=False, app=competitor)
        after = set((self.app.app_dir / "wallets").glob("*.vault.json"))
        self.assertEqual(len(after - before), 1)
        artifact = (after - before).pop()
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(bridge_tests.OTHER_PASS.encode(), artifact.read_bytes())
        self.assertNotIn(b"master_seed", artifact.read_bytes())
        self.assertEqual(owner_path.read_bytes(), original_bytes)
        self.assertEqual(backup.read_bytes(), backup_bytes)
        self.assertEqual(journal.read_bytes(), journal_bytes)
        self.assertFalse(self.app.session.locked)
        self.assertEqual(self.app.keys, owner_keys)
        self.assertTrue(self.app.history.blocked)
        self.assertEqual(self.app.history.records()[0]["operation_id"], operation)
        # Decrypt this new fixture without adopting its contested history: it is
        # a preserved recovery artifact, never a surviving app signing session.
        recovered = wallet_app.vault.WalletSession(artifact)
        self.addCleanup(recovered.lock)
        recovered.unlock(bridge_tests.OTHER_PASS)
        self.assertEqual(recovered.public_keys(), owner_keys)
        recovered.lock()
        self.assertEqual(journal.read_bytes(), journal_bytes)
        self.assertEqual(competitor.network.sent, [])
        self.assertEqual(competitor.network.funded, [])


if __name__ == "__main__":
    unittest.main()
