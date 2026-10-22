"""Authenticated local verification receipts using disposable wallet fixtures only."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from qlu import backup_verification as store
from qlu import vault

PASSPHRASE = "synthetic river amber lantern meadow"


class ReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wallet = vault.recovery.generate_wallet(vault.protocol.NETWORK, vault.protocol.GENESIS)
        cls.encrypted = vault._encrypt(cls.wallet, PASSPHRASE.encode())
        cls.backup, cls.code = vault.recovery.make_backup(cls.wallet)
        cls.other_wallet = vault.recovery.generate_wallet(vault.protocol.NETWORK, vault.protocol.GENESIS)
        cls.other_backup, cls.other_code = vault.recovery.make_backup(cls.other_wallet)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "wallet.vault.json"
        self.path.write_bytes(self.encrypted)
        self.path.chmod(0o600)
        self.session = vault.WalletSession(self.path)
        self.sessions = [self.session]
        self.directory = self.root / "backup-verification"

    def tearDown(self):
        for session in self.sessions:
            session.lock()
        self.temporary.cleanup()

    def enrolled(self):
        self.session.unlock(PASSPHRASE)
        return self.session.create_verification_receipt(self.backup, self.code)

    def remember(self, session):
        self.sessions.append(session)
        return session

    def test_receipt_requires_real_backup_authentication_and_wallet_match(self):
        self.session.unlock(PASSPHRASE)
        with self.assertRaises(vault.VaultError):
            self.session.create_verification_receipt(self.backup, self.other_code)
        with self.assertRaises(vault.VaultError):
            self.session.create_verification_receipt(self.other_backup, self.other_code)
        broken = bytearray(self.backup)
        broken[-2] ^= 1
        with self.assertRaises(vault.VaultError):
            self.session.create_verification_receipt(bytes(broken), self.code)
        receipt = self.session.create_verification_receipt(self.backup, self.code)
        self.assertTrue(self.session.accept_verification_receipt(receipt))

    def test_passphrase_only_reopen_accepts_receipt_without_backup_or_code(self):
        receipt = self.enrolled()
        digest = self.session.vault_digest
        store.save_receipt(self.directory, digest, receipt)
        self.session.lock()
        reopened = self.remember(vault.WalletSession(self.path))
        with mock.patch.object(vault.recovery, "restore_backup", side_effect=AssertionError("must not request recovery material")):
            reopened.unlock(PASSPHRASE)
            saved = store.load_receipt(self.directory, reopened.vault_digest)
            self.assertTrue(reopened.accept_verification_receipt(saved))

    def test_locked_session_cannot_enroll_or_authenticate_and_has_no_digest(self):
        self.assertIsNone(self.session.vault_digest)
        with self.assertRaisesRegex(vault.VaultError, "locked"):
            self.session.create_verification_receipt(self.backup, self.code)
        with self.assertRaisesRegex(vault.VaultError, "locked"):
            self.session.accept_verification_receipt(b"invalid")
        receipt = self.enrolled()
        self.session.lock()
        self.assertIsNone(self.session.vault_digest)
        with self.assertRaisesRegex(vault.VaultError, "locked"):
            self.session.accept_verification_receipt(receipt)

    def test_failed_unlock_clears_previous_digest(self):
        self.enrolled()
        self.assertIsNotNone(self.session.vault_digest)
        with self.assertRaises(vault.VaultError):
            self.session.unlock("wrong synthetic passphrase input")
        self.assertTrue(self.session.locked)
        self.assertIsNone(self.session.vault_digest)

    def test_idle_expiry_blocks_receipt_acceptance_before_authentication(self):
        receipt = self.enrolled()
        expired = self.session._deadline + 1
        with mock.patch.object(vault.time, "monotonic", return_value=expired), \
                mock.patch.object(vault.protocol, "keytool") as keytool:
            with self.assertRaisesRegex(vault.VaultError, "locked"):
                self.session.accept_verification_receipt(receipt)
            keytool.assert_not_called()
        self.assertTrue(self.session.locked)
        self.assertIsNone(self.session.vault_digest)

    def test_lock_during_receipt_save_prevents_unlocked_readback_acceptance(self):
        receipt = self.enrolled()
        digest = self.session.vault_digest
        original = os.fsync

        def lock_before_file_sync(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                self.session.lock()
            return original(fd)

        with mock.patch.object(store.os, "fsync", side_effect=lock_before_file_sync):
            store.save_receipt(self.directory, digest, receipt)
        saved = store.load_receipt(self.directory, digest)
        self.assertEqual(saved, receipt)
        self.assertTrue(self.session.locked)
        with self.assertRaisesRegex(vault.VaultError, "locked"):
            self.session.accept_verification_receipt(saved)
        # An authentic saved proof may be used only after a later explicit unlock.
        self.session.unlock(PASSPHRASE)
        self.assertTrue(self.session.accept_verification_receipt(saved))

    def test_digest_is_from_authenticated_read_not_a_later_file_replacement(self):
        replacement = vault._encrypt(self.wallet, PASSPHRASE.encode())
        original_read = vault.recovery.read_private

        def read_then_replace(*args, **kwargs):
            blob = original_read(*args, **kwargs)
            self.path.write_bytes(replacement)
            return blob

        with mock.patch.object(vault.recovery, "read_private", side_effect=read_then_replace) as reader:
            self.session.unlock(PASSPHRASE)
            self.assertEqual(reader.call_count, 1)
        self.assertEqual(self.session.vault_digest, hashlib.sha256(self.encrypted).hexdigest())
        self.assertNotEqual(self.session.vault_digest, hashlib.sha256(self.path.read_bytes()).hexdigest())
        receipt = self.session.create_verification_receipt(self.backup, self.code)
        self.session.lock()
        self.session.unlock(PASSPHRASE)
        self.assertFalse(self.session.accept_verification_receipt(receipt))

    def test_created_and_restored_vault_digest_matches_published_encrypted_blob(self):
        created = self.remember(vault.WalletSession.create(self.root / "created.json", PASSPHRASE))
        self.assertEqual(created.vault_digest, hashlib.sha256((self.root / "created.json").read_bytes()).hexdigest())
        restored = self.remember(vault.WalletSession.restore(self.root / "restored.json", self.backup, self.code, PASSPHRASE))
        self.assertEqual(restored.vault_digest, hashlib.sha256((self.root / "restored.json").read_bytes()).hexdigest())

    def test_receipt_replay_to_new_vault_with_same_keys_is_rejected(self):
        receipt = self.enrolled()
        restored = self.remember(vault.WalletSession.restore(self.root / "restored.json", self.backup, self.code, PASSPHRASE))
        self.assertEqual(restored.public_keys(), self.session.public_keys())
        self.assertNotEqual(restored.vault_digest, self.session.vault_digest)
        self.assertFalse(restored.accept_verification_receipt(receipt))
        own = restored.create_verification_receipt(self.backup, self.code)
        self.assertTrue(restored.accept_verification_receipt(own))
        self.assertFalse(self.session.accept_verification_receipt(own))

    def test_exact_vault_copy_keeps_its_authenticated_identity(self):
        receipt = self.enrolled()
        copied = self.root / "copied.json"
        copied.write_bytes(self.encrypted)
        copied.chmod(0o600)
        session = self.remember(vault.WalletSession(copied))
        session.unlock(PASSPHRASE)
        self.assertEqual(session.vault_digest, self.session.vault_digest)
        self.assertTrue(session.accept_verification_receipt(receipt))

    def test_other_wallet_cannot_accept_receipt_even_with_public_fields_rebound(self):
        receipt = json.loads(self.enrolled())
        other = self.remember(vault.WalletSession.restore(self.root / "other.json", self.other_backup, self.other_code, PASSPHRASE))
        receipt["vault_sha256"] = other.vault_digest
        receipt["wallet_commitment"] = other.public_keys()["key_commitment"]
        self.assertFalse(other.accept_verification_receipt(vault.recovery._canonical(receipt)))

    def test_receipt_rejects_tampering_every_bound_field(self):
        original = json.loads(self.enrolled())
        edits = {
            "format": "different", "version": 2, "network_id": "regtest",
            "genesis_hash": "00" * 32, "policy": "different-policy", "vault_sha256": "00" * 32,
            "wallet_commitment": "00" * 32, "backup_sha256": "00" * 32,
            "verified_at": original["verified_at"] + 1, "hmac_sha256": "00" * 32,
        }
        for field, value in edits.items():
            with self.subTest(field=field):
                altered = {**original, field: value}
                self.assertFalse(self.session.accept_verification_receipt(vault.recovery._canonical(altered)))

    def test_receipt_is_bounded_strict_and_never_echoes_secrets(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            receipt = self.enrolled()
            for value in (b"", b"[]", b"null", b"\xff", b"x" * (store.MAX_RECEIPT_BYTES + 1),
                          b'{"version":1,"version":1}', "not bytes", None):
                self.assertFalse(self.session.accept_verification_receipt(value))
            fields = json.loads(receipt)
            for field, value in (("version", True), ("verified_at", True), ("verified_at", -1),
                                 ("verified_at", 2**54), ("master_seed", "forbidden")):
                self.assertFalse(self.session.accept_verification_receipt(vault.recovery._canonical({**fields, field: value})))
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        for secret in (self.wallet["master_seed"], PASSPHRASE, self.code, self.backup.decode()):
            self.assertNotIn(secret.encode(), receipt)
        self.assertEqual(set(json.loads(receipt)), store.RECEIPT_FIELDS)

    def test_store_missing_is_read_only_and_safe_modes_are_exact(self):
        digest = hashlib.sha256(self.encrypted).hexdigest()
        self.assertIsNone(store.load_receipt(self.directory, digest))
        self.assertFalse(self.directory.exists())
        receipt = self.enrolled()
        store.save_receipt(self.directory, digest, receipt)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        path = self.directory / (digest + ".json")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(store.load_receipt(self.directory, digest), receipt)
        self.assertIsNone(store.load_receipt(self.directory, "ff" * 32))

    def test_store_rejects_malformed_payload_or_filename_binding(self):
        receipt = self.enrolled()
        digest = self.session.vault_digest
        for invalid in (b"{}", b"x" * (store.MAX_RECEIPT_BYTES + 1)):
            with self.assertRaises(store.VerificationError):
                store.save_receipt(self.directory, digest, invalid)
        with self.assertRaises(store.VerificationError):
            store.save_receipt(self.directory, "ff" * 32, receipt)
        self.assertFalse(self.directory.exists())
        store.save_receipt(self.directory, digest, receipt)
        path = self.directory / (digest + ".json")
        path.write_text("corrupt")
        with self.assertRaises(store.VerificationError):
            store.load_receipt(self.directory, digest)
        # A newly authenticated receipt can replace corrupt bytes in a safe inode.
        store.save_receipt(self.directory, digest, receipt)
        self.assertEqual(store.load_receipt(self.directory, digest), receipt)

    def test_store_does_not_claim_a_structurally_valid_receipt_is_authentic(self):
        receipt = json.loads(self.enrolled())
        receipt["hmac_sha256"] = "ff" * 32
        forged = vault.recovery._canonical(receipt)
        store.save_receipt(self.directory, self.session.vault_digest, forged)
        saved = store.load_receipt(self.directory, self.session.vault_digest)
        self.assertFalse(self.session.accept_verification_receipt(saved))

    def test_store_rejects_unsafe_files_and_directories_without_repair(self):
        receipt = self.enrolled()
        digest = self.session.vault_digest
        store.save_receipt(self.directory, digest, receipt)
        path = self.directory / (digest + ".json")
        for mode in (0o644, 0o400, 0o660):
            path.chmod(mode)
            for action in (lambda: store.load_receipt(self.directory, digest),
                           lambda: store.save_receipt(self.directory, digest, receipt)):
                with self.assertRaises(store.VerificationError):
                    action()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        path.chmod(0o600)
        self.directory.chmod(0o755)
        with self.assertRaises(store.VerificationError):
            store.load_receipt(self.directory, digest)
        with self.assertRaises(store.VerificationError):
            store.save_receipt(self.directory, digest, receipt)

    def test_store_rejects_file_directory_parent_symlinks_and_hardlinks(self):
        receipt = self.enrolled()
        digest = self.session.vault_digest
        store.save_receipt(self.directory, digest, receipt)
        path = self.directory / (digest + ".json")
        link = self.root / "linked"
        os.link(path, link)
        with self.assertRaises(store.VerificationError):
            store.load_receipt(self.directory, digest)
        link.unlink()
        path.unlink()
        link.write_bytes(receipt)
        link.chmod(0o600)
        path.symlink_to(link)
        with self.assertRaises(store.VerificationError):
            store.load_receipt(self.directory, digest)
        with self.assertRaises(store.VerificationError):
            store.save_receipt(self.directory, digest, receipt)
        alias = self.root / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(store.VerificationError):
            store.load_receipt(alias, digest)
        root_alias = self.root / "root-alias"
        root_alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(store.VerificationError):
            store.save_receipt(root_alias / "new", digest, receipt)

    def test_atomic_replacement_failure_preserves_previous_complete_receipt(self):
        receipt = self.enrolled()
        digest = self.session.vault_digest
        store.save_receipt(self.directory, digest, receipt)
        replacement = self.session.create_verification_receipt(self.backup, self.code)
        with mock.patch.object(store.os, "replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(store.VerificationError):
                store.save_receipt(self.directory, digest, replacement)
        self.assertEqual(store.load_receipt(self.directory, digest), receipt)
        self.assertEqual(list(self.directory.iterdir()), [self.directory / (digest + ".json")])

    def test_failed_file_sync_never_publishes_a_new_receipt(self):
        receipt = self.enrolled()
        self.directory.mkdir(mode=0o700)
        with mock.patch.object(store.os, "fsync", side_effect=OSError("synthetic sync failure")):
            with self.assertRaises(store.VerificationError):
                store.save_receipt(self.directory, self.session.vault_digest, receipt)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_failed_parent_sync_after_publication_leaves_only_complete_authentic_receipt(self):
        receipt = self.enrolled()
        self.directory.mkdir(mode=0o700)
        original = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory sync failure")
            return original(fd)

        with mock.patch.object(store.os, "fsync", side_effect=fsync):
            with self.assertRaises(store.VerificationError):
                store.save_receipt(self.directory, self.session.vault_digest, receipt)
        saved = store.load_receipt(self.directory, self.session.vault_digest)
        self.assertEqual(saved, receipt)
        self.assertTrue(self.session.accept_verification_receipt(saved))


if __name__ == "__main__":
    unittest.main()
