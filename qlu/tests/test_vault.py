"""Encrypted wallet storage and session boundaries, with disposable fixtures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import weakref

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qlu import vault


PASSPHRASE = "quiet river lanterns beyond midnight"


class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wallet = vault.recovery.generate_wallet(vault.protocol.NETWORK, vault.protocol.GENESIS)
        cls.encrypted = vault._encrypt(cls.wallet, PASSPHRASE.encode())  # Real Argon2id.
        cls.portable, cls.code = vault.recovery.make_backup(cls.wallet)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "wallet.qlu"
        self.path.write_bytes(self.encrypted)
        self.path.chmod(0o600)
        self.session = vault.WalletSession(self.path)
        self.extra_sessions = []

    def tearDown(self):
        self.session.lock()
        for session in self.extra_sessions:
            session.lock()
        self.temporary.cleanup()

    def unlocked(self):
        self.session.unlock(PASSPHRASE)
        return self.session

    def keep(self, session):
        self.extra_sessions.append(session)
        return session

    def rewrite(self, envelope):
        self.path.write_bytes(vault.recovery._canonical(envelope))

    def test_create_encrypts_only_and_emits_no_secrets(self):
        target = self.root / "created.qlu"
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(vault.recovery, "generate_wallet", return_value=self.wallet), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            created = self.keep(vault.WalletSession.create(target, PASSPHRASE))
            keys = created.public_keys()
        self.assertFalse(created.locked)
        self.assertEqual(keys, vault.protocol.keytool(self.wallet))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual({p.name for p in self.root.iterdir()}, {"wallet.qlu", "created.qlu"})
        for secret in (self.wallet["master_seed"], PASSPHRASE):
            self.assertNotIn(secret.encode(), target.read_bytes())
            self.assertNotIn(secret, repr(created) + stdout.getvalue() + stderr.getvalue())
        self.assertNotIn(b"master_seed", target.read_bytes())
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")

    def test_real_kdf_configuration_and_no_password_normalization(self):
        salt = bytes(range(16))
        with patch.object(vault, "Argon2id", wraps=vault.Argon2id) as constructor:
            key = vault._derive(PASSPHRASE.encode(), salt)
        self.assertEqual(len(key), 32)
        constructor.assert_called_once_with(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
        phrase = "  cafe\u0301 beside the river  "
        target = self.root / "unicode.qlu"
        created = self.keep(vault.WalletSession.create(target, phrase))
        for changed in (phrase.strip(), phrase.replace("e\u0301", "é")):
            with self.assertRaises(vault.VaultError):
                created.unlock(changed)
            self.assertTrue(created.locked)
        created.unlock(phrase)
        self.assertFalse(created.locked)

    def test_native_kdf_construction_waits_for_an_active_derivation(self):
        # CLI tooling uses the direct name; package clients use qlu.vault.
        import vault as direct_vault
        entered, release, second_started, second_entered = (threading.Event() for _ in range(4))
        calls = []

        class ControlledKDF:
            def __init__(self, **kwargs):
                calls.append(kwargs)
                self.first = len(calls) == 1
                if not self.first:
                    second_entered.set()

            def derive(self, phrase):
                if self.first:
                    entered.set()
                    if not release.wait(3):
                        raise RuntimeError("KDF test release timed out")
                return phrase.ljust(32, b"\x00")

        def second_derivation():
            second_started.set()
            return direct_vault._derive(b"second", b"b" * 16)

        with patch.object(vault, "Argon2id", ControlledKDF), \
                patch.object(direct_vault, "Argon2id", ControlledKDF), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(vault._derive, b"first", b"a" * 16)
            try:
                self.assertTrue(entered.wait(2))
                second = pool.submit(second_derivation)
                self.assertTrue(second_started.wait(2))
                self.assertFalse(second_entered.wait(0.2), "Overlapping native KDF entry")
            finally:
                release.set()
            self.assertEqual(first.result(timeout=2), b"first".ljust(32, b"\x00"))
            self.assertEqual(second.result(timeout=2), b"second".ljust(32, b"\x00"))
        self.assertTrue(second_entered.is_set())
        self.assertEqual(calls, [
            dict(salt=b"a" * 16, length=32, iterations=3, lanes=4, memory_cost=65536),
            dict(salt=b"b" * 16, length=32, iterations=3, lanes=4, memory_cost=65536),
        ])

    def test_native_kdf_failure_does_not_block_a_later_wallet_operation(self):
        for fail_during in ("construction", "derivation"):
            class FailingKDF:
                def __init__(self, **kwargs):
                    if fail_during == "construction":
                        raise UnsupportedAlgorithm("synthetic unavailable KDF")

                def derive(self, phrase):
                    raise UnsupportedAlgorithm("synthetic unavailable KDF")

            with self.subTest(fail_during=fail_during), patch.object(vault, "Argon2id", FailingKDF):
                with self.assertRaises(UnsupportedAlgorithm):
                    vault._derive(b"first", b"a" * 16)
            # Bound the failed-release regression itself; an executor would
            # otherwise wait forever for a worker stuck on the held gate.
            acquired = vault.ARGON2_LOCK.acquire(timeout=1)
            self.assertTrue(acquired, "Failed native KDF retained the shared gate")
            vault.ARGON2_LOCK.release()
            key = vault._derive(b"second", b"b" * 16)
            self.assertEqual(len(key), 32)

    def test_constructor_and_explicit_lock_gate_all_operations(self):
        operations = (self.session.public_keys, self.session.address, self.session.backup,
                      lambda: self.session.sign(None, None),
                      lambda: self.session.verify_backup(self.portable, self.code))
        for method in operations:
            with self.assertRaisesRegex(vault.VaultError, "locked"):
                method()
        self.unlocked().lock()
        with patch.object(vault.protocol, "keytool") as keytool:
            with self.assertRaisesRegex(vault.VaultError, "locked"):
                self.session.address()
            keytool.assert_not_called()

    def test_wrong_passphrase_relocks_an_unlocked_session(self):
        self.unlocked()
        wrong = "incorrect password sufficiently long"
        with self.assertRaises(vault.VaultError) as error:
            self.session.unlock(wrong)
        self.assertTrue(self.session.locked)
        self.assertEqual(str(error.exception), "Vault unlock failed")
        self.assertNotIn(wrong, str(error.exception))
        self.session.unlock(PASSPHRASE)
        self.assertFalse(self.session.locked)

    def test_selected_blob_mismatch_locks_before_decryption(self):
        self.unlocked()
        with patch.object(vault, "_decrypt") as decrypt:
            with self.assertRaises(vault.VaultChangedError) as error:
                self.session.unlock(PASSPHRASE, expected_digest="00" * 32)
            decrypt.assert_not_called()
        self.assertTrue(self.session.locked)
        self.assertIsNone(self.session.vault_digest)
        self.assertNotIn(PASSPHRASE, str(error.exception))

    def test_selected_digest_is_not_authentication(self):
        digest = hashlib.sha256(self.encrypted).hexdigest()
        with self.assertRaises(vault.VaultError):
            self.session.unlock("wrong password sufficiently long", expected_digest=digest)
        self.assertTrue(self.session.locked)
        self.session.unlock(PASSPHRASE, expected_digest=digest)
        self.assertEqual(self.session.vault_digest, digest)
        self.assertEqual(self.session.public_keys(), vault.protocol.keytool(self.wallet))

    def test_invalid_selection_pins_fail_before_read_or_decrypt(self):
        for value in (False, 1, [], {}, "", "00" * 31, "AB" * 32, "x" * 64):
            with self.subTest(kind=type(value).__name__), \
                    patch.object(vault.recovery, "read_private") as read, \
                    patch.object(vault, "_decrypt") as decrypt:
                with self.assertRaises(vault.VaultError):
                    self.session.unlock(PASSPHRASE, expected_digest=value)
                read.assert_not_called()
                decrypt.assert_not_called()
                self.assertTrue(self.session.locked)

    def test_path_replacement_during_decryption_cannot_substitute_authenticated_identity(self):
        original = vault._decrypt
        replacement_wallet = vault.recovery.generate_wallet(vault.protocol.NETWORK, vault.protocol.GENESIS)
        replacement = vault._encrypt(replacement_wallet, PASSPHRASE.encode())
        digest = hashlib.sha256(self.encrypted).hexdigest()
        def replace_after_authentication(blob, phrase):
            result = original(blob, phrase)
            self.path.write_bytes(replacement)
            return result
        with patch.object(vault, "_decrypt", side_effect=replace_after_authentication):
            self.session.unlock(PASSPHRASE, expected_digest=digest)
        self.assertEqual(self.session.vault_digest, digest)
        self.assertEqual(self.session.public_keys(), vault.protocol.keytool(self.wallet))
        self.assertNotEqual(self.session.public_keys(), vault.protocol.keytool(replacement_wallet))
        self.session.lock()
        with self.assertRaises(vault.VaultChangedError):
            self.session.unlock(PASSPHRASE, expected_digest=digest)

    def test_identical_private_copy_keeps_content_selection(self):
        digest = hashlib.sha256(self.encrypted).hexdigest()
        replacement = self.root / "copy.qlu"
        replacement.write_bytes(self.encrypted)
        replacement.chmod(0o600)
        os.replace(replacement, self.path)
        self.session.unlock(PASSPHRASE, expected_digest=digest)
        self.assertEqual(self.session.vault_digest, digest)

    def test_passphrase_policy_rejects_before_kdf_and_creates_no_file(self):
        values = ("short", "x" * 1025, "é" * 513, "QLU1-" + "a" * 40,
                  "  qlu1-" + "a" * 40, "bad surrogate \ud800 plus chars", b"not a unicode password")
        with patch.object(vault, "_derive") as derive:
            for value in values:
                with self.subTest(kind=type(value).__name__), self.assertRaises(vault.VaultError):
                    vault.WalletSession.create(self.root / "invalid.qlu", value)
            derive.assert_not_called()
        self.assertFalse((self.root / "invalid.qlu").exists())

    def test_hostile_envelope_is_rejected_before_kdf(self):
        original = json.loads(self.encrypted)
        edits = [("version", True), ("version", 2), ("cipher", "AES-128-GCM"),
                 ("network_id", "main"), ("genesis_hash", "00" * 32),
                 ("policy", "classical-only"), ("nonce", "bad"), ("salt", "bad"),
                 ("ciphertext", "bad"), ("extra", "unrecognized"), ("kdf", [])]
        for field, value in edits:
            altered = copy.deepcopy(original); altered[field] = value
            self.rewrite(altered)
            with self.subTest(field=field), patch.object(vault, "_derive") as derive:
                with self.assertRaises(vault.VaultError):
                    self.session.unlock(PASSPHRASE)
                derive.assert_not_called()
        for field in vault.KDF:
            altered = copy.deepcopy(original)
            altered["kdf"][field] = "fallback" if field == "name" else 2**60
            self.rewrite(altered)
            with self.subTest(kdf=field), patch.object(vault, "_derive") as derive:
                with self.assertRaises(vault.VaultError):
                    self.session.unlock(PASSPHRASE)
                derive.assert_not_called()
        for altered in ([], {**original, "kdf": {**original["kdf"], "unknown": 1}}):
            self.rewrite(altered)
            with patch.object(vault, "_derive") as derive, self.assertRaises(vault.VaultError):
                self.session.unlock(PASSPHRASE)
            derive.assert_not_called()

    def test_oversized_and_duplicate_envelopes_fail_before_kdf(self):
        for blob in (b"x" * (vault.MAX_VAULT_BYTES + 1), b'{"version":1,"version":1}'):
            self.path.write_bytes(blob)
            with patch.object(vault, "_derive") as derive, self.assertRaises(vault.VaultError):
                self.session.unlock(PASSPHRASE)
            derive.assert_not_called()

    def test_ciphertext_and_well_formed_aad_changes_fail_authentication(self):
        original = json.loads(self.encrypted)
        for field in ("ciphertext", "nonce", "salt"):
            altered = copy.deepcopy(original)
            payload = bytearray(vault.recovery._unb64(altered[field], minimum=1, maximum=4096))
            payload[0] ^= 1
            altered[field] = vault.recovery._b64(bytes(payload))
            self.rewrite(altered)
            with self.subTest(field=field), self.assertRaises(vault.VaultError):
                self.session.unlock(PASSPHRASE)
            self.assertTrue(self.session.locked)

    def test_authenticated_wrong_inner_network_is_rejected(self):
        envelope = json.loads(self.encrypted)
        header = {key: envelope[key] for key in vault.HEADER_FIELDS}
        salt = vault.recovery._unb64(header["salt"], minimum=16, maximum=16)
        nonce = vault.recovery._unb64(header["nonce"], minimum=12, maximum=12)
        altered = copy.deepcopy(self.wallet); altered["network_id"] = "other"
        ciphertext = AESGCM(vault._derive(PASSPHRASE.encode(), salt)).encrypt(
            nonce, vault.recovery._canonical(altered), vault.AAD_DOMAIN + vault.recovery._canonical(header))
        self.rewrite({**header, "ciphertext": vault.recovery._b64(ciphertext)})
        with self.assertRaises(vault.VaultError):
            self.session.unlock(PASSPHRASE)

    def test_unsupported_argon_provider_fails_closed(self):
        with patch.object(vault, "Argon2id", side_effect=UnsupportedAlgorithm("provider details must stay private")):
            with self.assertRaises(vault.VaultError) as error:
                self.session.unlock(PASSPHRASE)
            self.assertTrue(self.session.locked)
            with self.assertRaises(vault.VaultError):
                vault.WalletSession.create(self.root / "unsupported.qlu", PASSPHRASE)
        self.assertNotIn("provider", str(error.exception))
        self.assertFalse((self.root / "unsupported.qlu").exists())

    def test_restore_preserves_authority_and_keeps_only_encrypted_files(self):
        restored = self.keep(vault.WalletSession.restore(self.root / "restored.qlu", self.portable, self.code, PASSPHRASE))
        self.assertEqual(restored.public_keys(), vault.protocol.keytool(self.wallet))
        self.assertTrue(restored.verify_backup(self.portable, self.code))
        for path in self.root.iterdir():
            self.assertNotIn(self.wallet["master_seed"].encode(), path.read_bytes())
            self.assertNotIn(self.code.encode(), path.read_bytes())
        restored.lock(); restored.unlock(PASSPHRASE)
        self.assertTrue(restored.verify_backup(self.portable, self.code))

    def test_backup_verification_rejects_wrong_code_tamper_or_other_wallet(self):
        session = self.unlocked()
        backup, code = session.backup()
        self.assertTrue(session.verify_backup(backup, code))
        other = vault.recovery.generate_wallet(vault.protocol.NETWORK, vault.protocol.GENESIS)
        foreign, foreign_code = vault.recovery.make_backup(other)
        for blob, provided_code in ((backup, vault.recovery.generate_recovery_code()),
                                    (backup[:-1] + b"x", code), (foreign, foreign_code)):
            with self.assertRaises(vault.VaultError):
                session.verify_backup(blob, provided_code)
        with self.assertRaises(vault.VaultError):
            vault.WalletSession.restore(self.root / "invalid-restore.qlu", backup, foreign_code, PASSPHRASE)
        self.assertFalse((self.root / "invalid-restore.qlu").exists())

    def test_public_output_detached_and_unexpected_secret_field_rejected(self):
        session = self.unlocked()
        keys = session.public_keys()
        keys["key_commitment"] = "00" * 32
        self.assertNotEqual(keys, session.public_keys())
        self.assertTrue(session.address().startswith("qlud1"))
        malicious = {**session.public_keys(), "master_seed": self.wallet["master_seed"]}
        with patch.object(vault.protocol, "keytool", return_value=malicious), self.assertRaises(vault.VaultError):
            session.public_keys()

    def test_sign_uses_hybrid_wallet_and_preserves_unsigned_transaction(self):
        from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
        session = self.unlocked()
        script = vault.protocol.script_for(session.public_keys())
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(123, 0), nSequence=0xffffffff)]
        tx.vout = [CTxOut(99900000, script)]
        signed = session.sign(tx, [CTxOut(100000000, script)])
        self.assertTrue(tx.wit.is_null())
        self.assertEqual(signed.serialize_without_witness(), tx.serialize_without_witness())
        self.assertEqual([len(item) for item in signed.wit.vtxinwit[0].scriptWitness.stack], [1952, 32, 3309, 64])
        session.lock()
        with patch.object(vault.protocol, "sign_transaction") as signer, self.assertRaises(vault.VaultError):
            session.sign(tx, [CTxOut(100000000, script)])
        signer.assert_not_called()

    def test_real_idle_timer_releases_authority_without_property_access(self):
        session = self.keep(vault.WalletSession(self.path, idle_seconds=0.05))
        session.unlock(PASSPHRASE)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with session._mutex:
                if session._wallet is None:
                    break
            time.sleep(0.01)
        with session._mutex:
            self.assertIsNone(session._wallet)  # Property cannot drive this result.
        self.assertTrue(session.locked)

    def test_monotonic_gate_does_not_depend_on_timer_callback(self):
        session = self.unlocked()
        with patch.object(vault.time, "monotonic", return_value=session._deadline + 1), \
                patch.object(vault.protocol, "keytool") as keytool:
            with self.assertRaisesRegex(vault.VaultError, "locked"):
                session.public_keys()
            keytool.assert_not_called()
        self.assertTrue(session.locked)

    def test_stale_timer_cannot_lock_new_unlock(self):
        session = self.unlocked()
        stale = session._generation
        session.lock(); session.unlock(PASSPHRASE)
        vault._expire(weakref.ref(session), stale)
        self.assertFalse(session.locked)

    def test_lock_waits_for_inflight_operation_then_blocks_future_signing(self):
        session = self.unlocked()
        entered, finish, locked = threading.Event(), threading.Event(), threading.Event()
        def signing(wallet, tx, spent):
            entered.set()
            if not finish.wait(3):
                raise RuntimeError("test synchronization failed")
            return "public signature fixture"
        def locking():
            session.lock(); locked.set()
        with patch.object(vault.protocol, "sign_transaction", side_effect=signing):
            with ThreadPoolExecutor(max_workers=2) as pool:
                pending = pool.submit(session.sign, None, None)
                self.assertTrue(entered.wait(2))
                lock_job = pool.submit(locking)
                self.assertFalse(locked.wait(0.03))
                finish.set()
                self.assertEqual(pending.result(timeout=2), "public signature fixture")
                lock_job.result(timeout=2)
        self.assertTrue(session.locked)

    def test_links_fifo_and_broad_permissions_are_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(vault.VaultError):
            self.session.unlock(PASSPHRASE)
        self.path.chmod(0o600)
        os.link(self.path, self.root / "hardlink")
        with self.assertRaises(vault.VaultError):
            self.session.unlock(PASSPHRASE)
        (self.root / "hardlink").unlink()
        symlink = self.root / "symlink"; symlink.symlink_to(self.path)
        fifo = self.root / "fifo"; os.mkfifo(fifo, 0o600)
        for path in (symlink, fifo):
            with self.assertRaises(vault.VaultError):
                vault.WalletSession(path).unlock(PASSPHRASE)

    def test_unsafe_parent_and_parent_symlink_refused(self):
        directory = self.root / "unsafe"; directory.mkdir(); directory.chmod(0o777)
        symlink = self.root / "alias"; symlink.symlink_to(self.root, target_is_directory=True)
        for path in (directory / "vault", symlink / "vault"):
            with self.assertRaises(vault.VaultError):
                vault.WalletSession.create(path, PASSPHRASE)
        self.assertFalse((directory / "vault").exists())
        self.assertFalse((self.root / "vault").exists())

    def test_existing_destination_and_symlink_never_overwritten(self):
        alias = self.root / "alias"; alias.symlink_to(self.path)
        for path in (self.path, alias):
            with self.assertRaises(vault.VaultError):
                vault.WalletSession.create(path, PASSPHRASE)
        self.assertEqual(self.path.read_bytes(), self.encrypted)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(list(self.root.glob(".qlu-vault-*.tmp")), [])

    def test_concurrent_creation_has_exactly_one_winner(self):
        target = self.root / "concurrent.qlu"
        barrier = threading.Barrier(2)
        original = vault._publish
        def synchronized(path, blob):
            barrier.wait(timeout=4)
            return original(path, blob)
        def create():
            try:
                return vault.WalletSession.create(target, PASSPHRASE)
            except vault.VaultError:
                return None
        with patch.object(vault, "_publish", side_effect=synchronized), ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: create(), range(2)))
        winners = [self.keep(item) for item in results if item is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(list(self.root.glob(".qlu-vault-*.tmp")), [])
        reader = self.keep(vault.WalletSession(target)); reader.unlock(PASSPHRASE)
        self.assertEqual(reader.public_keys(), winners[0].public_keys())

    def test_interruption_before_publish_cleans_only_owned_temporary(self):
        target = self.root / "interrupted.qlu"
        sentinel = self.root / ".qlu-vault-unrelated.tmp"; sentinel.write_bytes(b"untouched")
        with patch.object(vault.os, "fsync", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                vault.WalletSession.create(target, PASSPHRASE)
        self.assertFalse(target.exists())
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        self.assertEqual(list(self.root.glob(".qlu-vault-*.tmp")), [sentinel])

    def test_directory_fsync_failure_keeps_complete_encrypted_destination(self):
        target = self.root / "fsync-failed.qlu"
        original = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("simulated directory sync failure")
            return original(fd)
        with patch.object(vault.os, "fsync", side_effect=fail_directory), self.assertRaises(vault.VaultError):
            vault.WalletSession.create(target, PASSPHRASE)
        preserved = target.read_bytes()
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(target.stat().st_nlink, 1)
        reader = self.keep(vault.WalletSession(target)); reader.unlock(PASSPHRASE)
        with self.assertRaises(vault.VaultError):
            vault.WalletSession.create(target, PASSPHRASE)
        self.assertEqual(target.read_bytes(), preserved)

    def test_interrupted_unlink_leaves_encrypted_hardlinks_and_fails_closed(self):
        target = self.root / "linked.qlu"
        with patch.object(vault.os, "unlink", side_effect=OSError("simulated interruption")):
            with self.assertRaises(vault.VaultError):
                vault.WalletSession.create(target, PASSPHRASE)
        self.assertEqual(target.stat().st_nlink, 2)
        self.assertNotIn(b"master_seed", target.read_bytes())
        with self.assertRaises(vault.VaultError):
            vault.WalletSession(target).unlock(PASSPHRASE)

    def test_temporary_replacement_is_not_published_as_success_or_deleted(self):
        target = self.root / "replaced.qlu"
        original = os.link
        replacement = b"foreign replacement must remain"
        replaced_name = []
        def replace_then_link(source, destination, **kwargs):
            directory_fd = kwargs["src_dir_fd"]
            os.unlink(source, dir_fd=directory_fd)
            fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
            try:
                os.write(fd, replacement)
            finally:
                os.close(fd)
            replaced_name.append(source)
            return original(source, destination, **kwargs)
        with patch.object(vault.os, "link", side_effect=replace_then_link), self.assertRaises(vault.VaultError):
            vault.WalletSession.create(target, PASSPHRASE)
        self.assertEqual(target.read_bytes(), replacement)
        self.assertEqual((self.root / replaced_name[0]).read_bytes(), replacement)


if __name__ == "__main__":
    unittest.main()
