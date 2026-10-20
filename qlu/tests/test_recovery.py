"""Recovery behavior and filesystem boundaries, using disposable test secrets."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qlu import recovery


NETWORK = "qlu-private-test"
GENESIS = "42" * 32


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.wallet = recovery.generate_wallet(NETWORK, GENESIS)
        self.wallet["discovery"]["scan_from_height"] = 101
        self.blob, self.code = recovery.make_backup(self.wallet)

    def restore(self, blob=None, code=None, network=NETWORK, genesis=GENESIS):
        return recovery.restore_backup(self.blob if blob is None else blob,
                                       self.code if code is None else code, network, genesis)

    def rewritten(self, **fields):
        envelope = json.loads(self.blob)
        envelope.update(fields)
        return json.dumps(envelope).encode()

    def test_complete_wallet_survives_backup_without_original_device_state(self):
        original = json.loads(json.dumps(self.wallet))
        self.wallet.clear()
        restored = self.restore()
        self.assertEqual(restored, original)
        self.assertEqual(restored["discovery"]["scan_from_height"], 101)
        self.assertEqual(restored["policy"], recovery.POLICY)
        self.assertNotIn(original["master_seed"].encode(), self.blob)

    def test_random_code_wallet_salt_nonce_and_backup_are_independent(self):
        other_wallet = recovery.generate_wallet(NETWORK, GENESIS)
        other_blob, other_code = recovery.make_backup(self.wallet)
        self.assertNotEqual(self.wallet["master_seed"], other_wallet["master_seed"])
        self.assertNotEqual(self.wallet["master_seed"], recovery._decode_code(self.code).hex())
        self.assertNotEqual(self.code, other_code)
        self.assertNotEqual(self.blob, other_blob)
        first, second = json.loads(self.blob), json.loads(other_blob)
        self.assertNotEqual(first["salt"], second["salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])

    def test_refreshed_backup_can_reuse_generated_code_with_fresh_encryption(self):
        blob, code = recovery.make_backup(self.wallet, self.code)
        self.assertEqual(code, self.code)
        self.assertNotEqual(blob, self.blob)
        self.assertEqual(self.restore(blob), self.wallet)

    def test_reused_code_is_returned_in_canonical_portable_form(self):
        blob, code = recovery.make_backup(self.wallet, "\n" + self.code.lower() + "\n")
        self.assertEqual(code, self.code)
        self.assertEqual(self.restore(blob, code), self.wallet)

    def test_independently_generated_wrong_code_fails_authentication(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "authentication"):
            self.restore(code=recovery.generate_recovery_code())

    def test_code_checksum_catches_a_transcription_error(self):
        modified = self.code[:-1] + ("A" if self.code[-1] != "A" else "B")
        with self.assertRaisesRegex(recovery.RecoveryError, "checksum"):
            self.restore(code=modified)

    def test_code_allows_case_and_outer_whitespace_but_no_password_or_pin(self):
        self.assertEqual(self.restore(code="\n" + self.code.lower() + "\n"), self.wallet)
        for code in ("1234", "a memorable password", "A" * 10000, None, b"secret"):
            with self.subTest(kind=type(code).__name__):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.restore_backup(self.blob, code, NETWORK, GENESIS)

    def test_wrong_network_and_same_name_different_genesis_rejected(self):
        for network, genesis in (("qlu-other", GENESIS), (NETWORK, "24" * 32)):
            with self.subTest(network=network):
                with self.assertRaisesRegex(recovery.RecoveryError, "different network"):
                    self.restore(network=network, genesis=genesis)

    def test_authenticated_header_cannot_be_rebound_to_another_chain(self):
        modified = self.rewritten(network_id="qlu-other", genesis_hash="24" * 32)
        with self.assertRaisesRegex(recovery.RecoveryError, "authentication"):
            self.restore(modified, network="qlu-other", genesis="24" * 32)

    def test_ciphertext_nonce_salt_and_tag_tampering_fail(self):
        envelope = json.loads(self.blob)
        for field in ("ciphertext", "nonce", "salt"):
            for position in (0, -1):
                with self.subTest(field=field, position=position):
                    raw = bytearray(base64.b64decode(envelope[field]))
                    raw[position] ^= 1
                    with self.assertRaisesRegex(recovery.RecoveryError, "authentication"):
                        self.restore(self.rewritten(**{field: base64.b64encode(raw).decode()}))

    def test_truncation_and_oversized_payloads_fail(self):
        for blob in (b"", self.blob[:1], self.blob[:-1], self.blob[:len(self.blob)//2],
                     b" " * (recovery.MAX_BACKUP_BYTES + 1), self.blob.decode()):
            with self.subTest(length=len(blob)):
                with self.assertRaises(recovery.RecoveryError):
                    self.restore(blob)

    def test_unknown_versions_policies_fields_and_unbounded_kdf_are_rejected(self):
        for patch in ({"version": 2}, {"version": True}, {"cipher": "AES-128-GCM"},
                      {"kdf": "scrypt"}, {"iterations": 2**63}, {"format": "wallet"}):
            with self.subTest(patch=patch):
                with self.assertRaises(recovery.RecoveryError):
                    self.restore(self.rewritten(**patch))

    def test_duplicate_json_fields_missing_fields_nonobjects_nan_and_deep_json_fail(self):
        envelope = json.loads(self.blob)
        del envelope["nonce"]
        invalid = [b'{"version":1,"version":2}', b"[]", b"null", b'{"x":NaN}',
                   b"\xff", b"[" * 3000 + b"]" * 3000, json.dumps(envelope).encode()]
        for blob in invalid:
            with self.subTest(length=len(blob)):
                with self.assertRaises(recovery.RecoveryError):
                    self.restore(blob)

    def test_invalid_encoded_field_lengths_and_noncanonical_base64_fail(self):
        for field, value in (("nonce", "AA=="), ("salt", "AA=="), ("ciphertext", ""),
                             ("nonce", "!" * 16), ("salt", 1234),
                             ("ciphertext", "A" * recovery.MAX_BACKUP_BYTES)):
            with self.subTest(field=field):
                with self.assertRaises(recovery.RecoveryError):
                    self.restore(self.rewritten(**{field: value}))

    def test_wallet_schema_rejects_weaker_policy_and_unsupported_derivation(self):
        for patch in ({"policy": "bip340-only"}, {"derivation_version": 2},
                      {"version": True}, {"master_seed": "00"}, {"extra": 1},
                      {"network_id": "../main"}, {"genesis_hash": "42" * 31}):
            with self.subTest(patch=patch):
                wallet = {**self.wallet, **patch}
                with self.assertRaises(recovery.RecoveryError):
                    recovery.make_backup(wallet)

    def test_single_key_discovery_rejects_unimplemented_hd_metadata(self):
        for field, value in (("scheme", "hd-v1"), ("key_index", 1), ("key_index", False),
                             ("scan_from_height", -1), ("scan_from_height", 2**31),
                             ("scan_from_height", True)):
            wallet = copy.deepcopy(self.wallet)
            wallet["discovery"][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.make_backup(wallet)

    def test_authenticated_plaintext_must_match_outer_chain_and_supported_schema(self):
        # A caller possessing the code can encrypt arbitrary data. Authentication
        # alone must not let malformed or mislabeled wallet structures through.
        envelope = json.loads(self.blob)
        header = {key: value for key, value in envelope.items() if key != "ciphertext"}
        salt = base64.b64decode(header["salt"])
        nonce = base64.b64decode(header["nonce"])
        key = recovery._key(recovery._decode_code(self.code), salt)
        for patch in ({"network_id": "qlu-other"}, {"genesis_hash": "24" * 32},
                      {"policy": "bip340-only"}):
            payload = recovery._canonical({**self.wallet, **patch})
            ciphertext = AESGCM(key).encrypt(nonce, payload, recovery.AAD_DOMAIN + recovery._canonical(header))
            with self.subTest(patch=patch):
                with self.assertRaises(recovery.RecoveryError):
                    self.restore(self.rewritten(ciphertext=base64.b64encode(ciphertext).decode()))


class PrivateFileTests(unittest.TestCase):
    def setUp(self):
        ignored = Path(__file__).resolve().parents[2] / ".local"
        self.temp = tempfile.TemporaryDirectory(prefix="recovery-tests-", dir=ignored)
        self.directory = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_private_file_mode_and_exclusive_creation(self):
        path = self.directory / "private"
        recovery.write_private(path, b"original")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(recovery.read_private(path), b"original")
        with self.assertRaises(FileExistsError):
            recovery.write_private(path, b"replacement")
        self.assertEqual(path.read_bytes(), b"original")

    def test_wallet_restore_to_fresh_file_after_original_file_is_removed(self):
        wallet = recovery.generate_wallet(NETWORK, GENESIS)
        original = self.directory / "original.wallet"
        recovery.save_wallet(original, wallet)
        blob, code = recovery.make_backup(recovery.load_wallet(original))
        original.unlink()
        restored = recovery.restore_backup(blob, code, NETWORK, GENESIS)
        destination = self.directory / "restored.wallet"
        recovery.save_wallet(destination, restored)
        self.assertEqual(recovery.load_wallet(destination), wallet)
        self.assertFalse(original.exists())

    def test_symlink_file_and_directory_components_refused(self):
        target = self.directory / "target"
        recovery.write_private(target, b"untouched")
        link = self.directory / "link"
        link.symlink_to(target)
        for operation in (lambda: recovery.read_private(link), lambda: recovery.write_private(link, b"no")):
            with self.assertRaises(OSError):
                operation()
        realdir = self.directory / "real"
        realdir.mkdir(mode=0o700)
        dirlink = self.directory / "dirlink"
        dirlink.symlink_to(realdir, target_is_directory=True)
        with self.assertRaises(OSError):
            recovery.write_private(dirlink / "new", b"no")
        self.assertEqual(target.read_bytes(), b"untouched")
        self.assertFalse((realdir / "new").exists())

    def test_hardlinks_are_refused_for_read_and_never_overwritten(self):
        target = self.directory / "target"
        recovery.write_private(target, b"original")
        linked = self.directory / "hardlink"
        os.link(target, linked)
        with self.assertRaises(recovery.RecoveryError):
            recovery.read_private(linked)
        with self.assertRaises(FileExistsError):
            recovery.write_private(linked, b"no")
        self.assertEqual(target.read_bytes(), b"original")

    def test_world_readable_secret_is_refused(self):
        path = self.directory / "private"
        recovery.write_private(path, b"secret")
        path.chmod(0o644)
        with self.assertRaises(recovery.RecoveryError):
            recovery.read_private(path)

    def test_other_writable_parent_is_refused(self):
        unsafe = self.directory / "unsafe"
        unsafe.mkdir(mode=0o700)
        unsafe.chmod(0o777)
        with self.assertRaises(recovery.RecoveryError):
            recovery.write_private(unsafe / "secret", b"no")

    def test_parent_traversal_is_rejected_before_normalizing_paths(self):
        link = self.directory / "link"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(recovery.RecoveryError):
            recovery.write_private(link / ".." / "ambiguous", b"no")
        self.assertFalse((self.directory / "ambiguous").exists())

    def test_fifo_directory_empty_and_oversized_files_are_refused(self):
        fifo = self.directory / "fifo"
        os.mkfifo(fifo, 0o600)
        directory = self.directory / "directory"
        directory.mkdir(mode=0o700)
        empty = self.directory / "empty"
        empty.touch(mode=0o600)
        large = self.directory / "large"
        large.write_bytes(b"x" * (recovery.MAX_BACKUP_BYTES + 1))
        large.chmod(0o600)
        for path in (fifo, directory, empty, large):
            with self.subTest(name=path.name):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.read_private(path)

    def test_cli_creates_backs_up_and_restores_without_printing_secrets(self):
        outputs = io.StringIO()
        original, restored = self.directory / "original", self.directory / "restored"
        code_dir, backup_dir = self.directory / "offline", self.directory / "backup"
        code_dir.mkdir(mode=0o700)
        backup_dir.mkdir(mode=0o700)
        code_path, backup_path = code_dir / "code", backup_dir / "backup"
        with redirect_stdout(outputs), redirect_stderr(outputs):
            self.assertEqual(recovery.main(["create", "--network", NETWORK, "--genesis", GENESIS,
                                            "--wallet", str(original)]), 0)
            wallet = recovery.load_wallet(original)
            self.assertEqual(recovery.main(["backup", "--wallet", str(original), "--backup", str(backup_path),
                                            "--code-file", str(code_path)]), 0)
            original.unlink()
            self.assertEqual(recovery.main(["restore", "--network", NETWORK, "--genesis", GENESIS,
                                            "--backup", str(backup_path), "--code-file", str(code_path),
                                            "--wallet", str(restored)]), 0)
        self.assertEqual(recovery.load_wallet(restored), wallet)
        self.assertNotIn(wallet["master_seed"], outputs.getvalue())
        self.assertNotIn(code_path.read_text().strip(), outputs.getvalue())

    def test_cli_refuses_backup_and_code_in_same_directory(self):
        original = self.directory / "original"
        recovery.save_wallet(original, recovery.generate_wallet(NETWORK, GENESIS))
        with redirect_stderr(io.StringIO()):
            self.assertEqual(recovery.main(["backup", "--wallet", str(original),
                                            "--backup", str(self.directory / "backup"),
                                            "--code-file", str(self.directory / "code")]), 1)
        self.assertFalse((self.directory / "backup").exists())
        self.assertFalse((self.directory / "code").exists())


if __name__ == "__main__":
    unittest.main()
