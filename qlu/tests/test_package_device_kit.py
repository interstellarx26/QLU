"""Source-kit integrity and import-shadowing boundaries, using tiny fake files."""
import hashlib
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qlu import package_device_kit as kit


class SourceKitTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        self.temp = tempfile.TemporaryDirectory(prefix="kit-verifier-test-", dir=root / ".local")
        self.root = Path(self.temp.name).resolve()
        self.files = {name: b"public source fixture\n" for name in kit.SOURCE_FILES}
        self.files.update({"NOTICE": b"license fixture\n", "transfer/backup.json": b'{"format":"qlu-backup"}',
                           "transfer/challenge.json": kit._canonical({"challenge_id": "12" * 16})})
        for name, blob in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
        self.manifest = {"format": "qlu-recovery-source-kit", "version": 1, "session_id": "12" * 16,
                         "files": {name: {"sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob)}
                                   for name, blob in self.files.items()},
                         "backup_sha256": hashlib.sha256(self.files["transfer/backup.json"]).hexdigest(),
                         "challenge_sha256": hashlib.sha256(self.files["transfer/challenge.json"]).hexdigest()}
        self.save_manifest()

    def tearDown(self):
        self.temp.cleanup()

    def save_manifest(self):
        (self.root / "KIT-MANIFEST.json").write_bytes(kit._canonical(self.manifest))

    def set_file(self, name, blob):
        self.files[name] = blob
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        self.manifest["files"][name] = {"sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob)}

    def wallet_profile(self):
        self.manifest.update(profile=kit.WALLET_PROFILE, purpose="physical-device", network_id="qludev", genesis_hash="42" * 32)
        challenge = {"challenge_id": self.manifest["session_id"], "network_id": "qludev",
                     "genesis_hash": self.manifest["genesis_hash"], "wallet_commitment": "34" * 32}
        self.set_file("transfer/challenge.json", kit._canonical(challenge))
        self.manifest["challenge_sha256"] = hashlib.sha256(self.files["transfer/challenge.json"]).hexdigest()
        for name in kit.WALLET_SOURCE_FILES:
            self.set_file(name, b"encrypted-wallet public source fixture\n")
        origin = {"format": "qlu-wallet-device-origin", "version": 1,
                  **{key: self.manifest[key] for key in ("session_id", "purpose", "network_id", "genesis_hash", "challenge_sha256", "backup_sha256")},
                  "wallet_commitment": challenge["wallet_commitment"],
                  "tooling": {name: hashlib.sha256(self.files[path]).hexdigest() for name, path in kit.WALLET_SCRIPT_HASHES.items()},
                  "origin_vault_sha256": "56" * 32,
                  "origin_checks": {"encrypted_reopen_same_identity": True, "portable_backup_verified": True},
                  "created_at": "2026-10-20T12:00:00+00:00"}
        self.save_origin(origin)
        return origin, challenge

    def save_origin(self, origin):
        blob = kit._canonical(origin)
        self.set_file("transfer/wallet-origin.json", blob)
        self.manifest["wallet_origin_sha256"] = hashlib.sha256(blob).hexdigest()
        self.save_manifest()

    def test_pristine_expected_sources_verify(self):
        result = kit.verify(self.root)
        self.assertTrue(result["verified"])
        self.assertEqual(result["files"], len(self.files))

    def test_unlisted_import_shadowing_and_bytecode_refused(self):
        for name in ("qlu/getpass.py", "qlu/__pycache__/recovery.cpython-313.pyc", "build/unlisted"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"unreviewed")
            with self.subTest(name=name), self.assertRaisesRegex(kit.KitError, "pristine"):
                kit.verify(self.root)
            path.unlink()

    def test_tampered_or_missing_source_refused(self):
        path = self.root / "qlu/protocol.py"
        path.write_bytes(b"different source")
        with self.assertRaisesRegex(kit.KitError, "fingerprint"):
            kit.verify(self.root)
        path.unlink()
        with self.assertRaisesRegex(kit.KitError, "pristine"):
            kit.verify(self.root)

    def test_symlink_file_directory_and_hardlink_refused(self):
        path = self.root / "qlu/protocol.py"
        original = self.root / "qlu/recovery.py"
        path.unlink(); path.symlink_to(original)
        with self.assertRaises(OSError): kit.verify(self.root)
        path.unlink(); os.link(original, path)
        with self.assertRaises(kit.KitError): kit.verify(self.root)
        path.unlink(); path.write_bytes(self.files["qlu/protocol.py"])
        directory = self.root / "extra-link"
        directory.symlink_to(self.root / "qlu", target_is_directory=True)
        with self.assertRaisesRegex(kit.KitError, "linked directory"):
            kit.verify(self.root)

    def test_list_challenge_rejected_even_with_matching_integrity_hashes(self):
        blob = b"[]"
        (self.root / "transfer/challenge.json").write_bytes(blob)
        self.manifest["challenge_sha256"] = hashlib.sha256(blob).hexdigest()
        self.manifest["files"]["transfer/challenge.json"] = {"sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob)}
        self.save_manifest()
        with self.assertRaises(kit.KitError): kit.verify(self.root)

    def test_duplicate_manifest_keys_and_traversal_refused(self):
        (self.root / "KIT-MANIFEST.json").write_bytes(b'{"version":1,"version":2}')
        with self.assertRaises(kit.KitError): kit.verify(self.root)
        for name in ("../private", "/absolute", "qlu/../private", ".local/secret", ".git/config", "qlu//recovery.py"):
            with self.subTest(name=name), self.assertRaises(kit.KitError): kit._safe_name(name)

    def test_selected_real_source_allowlist_excludes_private_runtime_files(self):
        sources = kit.selected_sources()
        self.assertIn("src/secp256k1/COPYING", sources)
        self.assertIn("test/functional/test_framework/messages.py", sources)
        self.assertIn("src/qlu/crypto.cpp", sources)
        for name in sources:
            self.assertNotIn(".local", Path(name).parts)
            self.assertNotIn(".git", Path(name).parts)
            self.assertNotIn("build", Path(name).parts)
            self.assertNotIn(name, {"code.txt", "wallet.json", "transfer/backup.json"})

    def test_wallet_profile_verifies_without_third_party_dependencies(self):
        self.wallet_profile()
        result = kit.verify(self.root)
        self.assertEqual(result["profile"], kit.WALLET_PROFILE)
        # -S disables site packages; target integrity checking must not import
        # vault/cryptography or require a completed native build.
        child = subprocess.run([sys.executable, "-S", str(Path(kit.__file__).resolve()),
                                "verify", "--directory", str(self.root)],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)["profile"], kit.WALLET_PROFILE)

    def test_wallet_profile_requires_every_added_source_and_public_origin(self):
        self.wallet_profile()
        for name in (*kit.WALLET_SOURCE_FILES, "transfer/wallet-origin.json"):
            record = self.manifest["files"].pop(name)
            self.save_manifest()
            with self.subTest(name=name), self.assertRaisesRegex(kit.KitError, "missing"):
                kit.verify(self.root)
            self.manifest["files"][name] = record
        self.save_manifest()

    def test_unknown_profiles_and_versions_are_refused(self):
        self.wallet_profile()
        for profile in ("unknown-v2", None, [], True):
            self.manifest["profile"] = profile; self.save_manifest()
            with self.subTest(profile=profile), self.assertRaises(kit.KitError):
                kit.verify(self.root)
        self.manifest["profile"] = kit.WALLET_PROFILE
        for version in (True, 2, "1"):
            self.manifest["version"] = version; self.save_manifest()
            with self.subTest(version=version), self.assertRaises(kit.KitError):
                kit.verify(self.root)
        with patch.object(kit, "_git") as git:
            with self.assertRaises(kit.KitError):
                kit.selected_sources(profile="unsupported")
            git.assert_not_called()

    def test_wallet_metadata_semantics_rejected_even_if_integrity_records_updated(self):
        original, _ = self.wallet_profile()
        edits = [("version", True), ("version", 2), ("format", "wrong"),
                 ("session_id", "11" * 16), ("purpose", "rehearsal"),
                 ("network_id", "other"), ("genesis_hash", "00" * 32),
                 ("challenge_sha256", "00" * 32), ("backup_sha256", "00" * 32),
                 ("wallet_commitment", "00" * 32), ("origin_vault_sha256", "not-a-hash"),
                 ("created_at", "2026-10-20T12:00:00"), ("created_at", []),
                 ("master_seed", "private data must never enter this schema")]
        for field, value in edits:
            altered = copy.deepcopy(original); altered[field] = value; self.save_origin(altered)
            with self.subTest(field=field), self.assertRaises(kit.KitError):
                kit.verify(self.root)
        for value in (False, 1, "true"):
            altered = copy.deepcopy(original)
            altered["origin_checks"]["portable_backup_verified"] = value
            self.save_origin(altered)
            with self.subTest(check=value), self.assertRaises(kit.KitError):
                kit.verify(self.root)
        self.save_origin([])
        with self.assertRaises(kit.KitError):
            kit.verify(self.root)

    def test_wallet_metadata_and_source_hashes_are_bound(self):
        original, _ = self.wallet_profile()
        self.manifest["wallet_origin_sha256"] = "00" * 32
        self.save_manifest()
        with self.assertRaisesRegex(kit.KitError, "origin fingerprint"):
            kit.verify(self.root)
        self.save_origin(original)
        for field in kit.WALLET_SCRIPT_HASHES:
            changed = copy.deepcopy(original); changed["tooling"][field] = "00" * 32
            self.save_origin(changed)
            with self.subTest(field=field), self.assertRaisesRegex(kit.KitError, "sources changed"):
                kit.verify(self.root)
        self.save_origin(original)
        self.set_file("qlu/vault.py", b"changed implementation with updated outer integrity record")
        self.save_manifest()
        with self.assertRaisesRegex(kit.KitError, "sources changed"):
            kit.verify(self.root)

    def test_wallet_profile_cannot_be_downgraded_or_include_private_artifacts(self):
        self.wallet_profile()
        del self.manifest["profile"]; self.save_manifest()
        with self.assertRaisesRegex(kit.KitError, "Unexpected source path"):
            kit.verify(self.root)
        self.manifest["profile"] = kit.WALLET_PROFILE
        for name in ("transfer/code.txt", "transfer/origin-vault.qlu", "transfer/passphrase.txt", "qlu/user-wallet.json"):
            self.set_file(name, b"private fixture must never be allowlisted")
            self.save_manifest()
            with self.subTest(name=name), self.assertRaisesRegex(kit.KitError, "Unexpected source path"):
                kit.verify(self.root)
            (self.root / name).unlink()
            del self.files[name]
            del self.manifest["files"][name]

    def test_wallet_archive_create_exports_only_approved_public_metadata_and_backup(self):
        from qlu import recovery
        origin, challenge = self.wallet_profile()
        identifier = origin["session_id"]
        session = {**self.manifest, "origin_tooling": {
            name: hashlib.sha256(self.files[path]).hexdigest() for name, path in kit.SCRIPT_HASHES.items()}}
        run = self.root / ".local" / "device-tests" / identifier
        (run / "transfer").mkdir(parents=True, mode=0o700)
        (run / "offline").mkdir(mode=0o700)
        recovery.write_private(run / "transfer/backup.json", self.files["transfer/backup.json"])
        recovery.write_private(run / "transfer/challenge.json", self.files["transfer/challenge.json"])
        recovery.write_private(run / "wallet-origin.json", kit._canonical(origin))
        private = b"PRIVATE-NONEXPORTED-FIXTURE-ONLY"
        recovery.write_private(run / "offline/code.txt", private)
        recovery.write_private(run / "origin-vault.qlu", private)
        recovery.write_private(run / "offline/passphrase.txt", private)
        sources = {name: blob for name, blob in self.files.items() if name in kit.SOURCE_FILES + kit.WALLET_SOURCE_FILES}
        sources["qlu/upstream.json"] = b'{"commit":"public-upstream-fixture"}'
        def secure_directory(path):
            path.mkdir(mode=0o700, exist_ok=True)
            path.chmod(0o700)
        modules = {"device_lab": SimpleNamespace(read_session=lambda *args: (run, session, challenge),
                                                session_id=lambda value: value),
                   "recovery": recovery, "devnet": SimpleNamespace(secure_directory=secure_directory)}
        with patch.dict(sys.modules, modules), patch.object(sys, "path", list(sys.path)), \
                patch.object(kit, "selected_sources", return_value=sources), \
                patch.object(kit, "_git", side_effect=lambda root, *args: b"a" * 40 if args[0] == "rev-parse" else b""):
            report = kit.create(identifier, self.root, profile=kit.WALLET_PROFILE)
        self.assertEqual(report["profile"], kit.WALLET_PROFILE)
        self.assertFalse(report["code_included"] or report["origin_vault_included"] or report["passphrase_included"])
        self.assertTrue(Path(report["archive"]).name.startswith("qlu-wallet-"))
        with tarfile.open(report["archive"], "r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            self.assertEqual({member.name.split("/", 1)[1] for member in members},
                             set(sources) | {"NOTICE", "transfer/backup.json", "transfer/challenge.json",
                                             "transfer/wallet-origin.json", "KIT-MANIFEST.json"})
            for member in members:
                self.assertEqual(member.mode, 0o600)
                self.assertNotIn(private, archive.extractfile(member).read())
            manifest = json.loads(archive.extractfile("qlu-wallet-" + identifier + "/KIT-MANIFEST.json").read())
            self.assertEqual(manifest["version"], 1)
            self.assertEqual(manifest["profile"], kit.WALLET_PROFILE)

    def test_explicit_recovery_profile_accepts_legacy_sources_without_wallet_files(self):
        self.manifest["profile"] = kit.RECOVERY_PROFILE; self.save_manifest()
        self.assertTrue(kit.verify(self.root)["verified"])


if __name__ == "__main__":
    unittest.main()
