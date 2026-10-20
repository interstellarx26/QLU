"""Source-kit integrity and import-shadowing boundaries, using tiny fake files."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
