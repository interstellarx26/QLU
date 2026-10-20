"""Origin evidence binding, safe retry, and encrypted preparation checks."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qlu import wallet_device_lab as lab


class WalletCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.run = Path(self.temporary.name).resolve()
        (self.run / "results").mkdir(mode=0o700)
        self.identifier = "34" * 16
        self.manifest = {"purpose": "rehearsal", "challenge_sha256": "12" * 32}
        self.response = {"mode": "rehearsal", "txid": "ab" * 32}
        self.origin = {"tooling": {"vault_sha256": "21" * 32},
                       "origin_checks": {"encrypted_reopen_same_identity": True,
                                         "portable_backup_verified": True}}
        self.envelope = {"response": self.response, "wallet_test": {"tooling": self.origin["tooling"]}}
        self.path = self.run / "returned.json"
        self.write(self.path, self.envelope)
        self.receipt = {"passed": True, "session_id": self.identifier, "purpose": "rehearsal",
                        "signed_payment_confirmed_on_four_nodes": True, "nodes": "stopped",
                        "physical_device_operator_attested": False, "hardware_attestation": False,
                        "challenge_sha256": self.manifest["challenge_sha256"],
                        "response_sha256": lab._canonical_hash(self.response), "txid": self.response["txid"]}
        self.patchers = [patch.object(lab, "read_origin", return_value=(self.run, self.manifest, {}, self.origin)),
                         patch.object(lab.wallet_device, "validate_result")]
        for item in self.patchers: item.start()

    def tearDown(self):
        for item in reversed(self.patchers): item.stop()
        self.temporary.cleanup()

    def write(self, path, document):
        lab.device.write_document(path, document)

    def checked_chain(self, *args, **kwargs):
        self.write(self.run / "receipt.json", self.receipt)
        return self.receipt

    def test_response_is_bound_before_any_chain_operation(self):
        self.envelope["wallet_test"]["tooling"] = {"vault_sha256": "ff" * 32}
        other = self.run / "changed.json"; self.write(other, self.envelope)
        with patch.object(lab.device_lab, "check") as check, self.assertRaises(ValueError):
            lab.check(self.identifier, other)
        check.assert_not_called()
        self.assertFalse((self.run / "results/wallet-response.json").exists())

    def test_physical_mode_requires_explicit_attestation(self):
        self.manifest["purpose"] = "physical-device"
        self.envelope["response"]["mode"] = "physical-device"
        other = self.run / "physical.json"; self.write(other, self.envelope)
        with patch.object(lab.device_lab, "check") as check, self.assertRaises(Exception):
            lab.check(self.identifier, other)
        check.assert_not_called()

    def test_rehearsal_cannot_be_relabelled_physical(self):
        with patch.object(lab.device_lab, "check") as check, self.assertRaises(Exception):
            lab.check(self.identifier, self.path, physical_attestation=True)
        check.assert_not_called()

    def test_first_check_saves_exact_outer_inner_and_chain_receipts(self):
        with patch.object(lab.device_lab, "check", side_effect=self.checked_chain) as check:
            result = lab.check(self.identifier, self.path)
        self.assertTrue(result["passed"])
        self.assertFalse(result["physical_device_operator_attested"])
        self.assertEqual(result["wallet_response_sha256"], lab._canonical_hash(self.envelope))
        self.assertEqual(lab.device.read_document(self.run / "results/wallet-payment-response.json"), self.response)
        self.assertEqual(check.call_args.args[1], self.run / "results/wallet-payment-response.json")
        self.assertEqual(lab.device.read_document(self.run / "wallet-receipt.json"), result)

    def test_retry_finishes_only_matching_post_chain_evidence_without_rebroadcast(self):
        original_save = lab._save_same
        def fail_wrapper(path, document):
            if path.name == "wallet-receipt.json": raise OSError("Injected final-write interruption")
            original_save(path, document)
        with patch.object(lab.device_lab, "check", side_effect=self.checked_chain), \
                patch.object(lab, "_save_same", side_effect=fail_wrapper), self.assertRaises(OSError):
            lab.check(self.identifier, self.path)
        self.assertFalse((self.run / "wallet-receipt.json").exists())
        with patch.object(lab.device_lab, "check") as check:
            result = lab.check(self.identifier, self.path)
            self.assertEqual(lab.check(self.identifier, self.path), result)
        check.assert_not_called()

    def test_existing_receipt_without_outer_evidence_cannot_be_adopted(self):
        self.write(self.run / "receipt.json", self.receipt)
        with patch.object(lab.device_lab, "check") as check, self.assertRaises(ValueError):
            lab.check(self.identifier, self.path)
        check.assert_not_called()

    def test_changed_outer_claims_cannot_reuse_a_spent_challenge(self):
        with patch.object(lab.device_lab, "check", side_effect=self.checked_chain):
            lab.check(self.identifier, self.path)
        changed = copy.deepcopy(self.envelope); changed["wallet_test"]["extra"] = "changed claim"
        other = self.run / "different.json"; self.write(other, changed)
        with patch.object(lab.device_lab, "check") as check, self.assertRaises(ValueError):
            lab.check(self.identifier, other)
        check.assert_not_called()

    def test_mismatched_chain_receipt_fails_closed(self):
        with patch.object(lab.device_lab, "check", side_effect=self.checked_chain):
            lab.check(self.identifier, self.path)
        receipt = self.run / "receipt.json"
        changed = copy.deepcopy(self.receipt); changed["response_sha256"] = "ff" * 32
        receipt.write_bytes(lab.recovery._canonical(changed))
        with patch.object(lab.device_lab, "check") as check, self.assertRaises(ValueError):
            lab.check(self.identifier, self.path)
        check.assert_not_called()

    def test_status_never_broadcasts_when_chain_receipt_is_missing(self):
        with patch.object(lab.device_lab, "check", side_effect=self.checked_chain):
            lab.check(self.identifier, self.path)
        (self.run / "receipt.json").unlink()
        with patch.object(lab.device_lab, "check") as check, self.assertRaises(ValueError):
            lab.status(self.identifier)
        check.assert_not_called()


class EncryptedOriginTests(unittest.TestCase):
    def test_preparation_encrypts_and_reopens_source_without_plaintext_seed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "transfer").mkdir(mode=0o700); (root / "offline").mkdir(mode=0o700)
            wallet = lab.recovery.generate_wallet(lab.protocol.NETWORK, lab.protocol.GENESIS)
            backup, code = lab.recovery.make_backup(wallet)
            lab.recovery.write_private(root / "transfer/backup.json", backup)
            lab.recovery.write_private(root / "offline/code.txt", code.encode())
            identifier = "56" * 16
            manifest = {"session_id": identifier, "purpose": "rehearsal", "network_id": lab.protocol.NETWORK,
                        "genesis_hash": lab.protocol.GENESIS, "challenge_sha256": "11" * 32,
                        "backup_sha256": lab.hashlib.sha256(backup).hexdigest()}
            challenge = {"wallet_commitment": lab.protocol.keytool(wallet)["key_commitment"]}
            sources = {key: "33" * 32 for key in lab.WALLET_SOURCES}
            with patch.object(lab.device_lab, "prepare", return_value={"session_id": identifier}), \
                    patch.object(lab.device_lab, "read_session", return_value=(root, manifest, challenge)), \
                    patch.object(lab, "tooling", return_value=sources):
                result = lab.prepare(root, rehearsal=True)
                origin = lab.read_origin(identifier, root)[3]
                self.assertEqual(result["status"], "awaiting-wallet-response")
                self.assertTrue(all(origin["origin_checks"].values()))
                vault_bytes = lab.recovery.read_private(root / "origin.vault.json")
                self.assertNotIn(wallet["master_seed"].encode(), vault_bytes)
                self.assertNotIn(b"master_seed", vault_bytes)
                self.assertNotIn(code, lab.recovery._canonical(origin).decode())
                self.assertEqual({p.name for p in root.iterdir()},
                                 {"transfer", "offline", "origin.vault.json", "wallet-origin.json"})
                corrupted = copy.deepcopy(origin); corrupted["version"] = True
                (root / "wallet-origin.json").write_bytes(lab.recovery._canonical(corrupted))
                with self.assertRaises(ValueError): lab.read_origin(identifier, root)


if __name__ == "__main__":
    unittest.main()
