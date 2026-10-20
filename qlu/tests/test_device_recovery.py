"""Offline recovery drill boundaries; all wallets and transfers are disposable."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from qlu import device_recovery as device
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut


class DeviceRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wallet = device.recovery.generate_wallet(device.protocol.NETWORK, device.protocol.GENESIS)
        cls.keys = device.protocol.keytool(cls.wallet)
        cls.backup, cls.code = device.recovery.make_backup(cls.wallet)
        cls.tx = CTransaction()
        cls.tx.vin = [CTxIn(COutPoint(int("12" * 32, 16), 3), nSequence=0xffffffff)]
        cls.tx.vout = [CTxOut(99900000, b"\x52\x20" + bytes.fromhex("34" * 32))]
        cls.previous = CTxOut(100000000, device.protocol.script_for(cls.keys))
        cls.challenge = device.make_challenge(cls.tx, cls.previous, cls.keys["key_commitment"])
        cls.response = device.respond(cls.backup, cls.code, cls.challenge)

    def setUp(self):
        root = Path(__file__).resolve().parents[2] / ".local"
        self.temp = tempfile.TemporaryDirectory(prefix="device-recovery-tests-", dir=root)
        self.directory = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_native_restore_signs_exact_transaction_without_exporting_seed_or_code(self):
        signed = device.validate_response(self.response, self.challenge)
        self.assertEqual(signed.serialize_without_witness(), self.tx.serialize_without_witness())
        self.assertEqual([len(x) for x in signed.wit.vtxinwit[0].scriptWitness.stack], [1952, 32, 3309, 64])
        self.assertEqual(self.response["mode"], "rehearsal")
        encoded = json.dumps(self.response)
        self.assertNotIn(self.wallet["master_seed"], encoded)
        self.assertNotIn(self.code, encoded)
        self.assertEqual(set(self.response["device"]), {"system", "release", "machine", "python"})
        self.assertEqual(set(self.response["tooling"]), device.TOOLING_FIELDS)
        self.assertEqual(self.response["tooling"], device._tooling())

    def test_fresh_process_restore_creates_only_public_response(self):
        # This exercises a separate process on this host, never claims another device.
        import subprocess
        import sys
        backup, code, challenge, response = [self.directory / name for name in ("backup.json", "code.txt", "challenge.json", "response.json")]
        device.recovery.write_private(backup, self.backup)
        device.recovery.write_private(code, (self.code + "\n").encode())
        device.write_document(challenge, self.challenge)
        result = subprocess.run([sys.executable, str(Path(device.__file__)), "respond", "--backup", str(backup),
                                 "--code-file", str(code), "--challenge", str(challenge),
                                 "--response", str(response)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REHEARSAL", result.stdout)
        self.assertNotIn(self.wallet["master_seed"], result.stdout + result.stderr)
        self.assertNotIn(self.code, result.stdout + result.stderr)
        self.assertEqual({p.name for p in self.directory.iterdir()}, {"backup.json", "code.txt", "challenge.json", "response.json"})
        self.assertEqual(device.validate_response(device.read_document(response), self.challenge).txid_hex, self.tx.txid_hex)

    def test_wrong_network_or_genesis_refused_before_decrypting(self):
        for field, value in (("network_id", "regtest"), ("genesis_hash", "00" * 32)):
            challenge = {**self.challenge, field: value}
            with self.subTest(field=field), mock.patch.object(device.recovery, "restore_backup") as restore:
                with self.assertRaises(device.DeviceRecoveryError):
                    device.respond(self.backup, self.code, challenge)
                restore.assert_not_called()

    def test_wrong_recovery_code_and_backup_tampering_fail(self):
        with self.assertRaises(device.recovery.RecoveryError):
            device.respond(self.backup, device.recovery.generate_recovery_code(), self.challenge)
        backup = json.loads(self.backup)
        import base64
        damaged = bytearray(base64.b64decode(backup["ciphertext"]))
        damaged[10] ^= 1
        backup["ciphertext"] = base64.b64encode(damaged).decode()
        with self.assertRaises(device.recovery.RecoveryError):
            device.respond(json.dumps(backup).encode(), self.code, self.challenge)

    def test_unrelated_backup_cannot_answer_wallet_challenge(self):
        wallet = device.recovery.generate_wallet(device.protocol.NETWORK, device.protocol.GENESIS)
        backup, code = device.recovery.make_backup(wallet)
        with self.assertRaisesRegex(device.DeviceRecoveryError, "does not match"):
            device.respond(backup, code, self.challenge)

    def test_challenge_strict_fields_versions_and_scalar_types(self):
        mutations = [{**self.challenge, "extra": 0}, {**self.challenge, "version": True},
                     {**self.challenge, "challenge_id": "AA" * 16},
                     {**self.challenge, "unsigned_tx": "ff" * 100000}]
        for field in self.challenge:
            missing = copy.deepcopy(self.challenge)
            del missing[field]
            mutations.append(missing)
        for challenge in mutations:
            with self.subTest(challenge_keys=tuple(challenge)), self.assertRaises(device.DeviceRecoveryError):
                device.validate_challenge(challenge)

    def test_every_unsigned_transaction_byte_is_bound_to_challenge(self):
        raw = bytes.fromhex(self.challenge["unsigned_tx"])
        for index in range(len(raw)):
            mutation = bytearray(raw)
            mutation[index] ^= 1
            with self.subTest(index=index), self.assertRaises(device.DeviceRecoveryError):
                device.validate_challenge({**self.challenge, "unsigned_tx": mutation.hex()})

    def test_extra_inputs_outputs_witness_trailing_bytes_and_noncanonical_counts_fail(self):
        candidates = []
        tx = CTransaction(self.tx); tx.vin.append(copy.deepcopy(tx.vin[0])); candidates.append(tx.serialize_without_witness().hex())
        tx = CTransaction(self.tx); tx.vout.append(copy.deepcopy(tx.vout[0])); candidates.append(tx.serialize_without_witness().hex())
        candidates += [self.response["signed_tx"], self.challenge["unsigned_tx"] + "00",
                       self.challenge["unsigned_tx"][:8] + "fd0100" + self.challenge["unsigned_tx"][10:]]
        for raw in candidates:
            with self.subTest(length=len(raw)), self.assertRaises(device.DeviceRecoveryError):
                device.validate_challenge({**self.challenge, "unsigned_tx": raw})

    def test_previous_outpoint_value_script_and_recipient_are_checked(self):
        changes = [("previous_output", "txid", "00" * 32), ("previous_output", "vout", True),
                   ("previous_output", "vout", 2**32 - 1), ("previous_output", "value_sat", -1),
                   ("previous_output", "value_sat", device.MAX_INPUT_SAT + 1),
                   ("previous_output", "script_pubkey", "5120" + "55" * 32),
                   ("previous_output", "script_pubkey", "5220" + "55" * 32),
                   ("recipient", "value_sat", self.tx.vout[0].nValue + 1),
                   ("recipient", "script_pubkey", "5220" + self.keys["key_commitment"])]
        for outer, field, value in changes:
            challenge = copy.deepcopy(self.challenge)
            challenge[outer][field] = value
            with self.subTest(outer=outer, field=field, value=value), self.assertRaises(device.DeviceRecoveryError):
                device.validate_challenge(challenge)

    def test_fee_cannot_be_increased_even_when_metadata_and_transaction_agree(self):
        tx = CTransaction(self.tx)
        tx.vout[0].nValue -= 1
        with self.assertRaises(device.DeviceRecoveryError):
            device.make_challenge(tx, self.previous, self.keys["key_commitment"])
        for value in (0, True, device.FEE_SAT - 1, device.FEE_SAT + 1):
            with self.subTest(value=value), self.assertRaises(device.DeviceRecoveryError):
                device.validate_challenge({**self.challenge, "fee_sat": value})

    def test_pending_locktime_nonfinal_sequence_and_script_sig_refused(self):
        for field in ("locktime", "sequence", "scriptSig"):
            tx = CTransaction(self.tx)
            if field == "locktime": tx.nLockTime = 1
            elif field == "sequence": tx.vin[0].nSequence = 0xfffffffd
            else: tx.vin[0].scriptSig = b"\x00"
            with self.subTest(field=field), self.assertRaises(device.DeviceRecoveryError):
                device.make_challenge(tx, self.previous, self.keys["key_commitment"])

    def test_response_bound_to_full_challenge_and_not_just_transfer(self):
        challenge = {**self.challenge, "challenge_id": "56" * 16}
        with self.assertRaises(device.DeviceRecoveryError):
            device.validate_response(self.response, challenge)
        response = {**self.response, "challenge_id": challenge["challenge_id"]}
        with self.assertRaisesRegex(device.DeviceRecoveryError, "fingerprint"):
            device.validate_response(response, challenge)

    def test_response_transaction_shape_and_witness_lengths_refused(self):
        raw = bytes.fromhex(self.response["signed_tx"])
        for position in (4, 5, 6, 47, 92, 93, len(raw) - 1):
            mutated = bytearray(raw); mutated[position] ^= 1
            with self.subTest(position=position), self.assertRaises(device.DeviceRecoveryError):
                device.validate_response({**self.response, "signed_tx": mutated.hex()}, self.challenge)
        for value in (raw[:-1].hex(), (raw + b"\x00").hex(), self.challenge["unsigned_tx"]):
            with self.assertRaises(device.DeviceRecoveryError):
                device.validate_response({**self.response, "signed_tx": value}, self.challenge)

    def test_response_public_key_must_match_recovered_commitment(self):
        raw = bytearray.fromhex(self.response["signed_tx"])
        # prefix is 93 bytes, then CompactSize(1952) is three bytes.
        raw[96] ^= 1
        with self.assertRaisesRegex(device.DeviceRecoveryError, "another wallet"):
            device.validate_response({**self.response, "signed_tx": raw.hex()}, self.challenge)

    def test_response_untrusted_timings_platform_and_unknown_fields_refused(self):
        cases = [{**self.response, "mode": "verified-device"}, {**self.response, "version": True},
                 {**self.response, "txid": "00" * 32}, {**self.response, "seed": "forbidden"}]
        cases.append({**self.response, "tooling": {**self.response["tooling"], "keytool_sha256": "bad"}})
        for value in (-1, float("nan"), float("inf"), True, "1.0"):
            cases.append({**self.response, "timing_seconds": {**self.response["timing_seconds"], "backup_decryption": value}})
        for value in ("line\nbreak", "x" * 129, "", None):
            cases.append({**self.response, "device": {**self.response["device"], "system": value}})
        for response in cases:
            with self.subTest(keys=tuple(response)), self.assertRaises(device.DeviceRecoveryError):
                device.validate_response(response, self.challenge)

    def test_explicit_physical_mode_is_only_operator_attestation(self):
        response = device.respond(self.backup, self.code, self.challenge, mode="physical-device")
        self.assertEqual(response["mode"], "physical-device")
        self.assertNotIn("hardware_verified", response)
        self.assertEqual(device.validate_response(response, self.challenge).txid_hex, self.tx.txid_hex)

    def test_document_exclusive_permissions_and_large_signed_response_roundtrip(self):
        path = self.directory / "response.json"
        device.write_document(path, self.response)
        self.assertGreater(path.stat().st_size, device.recovery.MAX_BACKUP_BYTES)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(device.read_document(path), self.response)
        with self.assertRaises(FileExistsError):
            device.write_document(path, self.challenge)
        self.assertEqual(device.read_document(path), self.response)

    def test_document_duplicate_fields_oversized_files_and_unsafe_links_fail(self):
        for name, blob in (("duplicate", b'{"x":1,"x":2}'), ("huge", b" " * (device.MAX_DOCUMENT_BYTES + 1))):
            path = self.directory / name
            path.write_bytes(blob); path.chmod(0o600)
            with self.assertRaises(ValueError):
                device.read_document(path)
        original = self.directory / "original.json"
        device.write_document(original, self.challenge)
        link = self.directory / "link.json"; link.symlink_to(original)
        with self.assertRaises(OSError): device.read_document(link)
        link.unlink(); os.link(original, link)
        with self.assertRaises(device.DeviceRecoveryError): device.read_document(link)
        link.unlink(); original.chmod(0o644)
        with self.assertRaises(device.DeviceRecoveryError): device.read_document(original)

    def test_cli_errors_do_not_echo_secrets_or_overwrite_response(self):
        backup, code, challenge, response = [self.directory / name for name in ("backup", "code", "challenge", "response")]
        device.recovery.write_private(backup, self.backup)
        device.recovery.write_private(code, (device.recovery.generate_recovery_code() + "\n").encode())
        device.write_document(challenge, self.challenge)
        device.write_document(response, {"sentinel": True})
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            result = device.main(["respond", "--backup", str(backup), "--code-file", str(code),
                                  "--challenge", str(challenge), "--response", str(response)])
        self.assertEqual(result, 1)
        self.assertEqual(device.read_document(response), {"sentinel": True})
        self.assertNotIn(self.wallet["master_seed"], output.getvalue() + error.getvalue())
        self.assertNotIn(code.read_text().strip(), output.getvalue() + error.getvalue())


if __name__ == "__main__":
    unittest.main()
