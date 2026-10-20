"""Origin recovery coordinator safety boundaries; no nodes or network started."""
import hashlib
from contextlib import redirect_stderr
import io
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import device_lab as lab
import device_recovery as device
import protocol
import recovery
from devnet import DevnetError
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut


SESSION = "ab" * 16


def fixture():
    previous = CTxOut(100000000, b"\x52\x20" + bytes.fromhex("12" * 32))
    transaction = CTransaction()
    transaction.vin = [CTxIn(COutPoint(123, 0), nSequence=0xffffffff)]
    transaction.vout = [CTxOut(99900000, b"\x52\x20" + bytes.fromhex("34" * 32))]
    challenge = device.make_challenge(transaction, previous, "12" * 32, SESSION)
    manifest = {key: "unused" for key in lab.MANIFEST_FIELDS}
    manifest.update(format="qlu-device-lab", version=1, session_id=SESSION, purpose="physical-device",
                    network_id=protocol.NETWORK, genesis_hash=protocol.GENESIS,
                    controller_data_name="device-" + SESSION,
                    challenge_sha256=device.challenge_hash(challenge),
                    backup_sha256=hashlib.sha256(b"fixture-backup").hexdigest(),
                    node_binary_sha256="ab" * 32, keytool_sha256="cd" * 32,
                    origin_tooling={name: "12" * 32 for name in ("device_recovery_sha256", "protocol_sha256", "recovery_sha256", "keytool_sha256")},
                    funding_txid=challenge["previous_output"]["txid"])
    return challenge, manifest


class DeviceLabTests(unittest.TestCase):
    def test_cli_failure_returns_diagnostic_without_masking_original_error(self):
        diagnostic = io.StringIO()
        with redirect_stderr(diagnostic):
            result = lab.main(["status", "--session", "../invalid"])
        self.assertEqual(result, 1)
        self.assertIn("Session must be", diagnostic.getvalue())
        self.assertIn("QLU recovery lab failed", diagnostic.getvalue())

    def test_session_identifier_cannot_escape_ignored_data(self):
        for value in ("../outside", "A" * 32, "a" * 31, "a" * 33, "/tmp/" + SESSION, True, None):
            with self.subTest(value=value), self.assertRaises(DevnetError):
                lab.session_id(value)
        self.assertEqual(lab.session_id(SESSION), SESSION)

    def test_controller_owns_separate_data_and_process_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            controller = lab.DeviceNet(SESSION, root)
            other = lab.DeviceNet("cd" * 16, root)
            self.assertEqual(controller.data, root.resolve() / ".local" / ("device-" + SESSION))
            self.assertNotEqual(controller.data, other.data)
            self.assertNotEqual(controller.process_label, other.process_label)
            self.assertEqual((controller.p2p_base, controller.rpc_base), (28440, 28540))
            self.assertEqual(controller.chain, "qludev")

    def test_session_creation_is_private_exclusive_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = lab.make_session(root, SESSION)
            for path in (run, run / "transfer", run / "offline", run / "results"):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                lab.make_session(root, SESSION)
            (root / ".local/device-tests" / ("cd" * 16)).symlink_to(run)
            with self.assertRaises(FileExistsError):
                lab.make_session(root, "cd" * 16)

    def test_coin_amounts_use_exact_integer_accounting(self):
        self.assertEqual(lab.satoshis("0.00000001"), 1)
        self.assertEqual(lab.satoshis(49.999), 4999900000)
        for value in ("0.000000001", "-1", "NaN", "Infinity"):
            with self.subTest(value=value), self.assertRaises(DevnetError):
                lab.satoshis(value)

    def test_spent_output_accepts_cli_empty_null_but_not_other_falsy_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            controller = lab.DeviceNet(SESSION, Path(temporary))
            empty = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with patch("devnet.subprocess.run", return_value=empty):
                spent = controller.rpc(0, "gettxout", "ab" * 32, 0)
            self.assertEqual(spent, "")
            self.assertTrue(lab.rpc_null(spent))
            self.assertTrue(lab.rpc_null(None))
            for malformed in (False, 0, [], {}, "null", "0"):
                with self.subTest(value=malformed):
                    self.assertFalse(lab.rpc_null(malformed))

    def test_rehearsal_cannot_become_physical_device_evidence(self):
        for manifest, response, attestation in (
                ({"purpose": "rehearsal"}, {"mode": "physical-device"}, True),
                ({"purpose": "physical-device"}, {"mode": "rehearsal"}, True),
                ({"purpose": "physical-device"}, {"mode": "physical-device"}, False),
                ({"purpose": "rehearsal"}, {"mode": "rehearsal"}, True)):
            with self.subTest(manifest=manifest, response=response, attestation=attestation), self.assertRaises(DevnetError):
                lab.authorize_mode(manifest, response, attestation)
        self.assertEqual(lab.authorize_mode({"purpose": "physical-device"}, {"mode": "physical-device"}, True), "physical-device")
        self.assertEqual(lab.authorize_mode({"purpose": "rehearsal"}, {"mode": "rehearsal"}, False), "rehearsal")

    def test_manifest_and_challenge_are_bound_before_any_node_work(self):
        challenge, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = lab.make_session(root, SESSION)
            device.write_document(run / "manifest.json", manifest)
            device.write_document(run / "transfer/challenge.json", challenge)
            recovery.write_private(run / "transfer/backup.json", b"fixture-backup")
            self.assertEqual(lab.read_session(root, SESSION)[1], manifest)
            (run / "transfer/challenge.json").unlink()
            challenge["recipient"]["script_pubkey"] = (b"\x52\x20" + bytes.fromhex("56" * 32)).hex()
            # A different but fully valid challenge still cannot replace the recorded one.
            transaction, previous = device.validate_challenge(fixture()[0])
            transaction.vout[0].scriptPubKey = bytes.fromhex(challenge["recipient"]["script_pubkey"])
            replacement = device.make_challenge(transaction, previous, "12" * 32, SESSION)
            device.write_document(run / "transfer/challenge.json", replacement)
            with self.assertRaisesRegex(DevnetError, "changed"):
                lab.read_session(root, SESSION)

    def test_manifest_wrong_network_or_data_name_rejected(self):
        challenge, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = lab.make_session(root, SESSION)
            device.write_document(run / "transfer/challenge.json", challenge)
            for field, replacement in (("network_id", "regtest"), ("genesis_hash", "00" * 32),
                                       ("controller_data_name", "qlu-private-v1"), ("version", True),
                                       ("session_id", "cd" * 16)):
                with self.subTest(field=field):
                    altered = dict(manifest); altered[field] = replacement
                    device.write_document(run / "manifest.json", altered)
                    with self.assertRaises(DevnetError):
                        lab.read_session(root, SESSION)
                    (run / "manifest.json").unlink()

    def test_changed_backup_is_not_a_valid_pending_package(self):
        challenge, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = lab.make_session(root, SESSION)
            device.write_document(run / "manifest.json", manifest)
            device.write_document(run / "transfer/challenge.json", challenge)
            recovery.write_private(run / "transfer/backup.json", b"changed-backup")
            with self.assertRaisesRegex(DevnetError, "backup changed"):
                lab.status(SESSION, root)

    def test_counterfeit_rehearsal_receipt_cannot_claim_physical_success(self):
        challenge, manifest = fixture()
        manifest["purpose"] = "rehearsal"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = lab.make_session(root, SESSION)
            device.write_document(run / "manifest.json", manifest)
            device.write_document(run / "transfer/challenge.json", challenge)
            recovery.write_private(run / "transfer/backup.json", b"fixture-backup")
            device.write_document(run / "receipt.json", {
                "passed": True, "session_id": SESSION, "purpose": "rehearsal",
                "signed_payment_confirmed_on_four_nodes": True, "physical_device_operator_attested": True,
                "hardware_attestation": False, "challenge_sha256": manifest["challenge_sha256"]})
            with self.assertRaisesRegex(DevnetError, "inconsistent"):
                lab.status(SESSION, root)

    def test_cleanup_runs_when_work_fails(self):
        controller = MagicMock()
        controller.status.return_value = [{"status": "stopped"}] * 4
        with self.assertRaisesRegex(RuntimeError, "work failed"):
            with lab.running(controller):
                raise RuntimeError("work failed")
        controller.stop.assert_called_once()

    def test_foreign_running_process_preflight_never_calls_stop(self):
        controller = MagicMock()
        controller.require_stopped.side_effect = DevnetError("unowned process")
        with self.assertRaisesRegex(DevnetError, "unowned"):
            with lab.running(controller):
                self.fail("Must not enter body")
        controller.start.assert_not_called()
        controller.stop.assert_not_called()

    def test_cleanup_failure_is_not_reported_as_success(self):
        controller = MagicMock()
        controller.status.return_value = [{"status": "running"}] * 4
        with self.assertRaisesRegex(DevnetError, "did not all stop"):
            with lab.running(controller):
                pass

    def test_missing_attestation_stops_before_node_start(self):
        challenge, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = lab.make_session(root, SESSION)
            with patch.object(lab, "read_session", return_value=(run, manifest, challenge)), \
                    patch.object(device, "read_document", return_value={"mode": "physical-device"}), \
                    patch.object(device, "validate_response"), patch.object(lab, "DeviceNet") as controller:
                with self.assertRaisesRegex(DevnetError, "explicit confirmation"):
                    lab.check(SESSION, run / "response.json", root)
                controller.assert_not_called()


if __name__ == "__main__":
    unittest.main()
