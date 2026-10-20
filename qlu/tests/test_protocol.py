"""Regression tests for wallet-policy, network and authorization boundaries."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import devnet
import private_net
import protocol
import recovery
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.segwit_addr import decode_segwit_address, encode_segwit_address


class ProtocolTests(unittest.TestCase):
    def test_unsupported_wallet_metadata_never_reaches_signer(self):
        wallet = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
        for key, value in (("policy", "classical-only"), ("derivation_version", 2), ("version", 2),
                           ("network_id", "other"), ("genesis_hash", "00" * 32)):
            altered = dict(wallet); altered[key] = value
            with self.subTest(field=key), patch.object(protocol.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    protocol.keytool(altered)
                run.assert_not_called()

    def test_digest_binds_every_input_output_and_chain(self):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(1, 0), nSequence=0xffffffff), CTxIn(COutPoint(2, 1), nSequence=0xffffffff)]
        tx.vout = [CTxOut(1500, b"\x52\x20" + bytes(32))]
        spent = [CTxOut(1000, tx.vout[0].scriptPubKey), CTxOut(1000, tx.vout[0].scriptPubKey)]
        original = protocol.authorization_digest(tx, spent, 0)
        self.assertNotEqual(original, protocol.authorization_digest(tx, spent, 1))
        self.assertNotEqual(original, protocol.authorization_digest(tx, spent, 0, "00" * 32))
        changes = [lambda t: setattr(t, "nLockTime", 1), lambda t: setattr(t, "version", 3),
                   lambda t: setattr(t.vin[1], "nSequence", 123), lambda t: setattr(t.vin[1].prevout, "n", 2),
                   lambda t: setattr(t.vout[0], "nValue", 1499),
                   lambda t: setattr(t.vout[0], "scriptPubKey", b"\x51")]
        for change in changes:
            altered = CTransaction(tx); change(altered)
            self.assertNotEqual(original, protocol.authorization_digest(altered, spent, 0))
        for field, value in (("nValue", 999), ("scriptPubKey", b"\x51")):
            altered = copy.deepcopy(spent); setattr(altered[1], field, value)
            self.assertNotEqual(original, protocol.authorization_digest(tx, altered, 0))
        with self.assertRaises(ValueError):
            protocol.authorization_digest(tx, spent[:1], 0)

    def test_addresses_reject_valid_other_network_and_bad_checksum(self):
        keys = {"key_commitment": "43" * 32}
        address = protocol.address_for(keys)
        self.assertEqual(decode_segwit_address("qlud", address), (2, list(bytes.fromhex(keys["key_commitment"]))))
        other = encode_segwit_address("bcrt", 2, bytes.fromhex(keys["key_commitment"]))
        self.assertIsNotNone(decode_segwit_address("bcrt", other)[0])
        self.assertEqual(decode_segwit_address("qlud", other), (None, None))
        corrupt = address[:-1] + ("q" if address[-1] != "q" else "p")
        self.assertEqual(decode_segwit_address("qlud", corrupt), (None, None))

    def test_private_controller_is_separate_and_disables_classical_wallet(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base, qlu = devnet.Devnet(root), private_net.QLUPrivateNet(root)
            self.assertNotEqual(base.data, qlu.data)
            qlu.setup()
            config = (qlu.node(0) / "bitcoin.conf").read_text()
            for required in ("qludev=1", "[qludev]", "disablewallet=1", "port=28440", "rpcport=28540", "bind=127.0.0.1:28440"):
                self.assertIn(required, config.splitlines())
            self.assertFalse(base.data.exists())
            with patch.object(qlu, "rpc", side_effect=[{"chain": "qludev"}, {"logpath": str(qlu.node(0) / "qludev/debug.log")}, "00" * 32]):
                with self.assertRaisesRegex(devnet.DevnetError, "genesis"):
                    qlu.verify_node(0)


if __name__ == "__main__":
    unittest.main()
