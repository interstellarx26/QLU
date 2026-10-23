"""Public vector and failure-boundary checks for independent payment conformance."""
from contextlib import contextmanager, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qlu import conformance_smoke as smoke
from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import CTransaction, CTxOut, from_hex


def public_fixture():
    document = json.loads(smoke.VECTORS.read_text())
    tx = from_hex(CTransaction(), document["reference_signed_transaction"])
    spent = [CTxOut(row["sats"], bytes.fromhex(row["script"])) for row in document["spent"]]
    wallet = smoke.recovery.generate_wallet(smoke.protocol.NETWORK, smoke.protocol.GENESIS)
    wallet["master_seed"] = document["public_synthetic_master_seed"]
    return document, tx, spent, wallet


class PublicConformanceTests(unittest.TestCase):
    def test_frozen_both_signers_verify_at_both_input_indices(self):
        result = smoke.check_public_vectors()
        self.assertEqual(result["inputs"], 2)
        self.assertEqual(len(result["signers"]), 2)
        self.assertFalse(result["native_keys_checked"])

    def test_public_fixture_seed_is_explicitly_reproducible_and_valueless(self):
        document, tx, spent, _ = public_fixture()
        self.assertIs(document["public_synthetic"], True)
        self.assertEqual(hashlib.sha256(document["public_seed_label"].encode("ascii")).hexdigest(),
                         document["public_synthetic_master_seed"])
        self.assertIn("Never send funds", document["warning"])
        self.assertEqual(len(tx.vin), len(spent))
        self.assertEqual(tx.nLockTime, 42)
        self.assertNotEqual(tx.vin[0].nSequence, tx.vin[1].nSequence)

    def test_frozen_fields_and_native_signatures_are_not_silently_regenerated(self):
        original = json.loads(smoke.VECTORS.read_text())
        for field in ("digests", "keys", "address", "public_synthetic", "native_signed_transaction"):
            document = copy.deepcopy(original)
            if field == "digests":
                document[field][1] = "00" * 32
            elif field == "keys":
                document[field]["key_commitment"] = "00" * 32
            elif field == "address":
                document[field] = document[field][:-1] + "x"
            elif field == "public_synthetic":
                document[field] = False
            else:
                tx = from_hex(CTransaction(), document[field])
                tx.wit.vtxinwit[1].scriptWitness.stack[3] = bytes(64)
                document[field] = tx.serialize_with_witness().hex()
            with self.subTest(field=field), patch.object(Path, "read_text", return_value=json.dumps(document)), \
                    self.assertRaises(smoke.DevnetError):
                smoke.check_public_vectors()

    def test_native_key_disagreement_fails_closed(self):
        document, _, _, wallet = public_fixture()
        changed = dict(document["keys"]); changed["key_commitment"] = "00" * 32
        with patch.object(smoke.protocol, "keytool", return_value=changed), self.assertRaises(smoke.DevnetError):
            smoke.compare_keys(wallet)

    def test_independent_serialization_disagreement_fails_closed(self):
        _, tx, _, _ = public_fixture()
        with patch.object(smoke.reference, "unsigned_transaction", return_value=b"bad"), self.assertRaises(smoke.DevnetError):
            smoke.independent_unsigned(tx)

    def test_independent_digest_disagreement_fails_closed(self):
        _, tx, spent, _ = public_fixture()
        with patch.object(smoke.reference, "authorization_digest", return_value=bytes(32)), self.assertRaises(smoke.DevnetError):
            smoke.independent_digests(tx, spent)

    def test_negative_cases_bind_both_spent_outputs_and_nonzero_input_index(self):
        document, tx, spent, wallet = public_fixture()
        recipient = smoke.reference.derive_keys(hashlib.sha256(b"PUBLIC SYNTHETIC alternate recipient").digest())
        # Make the original recipient distinct, as in the live two-wallet drill.
        unsigned = CTransaction(tx); unsigned.vout[0].scriptPubKey = smoke.reference.script_for(recipient)
        tx = smoke.independent_sign(wallet, unsigned, spent)
        cases = smoke.negative_cases(wallet, tx, spent, recipient)
        self.assertEqual(len(cases), 14)
        self.assertEqual({name for name, _, _ in cases}, {
            "changed-output-amount", "changed-recipient", "corrupt-mldsa", "corrupt-schnorr",
            "missing-mldsa", "missing-schnorr", "wrong-mldsa-key", "wrong-schnorr-key",
            "wrong-spent-amount-0", "wrong-spent-amount-1", "wrong-spent-script", "wrong-network",
            "wrong-mldsa-context", "wrong-input-index"})
        for name, altered, reason in cases:
            with self.subTest(name=name):
                self.assertEqual(altered.txid_hex == tx.txid_hex, name not in ("changed-output-amount", "changed-recipient"))
                with self.assertRaises(smoke.DevnetError):
                    smoke.verify_independently(altered, spent, document["keys"])
                self.assertIn(reason, ("qlu-hybrid-signature", "qlu-key-commitment", "qlu-witness-shape"))
        smoke.verify_independently(tx, spent, document["keys"])


class RejectionBoundaryTests(unittest.TestCase):
    def setUp(self):
        _, self.tx, _, _ = public_fixture()
        coinbase = create_coinbase(103, script_pubkey=self.tx.vout[0].scriptPubKey, fees=100000, halving_period=150)
        block = create_block(1234, coinbase, 1792368100, txlist=[self.tx])
        add_witness_commitment(block)
        self.candidate = block.serialize().hex()

    def network(self, mode="valid"):
        class Network:
            calls = []
            def rpc(inner, index, method, *args):
                inner.calls.append((index, method, args))
                if method == "getbestblockhash":
                    return "changed" if mode == "changed-tip" and any(row[1] == "submitblock" for row in inner.calls) else "original"
                if method == "getrawmempool":
                    return ["changed"] if mode == "changed-mempool" and any(row[1] == "submitblock" for row in inner.calls) else []
                if method == "testmempoolaccept":
                    return [{"allowed": mode == "allowed", "reject-reason": "wrong-reason" if mode == "wrong-admission" else "qlu-hybrid-signature"}]
                if method == "sendrawtransaction":
                    if mode == "broadcast-accepted":
                        return "accepted"
                    raise smoke.RpcError("qlu-hybrid-signature", -25 if mode == "wrong-rpc-code" else -26)
                if method == "submitblock":
                    return "wrong-reason" if mode == "wrong-block" else "qlu-hybrid-signature"
                raise AssertionError(method)
        return Network()

    def test_each_node_rejects_admission_broadcast_and_distinct_direct_block(self):
        net = self.network()
        result = smoke.reject_everywhere(net, self.tx, "qlu-hybrid-signature", self.candidate)
        self.assertEqual([row["node"] for row in result["admission"]], list(range(4)))
        self.assertEqual(len({row["block"] for row in result["blocks"]}), 4)
        for method in ("testmempoolaccept", "sendrawtransaction", "submitblock"):
            self.assertEqual([index for index, called, _ in net.calls if called == method], list(range(4)))

    def test_wrong_rejection_reason_rpc_result_and_side_effects_fail(self):
        for mode in ("allowed", "wrong-admission", "broadcast-accepted", "wrong-rpc-code", "wrong-block", "changed-tip", "changed-mempool"):
            with self.subTest(mode=mode), self.assertRaises(smoke.DevnetError):
                smoke.reject_everywhere(self.network(mode), self.tx, "qlu-hybrid-signature", self.candidate)

    def test_unexpected_candidate_transaction_is_rejected(self):
        from test_framework.messages import CBlock
        block = from_hex(CBlock(), self.candidate)
        block.vtx.append(self.tx)
        with self.assertRaises(smoke.DevnetError):
            smoke.reject_everywhere(self.network(), self.tx, "qlu-hybrid-signature", block.serialize().hex())


class ConformanceLifecycleTests(unittest.TestCase):
    def test_installed_implementation_fingerprints_record_bytes_and_reject_wrong_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            implementation = Path("dilithium_py/ml_dsa/ml_dsa.py")
            (root / implementation).parent.mkdir(parents=True)
            (root / implementation).write_bytes(b"public-test-implementation")
            class Distribution:
                version = "1.5.1"
                files = [implementation]
                def locate_file(self, path): return root / path
            distribution = Distribution()
            with patch.object(smoke.importlib.metadata, "distribution", return_value=distribution):
                original = smoke.dependency_fingerprints()
                self.assertEqual(original[str(implementation)], hashlib.sha256(b"public-test-implementation").hexdigest())
                (root / implementation).write_bytes(b"changed-implementation")
                self.assertNotEqual(smoke.dependency_fingerprints(), original)
                distribution.version = "other"
                with self.assertRaises(smoke.DevnetError):
                    smoke.dependency_fingerprints()

    def test_fresh_owned_directory_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for identifier in ("../outside", "", "A" * 32, None):
                with self.assertRaises(smoke.DevnetError):
                    smoke.ConformanceNet(root, identifier)
            self.assertEqual(list(root.iterdir()), [])
            net = smoke.ConformanceNet(root, "ab" * 16)
            net.data.mkdir(parents=True)
            with self.assertRaises(smoke.DevnetError):
                smoke.ConformanceNet(root, "ab" * 16)

    def test_expired_budget_does_not_call_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            net = smoke.ConformanceNet(Path(directory), "ab" * 16)
            net.work_deadline = 5
            with patch.object(smoke.time, "monotonic", return_value=5), patch.object(smoke.QLUPrivateNet, "rpc") as rpc:
                with self.assertRaises(smoke.DevnetError):
                    net.rpc(0, "getbestblockhash")
                rpc.assert_not_called()

    def test_expired_work_and_failed_evidence_still_clean_up_without_leaking_secrets(self):
        secret, events, saved = "SECRET-DO-NOT-LOG", [], []
        @contextmanager
        def port_lock(root):
            (root / ".local").mkdir(mode=0o700)
            events.append("lock")
            try:
                yield
            finally:
                events.append("unlock")
        class Network:
            work_deadline = None
            def __init__(inner, root, identifier):
                inner.data = root / ".local" / ("conformance-" + identifier)
            def setup(inner): pass
            def require_binaries(inner): pass
            def require_stopped(inner): pass
            def start(inner):
                self.assertIsNotNone(inner.work_deadline)
                events.append("started")
                inner.work_deadline = 0
                raise smoke.DevnetError(secret)
            def stop(inner):
                self.assertIsNone(inner.work_deadline)
                events.append("stopped")
            def status(inner): return [{"status": "stopped"}] * 4
            def port_free(inner, port): return True
        def save(path, contents):
            saved.append(json.loads(contents))
            if len(saved) > 2:
                raise OSError(secret)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, patch.object(smoke.protocol, "ROOT", Path(directory)), \
                patch.object(smoke, "private_port_lock", port_lock), patch.object(smoke, "ConformanceNet", Network), \
                patch.object(smoke, "fingerprints", return_value={"public": "hash"}), \
                patch.object(smoke.subprocess, "check_output", return_value="public-head"), \
                patch.object(smoke, "check_public_vectors", return_value={}), \
                patch.object(smoke.reference, "self_test", return_value={}, create=True), \
                patch.object(smoke, "compare_keys", return_value={}), \
                patch.object(smoke, "write_private", side_effect=save), redirect_stdout(output):
            with self.assertRaisesRegex(smoke.DevnetError, "Independent conformance failed"):
                smoke.run()
        self.assertEqual(events, ["lock", "started", "stopped", "unlock"])
        self.assertFalse(saved[-1]["passed"])
        self.assertEqual(saved[-1]["cleanup"], "owned-nodes-stopped")
        self.assertIn('"evidence_error_type": "OSError"', output.getvalue())
        self.assertNotIn(secret, output.getvalue())
        self.assertNotIn(directory, output.getvalue())


if __name__ == "__main__":
    unittest.main()
