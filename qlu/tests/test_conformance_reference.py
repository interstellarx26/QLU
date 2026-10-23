"""Independent primitive known answers and QLU v1 serialization boundaries.

All seeds/keys here and in conformance_vendor are published synthetic test data.
Missing or mismatched reference dependencies fail collection; nothing is skipped.
"""
import ast
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import conformance_reference as reference

VENDOR = Path(reference.__file__).parent / "conformance_vendor"
SCRIPT = b"\x52\x20" + bytes(range(32))
INPUTS = [("01" * 32, 2, 0xfffffffe), ("02" * 32, 3, 0xfffffffd)]
OUTPUTS = [(1000, SCRIPT), (0, b"\x6a\x01Q")]
SPENT = [(700, SCRIPT), (400, SCRIPT)]


class OfficialReferenceTests(unittest.TestCase):
    def test_vendored_files_match_pinned_external_hashes(self):
        manifest = json.loads((VENDOR / "provenance.json").read_text())
        self.assertEqual(manifest["dilithium_py"]["release"], "1.5.1")
        for filename, expected in manifest["vendored_sha256"].items():
            with self.subTest(file=filename):
                self.assertEqual(hashlib.sha256((VENDOR / filename).read_bytes()).hexdigest(), expected)
        self.assertFalse(reference.bip340.DEBUG)

    def test_all_official_bip340_vectors(self):
        with (VENDOR / "bip340_test_vectors.csv").open(newline="") as stream:
            vectors = list(csv.DictReader(stream))
        self.assertEqual(len(vectors), 19)
        for vector in vectors:
            with self.subTest(index=vector["index"]):
                public = bytes.fromhex(vector["public key"])
                message = bytes.fromhex(vector["message"])
                signature = bytes.fromhex(vector["signature"])
                expected = vector["verification result"] == "TRUE"
                self.assertEqual(reference.bip340.schnorr_verify(message, public, signature), expected)
                if vector["secret key"]:
                    secret = bytes.fromhex(vector["secret key"])
                    auxiliary = bytes.fromhex(vector["aux_rand"])
                    self.assertEqual(reference.bip340.pubkey_gen(secret), public)
                    self.assertEqual(reference.bip340.schnorr_sign(message, secret, auxiliary), signature)

    def test_nist_mldsa65_key_generation_full_public_key(self):
        vector = json.loads((VENDOR / "nist_mldsa65_subset.json").read_text())["keygen"][0]
        public, _ = reference.ML_DSA_65.key_derive(bytes.fromhex(vector["seed"]))
        self.assertEqual(public, bytes.fromhex(vector["pk"]))
        self.assertEqual(hashlib.sha256(public).hexdigest(),
                         "b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a")

    def test_nist_mldsa65_external_pure_context_signature_exact_bytes(self):
        vector = json.loads((VENDOR / "nist_mldsa65_subset.json").read_text())["siggen"][0]
        self.assertEqual((vector["parameterSet"], vector["signatureInterface"], vector["preHash"], vector["deterministic"]),
                         ("ML-DSA-65", "external", "pure", True))
        private, message, context = (bytes.fromhex(vector[key]) for key in ("sk", "message", "context"))
        signature = reference.ML_DSA_65.sign(private, message, ctx=context, deterministic=True)
        self.assertEqual(signature, bytes.fromhex(vector["signature"]))
        public = reference.ML_DSA_65.pk_from_sk(private)
        self.assertTrue(reference.ML_DSA_65.verify(public, message, signature, ctx=context))
        self.assertFalse(reference.ML_DSA_65.verify(public, message, signature, ctx=b""))

    def test_nist_mldsa65_external_verification_accepts_and_rejects(self):
        vectors = json.loads((VENDOR / "nist_mldsa65_subset.json").read_text())["sigver"]
        self.assertEqual([v["testPassed"] for v in vectors], [False, False, True])
        for vector in vectors:
            with self.subTest(case=vector["tcId"]):
                self.assertEqual((vector["signatureInterface"], vector["preHash"]), ("external", "pure"))
                public, message, signature, context = (bytes.fromhex(vector[key]) for key in ("pk", "message", "signature", "context"))
                self.assertEqual(reference.ML_DSA_65.verify(public, message, signature, ctx=context), vector["testPassed"])

    def test_standalone_self_test_checks_integrity_and_all_official_vectors(self):
        result = reference.self_test()
        self.assertEqual(result["bip340_vectors"], 19)
        self.assertEqual(result["nist_mldsa65_keygen_vectors"], 1)
        self.assertEqual(result["nist_mldsa65_sign_vectors"], 1)
        self.assertEqual(result["nist_mldsa65_verify_vectors"], 3)
        self.assertEqual(len(result["installed_python_sha256"]), 20)

    def test_standalone_self_test_rejects_altered_vendor_or_package_hash(self):
        original = Path.read_bytes

        def altered(path):
            data = original(path)
            return data + b"\n# altered\n" if path.name == "bip340_reference.py" else data

        with patch.object(Path, "read_bytes", altered), self.assertRaisesRegex(RuntimeError, "integrity"):
            reference.self_test()
        def package_altered(path):
            data = original(path)
            return data + b"\n# altered\n" if path.name == "ml_dsa.py" else data
        with patch.object(Path, "read_bytes", package_altered), self.assertRaisesRegex(RuntimeError, "integrity"):
            reference.self_test()

    def test_optional_unpinned_shake_backend_rejected(self):
        with patch.object(reference.ml_dsa_module, "shake256", object()), self.assertRaisesRegex(RuntimeError, "SHAKE"):
            reference.self_test()
        with patch.object(reference.polynomial_module, "shake128", object()), self.assertRaisesRegex(RuntimeError, "SHAKE"):
            reference.self_test()


class IndependentSerializationTests(unittest.TestCase):
    def setUp(self):
        self.raw = reference.unsigned_transaction(INPUTS, OUTPUTS)

    def test_reference_has_no_production_or_native_crypto_imports(self):
        tree = ast.parse(Path(reference.__file__).read_text())
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module)
        allowed = {"__future__", "csv", "hashlib", "hmac", "importlib.metadata", "json", "pathlib", "struct", "dilithium_py", "dilithium_py.ml_dsa", "dilithium_py.polynomials", "dilithium_py.shake", "conformance_vendor"}
        self.assertLessEqual(set(names), allowed)

    def test_no_witness_serialization_exact_layout_and_round_trip(self):
        expected = (b"\x02\x00\x00\x00\x02" + b"\x01" * 32 + bytes.fromhex("0200000000feffffff")
                    + b"\x02" * 32 + bytes.fromhex("0300000000fdffffff02e80300000000000022")
                    + SCRIPT + bytes.fromhex("0000000000000000036a015100000000"))
        self.assertEqual(self.raw, expected)
        self.assertEqual(reference.parse_transaction(self.raw),
                         {"version": 2, "inputs": INPUTS, "outputs": OUTPUTS, "locktime": 0})

    def test_display_txid_is_reversed_and_uint_fields_are_little_endian(self):
        raw = reference.unsigned_transaction([(bytes(range(32)).hex(), 0x12345678, 0x90abcdef)], [(0, SCRIPT)], locktime=0xdeadbeef)
        self.assertEqual(raw[5:37], bytes(range(32))[::-1])
        self.assertEqual(raw[37:46], bytes.fromhex("7856341200efcdab90"))
        self.assertEqual(raw[-4:], bytes.fromhex("efbeadde"))

    def test_every_truncation_trailing_data_and_witness_marker_rejected(self):
        for n in range(len(self.raw)):
            with self.subTest(length=n), self.assertRaises(ValueError):
                reference.parse_transaction(self.raw[:n])
        for raw in (self.raw + b"\x00", self.raw[:4] + b"\x00\x01" + self.raw[4:]):
            with self.assertRaises(ValueError):
                reference.parse_transaction(raw)

    def test_noncanonical_counts_and_scriptsig_rejected(self):
        bad = [self.raw[:4] + b"\xfd\x02\x00" + self.raw[5:],
               self.raw[:4] + b"\xfe\x02\x00\x00\x00" + self.raw[5:],
               self.raw[:4] + b"\xff" + (2).to_bytes(8, "little") + self.raw[5:],
               self.raw[:41] + b"\x01\x51" + self.raw[42:]]
        for raw in bad:
            with self.subTest(raw=raw[:8].hex()), self.assertRaises(ValueError):
                reference.parse_transaction(raw)

    def test_empty_oversized_version_and_duplicate_inputs_rejected(self):
        for inputs, outputs, version_number in [([], OUTPUTS, 2), (INPUTS, [], 2),
                (INPUTS * 9, OUTPUTS, 2), (INPUTS, OUTPUTS * 17, 2),
                (INPUTS, OUTPUTS, 3), (INPUTS, OUTPUTS, True),
                ([INPUTS[0], INPUTS[0]], OUTPUTS, 2),
                ([("00" * 32, 0xffffffff, 0)], OUTPUTS, 2)]:
            with self.subTest(counts=(len(inputs), len(outputs)), version=version_number), self.assertRaises(ValueError):
                reference.unsigned_transaction(inputs, outputs, version_number)
        with self.assertRaises(ValueError):
            reference.parse_transaction(bytes(4097))

    def test_money_output_script_and_metadata_limits(self):
        for outputs in [[(-1, SCRIPT)], [(True, SCRIPT)], [(reference.MAX_MONEY + 1, SCRIPT)],
                        [(reference.MAX_MONEY, SCRIPT), (1, SCRIPT)], [(1, b"\x51")],
                        [(0, b"")], [(1, b"\x6a")], [(0, b"\x6a" + bytes(83))]]:
            with self.subTest(amount=outputs[0][0], size=len(outputs[0][1])), self.assertRaises(ValueError):
                reference.unsigned_transaction(INPUTS, outputs)
        raw = reference.unsigned_transaction(INPUTS, [(0, b"\x6a" + bytes(82))])
        self.assertEqual(reference.parse_transaction(raw)["outputs"][0][1], b"\x6a" + bytes(82))

    def test_compact_size_boundaries(self):
        values = {0: "00", 252: "fc", 253: "fdfd00", 65535: "fdffff",
                  65536: "fe00000100", 0xffffffff: "feffffffff", 0x100000000: "ff0000000001000000"}
        for value, encoded in values.items():
            self.assertEqual(reference.compact_size(value).hex(), encoded)
        for value in (-1, 1 << 64, True, 1.0):
            with self.assertRaises(ValueError):
                reference.compact_size(value)

    def test_all_inputs_values_scripts_and_transaction_fields_bound(self):
        original = reference.authorization_digest(self.raw, SPENT, 0)
        candidates = [reference.authorization_digest(self.raw, SPENT, 1),
                      reference.authorization_digest(self.raw, SPENT, 0, "ff" * 32),
                      reference.authorization_digest(reference.unsigned_transaction(INPUTS, OUTPUTS, locktime=1), SPENT, 0)]
        for position in range(2):
            for field, replacement in [(0, "03" * 32), (1, 4), (2, 12)]:
                changed = list(INPUTS)
                triple = list(changed[position]); triple[field] = replacement; changed[position] = tuple(triple)
                candidates.append(reference.authorization_digest(reference.unsigned_transaction(changed, OUTPUTS), SPENT, 0))
            for changed_spent in [SPENT[:position] + [(SPENT[position][0] + 1, SCRIPT)] + SPENT[position + 1:],
                                  SPENT[:position] + [(SPENT[position][0], b"\x52\x20" + b"\xfe" * 32)] + SPENT[position + 1:]]:
                candidates.append(reference.authorization_digest(self.raw, changed_spent, 0))
        for outputs in [[(999, SCRIPT), OUTPUTS[1]], [(1000, b"\x52\x20" + b"\xfd" * 32), OUTPUTS[1]],
                        [OUTPUTS[0], (0, b"\x6a\x01R")], list(reversed(OUTPUTS))]:
            candidates.append(reference.authorization_digest(reference.unsigned_transaction(INPUTS, outputs), SPENT, 0))
        self.assertEqual(len(candidates), len(set(candidates)))
        self.assertNotIn(original, candidates)

    def test_auth_input_shapes_and_negative_fee_rejected(self):
        for spent, index, genesis in [(SPENT[:1], 0, reference.GENESIS), (SPENT, -1, reference.GENESIS),
                (SPENT, 2, reference.GENESIS), (SPENT, True, reference.GENESIS), (SPENT, 0, "00" * 31),
                ([(1, SCRIPT), (1, SCRIPT)], 0, reference.GENESIS),
                ([(700, b"\x6a"), SPENT[1]], 0, reference.GENESIS),
                ([(reference.MAX_MONEY, SCRIPT), SPENT[1]], 0, reference.GENESIS)]:
            with self.subTest(index=index, count=len(spent)), self.assertRaises(ValueError):
                reference.authorization_digest(self.raw, spent, index, genesis)

    def test_witness_layout_and_lengths_are_exact(self):
        stack = [bytes(1952), bytes(32), bytes(3309), bytes(64)]
        encoded = reference.encode_witness(self.raw, [stack, stack])
        witness = b"\x04" + b"\xfd\xa0\x07" + bytes(1952) + b"\x20" + bytes(32) + b"\xfd\xed\x0c" + bytes(3309) + b"\x40" + bytes(64)
        self.assertEqual(encoded, self.raw[:4] + b"\x00\x01" + self.raw[4:-4] + witness * 2 + self.raw[-4:])
        for stacks in [[stack], [stack[:3], stack], [stack + [b""], stack], [[b""] + stack[1:], stack]]:
            with self.assertRaises(ValueError):
                reference.encode_witness(self.raw, stacks)


class HybridReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed = bytes(range(32))  # Public synthetic vector; no user wallet.
        cls.digest = hashlib.sha256(b"public QLU conformance fixture").digest()
        cls.signed = reference.sign(cls.seed, cls.digest)
        cls.ml = bytes.fromhex(cls.signed["mldsa_signature"])
        cls.schnorr = bytes.fromhex(cls.signed["schnorr_signature"])

    def test_hybrid_derivation_repeatability_and_both_signatures(self):
        keys = reference.derive_keys(self.seed)
        self.assertEqual(keys, {k: self.signed[k] for k in keys})
        self.assertEqual(len(bytes.fromhex(keys["mldsa_public"])), 1952)
        self.assertTrue(reference.verify(keys, self.digest, self.ml, self.schnorr))
        self.assertEqual(reference.sign(self.seed, self.digest), self.signed)
        self.assertEqual(reference.script_for(keys), b"\x52\x20" + bytes.fromhex(keys["key_commitment"]))
        self.assertTrue(reference.address_for(keys).startswith("qlud1z"))

    def test_missing_corrupt_components_digest_context_and_commitment_rejected(self):
        for ml, schnorr in [(b"", self.schnorr), (self.ml, b""), (self.ml[:-1], self.schnorr),
                (self.ml + b"\x00", self.schnorr), (self.ml, self.schnorr[:-1]),
                (self.ml[:100] + bytes([self.ml[100] ^ 1]) + self.ml[101:], self.schnorr),
                (self.ml, bytes([self.schnorr[0] ^ 1]) + self.schnorr[1:])]:
            self.assertFalse(reference.verify(self.signed, self.digest, ml, schnorr))
        self.assertFalse(reference.verify(self.signed, bytes(32), self.ml, self.schnorr))
        self.assertFalse(reference.verify(self.signed, self.digest, self.ml, self.schnorr, context=b""))
        self.assertFalse(reference.verify(self.signed, self.digest, self.ml, self.schnorr, context=b"x" * 256))
        for key, value in [("key_commitment", "00" * 32), ("mldsa_public", "00" * 1952),
                           ("schnorr_public", "ff" * 32), ("schnorr_public", "00" * 31)]:
            self.assertFalse(reference.verify(self.signed | {key: value}, self.digest, self.ml, self.schnorr))

    def test_wrong_context_signatures_do_not_authorize_normal_context(self):
        signed = reference.sign(self.seed, self.digest, context=b"wrong-context")
        ml = bytes.fromhex(signed["mldsa_signature"])
        schnorr = bytes.fromhex(signed["schnorr_signature"])
        self.assertFalse(reference.verify(signed, self.digest, ml, schnorr))
        self.assertTrue(reference.verify(signed, self.digest, ml, schnorr, context=b"wrong-context"))

    def test_secret_and_message_sizes_checked_before_crypto(self):
        for seed in (bytes(31), bytes(33), "00" * 32):
            with self.assertRaises(ValueError):
                reference.derive_keys(seed)
        for digest in (bytes(31), bytes(33), "00" * 32):
            with self.assertRaises(ValueError):
                reference.sign(self.seed, digest)
            self.assertFalse(reference.verify(self.signed, digest, self.ml, self.schnorr))

    def test_schnorr_rejection_sampling_uses_big_endian_counter_without_modulo(self):
        results = [bytes(32), bytes(32), reference.bip340.n.to_bytes(32, "big"),
                   (reference.bip340.n + 1).to_bytes(32, "big"), (2).to_bytes(32, "big")]
        with patch.object(reference.hmac, "digest", side_effect=results) as hmac_digest:
            _, _, secret = reference._private_keys(self.seed)
        self.assertEqual(secret, (2).to_bytes(32, "big"))
        self.assertEqual(hmac_digest.call_args_list[0].args, (self.seed, b"QLU/ML-DSA-65/seed/v1", "sha256"))
        for counter, call in enumerate(hmac_digest.call_args_list[1:]):
            self.assertEqual(call.args, (self.seed, b"QLU/BIP340/secret/v1" + struct.pack(">I", counter), "sha256"))


if __name__ == "__main__":
    unittest.main()
