"""Original-byte outbox validation and network preflight, with synthetic keys."""
import copy
from contextlib import nullcontext
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import payment_resume as resume
import wallet_app_network as app
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness
from test_framework.segwit_addr import encode_segwit_address

TAG = hashlib.sha256(b"QLU/key-commitment/v1").digest()
OWN = b"\x52\x20" + hashlib.sha256(TAG + TAG + b"\x01" + b"a" * 1952 + b"b" * 32).digest()
TARGET = b"\x52\x20" + b"c" * 32
TIP = "ab" * 32
BLOCK = "bc" * 32


def fixture():
    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(123, 0))]
    tx.vout = [CTxOut(10_000_000, TARGET), CTxOut(89_900_000, OWN)]
    wit = CTxInWitness()
    # Structural fixtures only. Live drills verify actual dual signatures.
    wit.scriptWitness.stack = [b"a" * 1952, b"b" * 32, b"s" * 3309, b"t" * 64]
    tx.wit.vtxinwit = [wit]
    return {"operation_id": "12" * 16, "kind": "send", "status": "pending", "start_height": 100,
            "txid": tx.txid_hex, "transaction": tx.serialize_without_witness().hex(),
            "signed_transaction": tx.serialize_with_witness().hex(),
            "spent_outputs": [{"value": 100_000_000, "script": OWN.hex()}],
            "recipient": encode_segwit_address("qlud", 2, TARGET[2:]),
            "amount": "0.10000000", "fee": "0.00100000"}


class OutboxValidationTests(unittest.TestCase):
    def test_valid_send_and_funding_identity(self):
        record = fixture()
        self.assertEqual(resume.validate_resume_record(record, OWN).txid_hex, record["txid"])
        self.assertTrue(resume.locally_resumable(record))
        with self.assertRaises(ValueError):
            resume.validate_resume_record(record, TARGET)
        record["kind"] = "funding"
        resume.validate_resume_record(record, TARGET)
        with self.assertRaises(ValueError):
            resume.validate_resume_record(record, OWN)

    def test_legacy_and_monotonic_conflict_confirmation_markers_exclude_resume(self):
        for changes in ({"status": "confirmed"}, {"status": "not_sent"}, {"block": BLOCK},
                        {"conflict": {}}, {"kind": "receive"}, {"signed_transaction": None}):
            with self.subTest(changes=changes):
                self.assertFalse(resume.locally_resumable({**fixture(), **changes}))

    def test_bad_encoding_intent_prevouts_and_extra_fields_fail_closed(self):
        valid = fixture()
        cases = [{"signed_transaction": valid["signed_transaction"] + "00"},
                 {"signed_transaction": valid["signed_transaction"].upper()},
                 {"signed_transaction": "00" * (resume.MAX_SIGNED_HEX // 2 + 1)},
                 {"transaction": valid["transaction"] + "00"}, {"txid": "ff" * 32},
                 {"amount": "0.20000000"}, {"amount": "1e-1"}, {"fee": "0.00200000"},
                 {"recipient": valid["recipient"].upper()}, {"spent_outputs": []},
                 {"spent_outputs": [{"value": True, "script": OWN.hex()}]},
                 {"spent_outputs": [{"value": 100_000_001, "script": OWN.hex()}]},
                 {"spent_outputs": [{"value": 100_000_000, "script": TARGET.hex()}]},
                 {"spent_outputs": [{"value": 100_000_000, "script": OWN.hex(), "extra": 1}]}]
        for changes in cases:
            with self.subTest(fields=tuple(changes)), self.assertRaises(ValueError):
                resume.validate_resume_record({**valid, **changes})

    def test_witness_shape_commitment_and_unsigned_binding(self):
        valid = fixture()
        for mutate in (lambda tx: tx.wit.vtxinwit[0].scriptWitness.stack.pop(),
                       lambda tx: tx.wit.vtxinwit[0].scriptWitness.stack.__setitem__(0, b"z" * 1952),
                       lambda tx: tx.vout[0].__setattr__("nValue", 10_000_001),
                       lambda tx: tx.vin[0].__setattr__("scriptSig", b"x")):
            tx = resume.validate_resume_record(valid)
            mutate(tx)
            with self.assertRaises(ValueError):
                resume.validate_resume_record({**valid, "signed_transaction": tx.serialize_with_witness().hex()})


class ResumeController:
    def __init__(self, record):
        self.record = record
        self.tip, self.height = TIP, 100
        self.pools = [False] * 4
        self.broadcasts, self.mines, self.checks = [], 0, []
        self.reject = self.bad_input = self.bad_raw = self.offline = None
        self.accept_then_timeout = False

    def rpc_budget(self, deadline):
        return nullcontext()

    def wait_synced(self, block):
        assert self.tip == block

    def rpc(self, index, method, *args):
        if self.offline == index:
            raise RuntimeError("Synthetic offline node")
        if method == "getblockcount":
            return self.height
        if method == "getbestblockhash":
            return self.tip
        if method == "getrawmempool":
            return [self.record["txid"]] if self.pools[index] else []
        if method == "getrawtransaction":
            if not self.pools[index]:
                raise RuntimeError("Synthetic missing transaction")
            return self.record["signed_transaction"] + ("00" if self.bad_raw == index else "")
        if method == "gettxout":
            self.checks.append((index, args[2]))
            if self.tip == BLOCK or self.bad_input == index or args[2] and self.pools[index]:
                return None
            return {"value": "1.00000000", "scriptPubKey": {"hex": OWN.hex()},
                    "bestblock": TIP, "confirmations": 100, "coinbase": False}
        if method == "testmempoolaccept":
            assert args == ([self.record["signed_transaction"]],)
            return [{"allowed": index != self.reject}]
        if method == "sendrawtransaction":
            assert args == (self.record["signed_transaction"],)
            self.broadcasts.append((index, args[0]))
            self.pools[index] = True
            if self.accept_then_timeout:
                raise TimeoutError("Synthetic lost accepted response")
            return self.record["txid"]
        if method == "generateblock":
            assert args[1] == [self.record["txid"]]
            self.mines += 1
            self.tip, self.height = BLOCK, 101
            return {"hash": BLOCK}
        raise AssertionError(method)


class NetworkResumeTests(unittest.TestCase):
    def setUp(self):
        self.record = fixture()
        self.network = app.WalletAppNetwork()
        self.controller = ResumeController(self.record)
        self.network.controller = self.controller
        self.network._validate = lambda: self.controller.tip
        self.network._ensure_faucet = Mock(return_value="synthetic-mining-address")
        self.network.payment_status = Mock(side_effect=lambda record, finish=False: {
            **{k: record[k] for k in ("txid", "amount", "fee", "recipient", "start_height")},
            "status": "confirmed", "block": BLOCK, "confirmed_nodes": 4})

    def test_resume_reuses_exact_original_bytes_without_any_signer(self):
        prepared = self.network.prepare_resume(self.record, OWN)
        self.assertEqual(self.controller.broadcasts, [])
        for private in ("signed_transaction", "spent_outputs", "transaction"):
            self.assertNotIn(private, prepared.public())
        guard = Mock()
        with patch.object(app.protocol, "sign_transaction", side_effect=AssertionError("Must never sign")):
            receipt = self.network.resume(prepared, before_broadcast=guard)
        self.assertEqual(receipt["txid"], self.record["txid"])
        self.assertEqual(len(self.controller.broadcasts), 4)
        self.assertEqual({raw for _, raw in self.controller.broadcasts}, {self.record["signed_transaction"]})
        self.assertEqual(guard.call_count, 2)
        self.assertEqual(self.controller.mines, 1)
        with self.assertRaises(app.NetworkError):
            self.network.resume(prepared, before_broadcast=guard)
        self.assertEqual(self.controller.mines, 1)

    def test_partly_pooled_and_accepted_timeout_preserve_one_transaction(self):
        self.controller.pools = [True, False, True, False]
        self.controller.accept_then_timeout = True
        prepared = self.network.prepare_resume(self.record, OWN)
        self.network.resume(prepared, before_broadcast=lambda: None)
        self.assertEqual([index for index, _ in self.controller.broadcasts], [1, 3])
        self.assertEqual(self.controller.mines, 1)
        self.assertNotIn((0, True), self.controller.checks)
        self.assertIn((1, True), self.controller.checks)

    def test_all_pooled_needs_no_rebroadcast(self):
        self.controller.pools = [True] * 4
        prepared = self.network.prepare_resume(self.record, OWN)
        self.network.resume(prepared, before_broadcast=lambda: None)
        self.assertEqual(self.controller.broadcasts, [])
        self.assertEqual(self.controller.mines, 1)

    def test_offline_rejection_input_conflict_or_different_witness_fail_before_broadcast(self):
        for attribute in ("offline", "reject", "bad_input", "bad_raw"):
            with self.subTest(attribute=attribute):
                setattr(self.controller, attribute, 3)
                self.controller.pools = [False, False, False, attribute == "bad_raw"]
                with self.assertRaises(app.NetworkError):
                    self.network.prepare_resume(self.record, OWN)
                setattr(self.controller, attribute, None)
        self.assertEqual(self.controller.broadcasts, [])
        self.assertEqual(self.controller.mines, 0)

    def test_chain_change_and_history_guard_prevent_stale_submission(self):
        prepared = self.network.prepare_resume(self.record, OWN)
        self.controller.height += 1
        with self.assertRaises(app.NetworkError):
            self.network.resume(prepared, before_broadcast=lambda: None)
        self.controller.height -= 1
        with self.assertRaises(app.NetworkError) as caught:
            self.network.resume(prepared, before_broadcast=Mock(side_effect=ValueError("changed history")))
        self.assertEqual(caught.exception.code, "history_failed")
        self.assertEqual(self.controller.broadcasts, [])

    def test_original_caller_mutation_cannot_change_frozen_review(self):
        prepared = self.network.prepare_resume(self.record, OWN)
        changed = copy.deepcopy(self.record)
        changed["amount"] = "0.90000000"
        self.assertEqual(prepared.public()["amount"], "0.10000000")
        with self.assertRaises(app.NetworkError):
            self.network.prepare_resume(changed, OWN)
        other = app.WalletAppNetwork()
        other.controller = self.controller
        with self.assertRaises(app.NetworkError) as caught:
            other.resume(prepared, before_broadcast=lambda: None)
        self.assertEqual(caught.exception.code, "resume_invalid")


if __name__ == "__main__":
    unittest.main()
