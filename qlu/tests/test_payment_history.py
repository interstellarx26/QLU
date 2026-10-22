"""Durable public payment metadata only; no real wallets, keys, or test nodes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from qlu import payment_history as history
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut

WALLET = "11" * 32
OTHER = "22" * 32
TXID = "33" * 32
BLOCK = "44" * 32
DETAILS = {"recipient": "synthetic private recipient", "amount": "0.1", "fee": "0.001"}
BROADCAST = {**DETAILS, "txid": TXID, "start_height": 100}
RECEIPT = {**BROADCAST, "block": BLOCK, "confirmed_nodes": 4}
RECEIVED = {key: value for key, value in RECEIPT.items() if key != "fee"}
RECEIVED["recipient"] = history.protocol.address_for({"key_commitment": WALLET})
ORIGINAL = CTransaction()
ORIGINAL.vin = [CTxIn(COutPoint(int("55" * 32, 16), 2), nSequence=0xffffffff)]
ORIGINAL.vout = [CTxOut(10_000_000, history.protocol.script_for({"key_commitment": WALLET}))]
TRANSACTION = ORIGINAL.serialize_without_witness().hex()
CONFLICT_BROADCAST = {**BROADCAST, "txid": ORIGINAL.txid_hex, "transaction": TRANSACTION}
CONFLICT_PROOF = {"txid": "66" * 32, "block": "77" * 32, "height": 101,
                  "input": {"txid": "55" * 32, "vout": 2}}
CONFLICT_STATUS = {**CONFLICT_BROADCAST, "status": "conflicted", "conflict": CONFLICT_PROOF,
                   "confirmed_nodes": 4}


def make_outbox(keys=None, recipient=None):
    """Structurally valid synthetic signatures; deliberately not broadcastable.

    The real-node suite verifies cryptography separately. No private key is
    needed to test durable byte preservation and public-output redaction here.
    """
    if keys is None:
        ml, schnorr = b"\x11" * 1952, b"\x22" * 32
        tag = hashlib.sha256(b"QLU/key-commitment/v1").digest()
        keys = {"mldsa_public": ml.hex(), "schnorr_public": schnorr.hex(),
                "key_commitment": hashlib.sha256(tag + tag + b"\x01" + ml + schnorr).hexdigest()}
    own = history.protocol.script_for(keys)
    recipient = recipient or history.protocol.address_for(keys)
    from test_framework.segwit_addr import decode_segwit_address
    _, program = decode_segwit_address("qlud", recipient)
    transaction = CTransaction()
    transaction.vin = [CTxIn(COutPoint(int("55" * 32, 16), 2), nSequence=0xffffffff)]
    transaction.vout = [CTxOut(10_000_000, b"\x52\x20" + bytes(program)), CTxOut(20_000_000, own)]
    witness = CTxInWitness()
    witness.scriptWitness.stack = [bytes.fromhex(keys["mldsa_public"]), bytes.fromhex(keys["schnorr_public"]),
                                   b"\x33" * 3309, b"\x44" * 64]
    transaction.wit.vtxinwit = [witness]
    return {"txid": transaction.txid_hex, "recipient": recipient, "amount": "0.10000000", "fee": "0.00100000",
            "start_height": 100, "transaction": transaction.serialize_without_witness().hex(),
            "signed_transaction": transaction.serialize_with_witness().hex(),
            "spent_outputs": [{"value": 30_100_000, "script": own.hex()}]}


class PaymentHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name).resolve()
        self.directory = self.parent / "payment-history"
        self.store = history.PaymentHistory(self.directory, WALLET)
        self.path = self.directory / (WALLET + ".json")

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def reopen(self):
        self.store.close()
        self.store = history.PaymentHistory(self.directory, WALLET)

    def pending(self):
        operation = self.store.begin("send", **DETAILS)
        self.store.before_broadcast(operation, BROADCAST)
        return operation

    def confirmed(self):
        operation = self.pending()
        self.store.finish(operation, RECEIPT)
        return operation

    def unavailable(self, function, *args, **kwargs):
        with self.assertRaises(history.HistoryError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, "history_unavailable")
        self.assertEqual(str(raised.exception), history.MESSAGES["history_unavailable"])

    def pending_outbox(self):
        data = make_outbox()
        operation = self.store.begin("send", **{key: data[key] for key in ("recipient", "amount", "fee")})
        self.store.before_broadcast(operation, data)
        return operation, data

    def test_signed_outbox_is_durable_immutable_and_never_public(self):
        operation, data = self.pending_outbox()
        before = self.path.read_bytes()
        self.store.assert_resume(operation, data["signed_transaction"])
        self.assertEqual(self.path.read_bytes(), before)
        self.reopen()
        entry = self.store.records()[0]
        for field in ("txid", "transaction", "signed_transaction", "spent_outputs"):
            self.assertEqual(entry[field], data[field])
        public = self.store.public_records()[0]
        self.assertTrue(public["resume_available"])
        for field in ("transaction", "signed_transaction", "spent_outputs", "start_height"):
            self.assertNotIn(field, public)
        self.assertTrue(self.store.blocked)
        self.unavailable(self.store.begin, "send", operation_id=operation)

    def test_signed_outbox_requires_complete_valid_pair_before_broadcast(self):
        data = make_outbox()
        variants = [
            {key: value for key, value in data.items() if key != "signed_transaction"},
            {key: value for key, value in data.items() if key != "spent_outputs"},
            {key: value for key, value in data.items() if key != "transaction"},
            {**data, "signed_transaction": data["transaction"]},
            {**data, "signed_transaction": data["signed_transaction"] + "00"},
            {**data, "spent_outputs": [{"value": 1, "script": data["spent_outputs"][0]["script"]}]},
            {**data, "spent_outputs": [{**data["spent_outputs"][0], "seed": "forbidden"}]},
        ]
        for invalid in variants:
            operation = self.store.begin("send")
            self.unavailable(self.store.before_broadcast, operation, invalid)
            self.assertEqual(self.store.records()[-1]["status"], "preparing")
            self.store.fail_before_broadcast(operation)

    def test_update_cannot_change_witness_bytes_or_spent_outputs(self):
        operation, data = self.pending_outbox()
        raw = data["signed_transaction"]
        # Change a signature byte while preserving the original non-witness txid.
        changed = raw.replace("33" * 3309, "34" + "33" * 3308, 1)
        self.assertNotEqual(changed, raw)
        before = self.path.read_bytes()
        for field, value in (("signed_transaction", changed),
                             ("spent_outputs", [{**data["spent_outputs"][0], "value": 30_200_000}])):
            self.unavailable(self.store.update, operation, {"status": "pending", field: value})
            self.assertEqual(self.path.read_bytes(), before)
        self.unavailable(self.store.assert_resume, operation, changed)

    def test_legacy_record_cannot_acquire_signed_outbox_after_broadcast(self):
        data = make_outbox()
        operation = self.store.begin("send")
        self.store.before_broadcast(operation, {key: value for key, value in data.items()
                                               if key not in {"signed_transaction", "spent_outputs"}})
        self.unavailable(self.store.update, operation, {"status": "pending", **data})
        self.assertFalse(self.store.public_records()[0]["resume_available"])
        self.unavailable(self.store.assert_resume, operation, data["signed_transaction"])

    def test_confirmed_outbox_stays_ineligible_after_reorg_and_restart(self):
        operation, data = self.pending_outbox()
        self.store.finish(operation, {**data, "block": BLOCK, "confirmed_nodes": 4})
        self.store.update(operation, {"status": "pending", "status_reason": "not_found"})
        self.reopen()
        self.assertEqual(self.store.records()[0]["block"], BLOCK)
        self.assertFalse(self.store.public_records()[0]["resume_available"])
        self.unavailable(self.store.assert_resume, operation, data["signed_transaction"])
        self.assertTrue(self.store.blocked)

    def test_conflicted_outbox_stays_ineligible_after_reorg_and_restart(self):
        operation, data = self.pending_outbox()
        self.store.update(operation, {**data, "status": "conflicted", "conflict": CONFLICT_PROOF, "confirmed_nodes": 4})
        self.store.update(operation, {"status": "pending", "status_reason": "not_found"})
        self.reopen()
        self.assertEqual(self.store.records()[0]["conflict"], CONFLICT_PROOF)
        self.assertFalse(self.store.public_records()[0]["resume_available"])
        self.unavailable(self.store.assert_resume, operation, data["signed_transaction"])

    def test_v3_migration_preserves_legacy_conflicts_without_creating_outbox(self):
        operation = self.pending_with_transaction()
        self.store.update(operation, CONFLICT_STATUS)
        original = self.make_legacy_journal(version=3)
        self.reopen()
        self.assertEqual(json.loads(self.path.read_bytes())["version"], 4)
        self.assertEqual(self.store.records(), original["records"])
        self.assertFalse(self.store.public_records()[0]["resume_available"])
        self.unavailable(self.store.begin, "send", operation_id=operation)

    def test_v3_rejects_signed_outbox_injection_without_migration(self):
        self.pending_outbox()
        original = self.make_legacy_journal(version=3)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.assertEqual(json.loads(self.path.read_bytes()), original)

    def test_another_outgoing_reorg_blocks_selected_outbox_but_received_pending_does_not(self):
        old = self.pending_with_transaction()
        self.store.update(old, CONFLICT_STATUS)
        operation, data = self.pending_outbox()
        self.store.assert_resume(operation, data["signed_transaction"])
        self.store.update(old, {"status": "pending", "status_reason": "not_found"})
        self.assertFalse(next(row for row in self.store.public_records() if row["operation_id"] == operation)["resume_available"])
        self.unavailable(self.store.assert_resume, operation, data["signed_transaction"])
        self.store.update(old, CONFLICT_STATUS)
        received = self.store.observe_received(RECEIVED)["operation_id"]
        self.store.update(received, {"status": "pending", "status_reason": "not_found"})
        self.store.assert_resume(operation, data["signed_transaction"])
        self.assertTrue(next(row for row in self.store.public_records() if row["operation_id"] == operation)["resume_available"])

    def test_resume_rechecks_journal_storage_before_sending(self):
        operation, data = self.pending_outbox()
        self.path.unlink()
        self.unavailable(self.store.assert_resume, operation, data["signed_transaction"])
        self.assertTrue(self.store.blocked)

    def test_signed_outbox_write_failure_keeps_durable_preparing_marker(self):
        data = make_outbox()
        operation = self.store.begin("send")
        with mock.patch.object(history.os, "replace", side_effect=OSError("synthetic outbox save failure")):
            self.unavailable(self.store.before_broadcast, operation, data)
        self.assertTrue(self.store.blocked)
        self.reopen()
        self.assertEqual(self.store.records()[0]["status"], "not_sent")
        self.assertNotIn("signed_transaction", self.store.records()[0])

    def test_initial_storage_has_strict_modes_and_network_binding(self):
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.directory / (WALLET + ".lock")).stat().st_mode), 0o600)
        document = json.loads(self.path.read_bytes())
        self.assertEqual(document["wallet_id"], WALLET)
        self.assertEqual(document["network_id"], history.protocol.NETWORK)
        self.assertEqual(document["genesis_hash"], history.protocol.GENESIS)
        self.assertEqual(document["version"], 4)
        self.assertFalse(self.store.blocked)

    def make_legacy_journal(self, version=1):
        document = json.loads(self.path.read_bytes())
        self.store.close()
        document["version"] = version
        self.path.write_text(json.dumps(document))
        return document

    def test_v1_migration_preserves_outgoing_identities_and_pending_guards(self):
        confirmed = self.confirmed()
        abandoned = self.store.begin("funding", operation_id="ab" * 16)
        self.store.fail_before_broadcast(abandoned)
        pending = self.pending()
        original = self.make_legacy_journal()
        self.reopen()
        self.assertEqual(json.loads(self.path.read_bytes())["version"], 4)
        self.assertEqual(self.store.records(), original["records"])
        self.assertTrue(self.store.blocked)
        for operation in (confirmed, abandoned, pending):
            self.unavailable(self.store.begin, "send", operation_id=operation)
        with self.assertRaises(history.HistoryError) as raised:
            self.store.begin("funding")
        self.assertEqual(raised.exception.code, "payment_pending")

    def test_v1_migration_applies_only_safe_preparing_crash_recovery(self):
        operation = self.store.begin("send", **DETAILS)
        original = self.make_legacy_journal()
        self.reopen()
        entry = self.store.records()[0]
        self.assertEqual(entry["operation_id"], operation)
        self.assertEqual(entry["status"], "not_sent")
        self.assertEqual(entry["created_at"], original["records"][0]["created_at"])
        self.assertGreaterEqual(entry["updated_at"], original["records"][0]["updated_at"])
        self.assertFalse(self.store.blocked)

    def test_v1_migration_rejects_receive_injection_and_invalid_data_without_reset(self):
        self.store.observe_received(RECEIVED)
        original = self.make_legacy_journal()
        variants = [original]
        for field, value in (("network_id", "mainnet"), ("version", 5), ("version", True)):
            candidate = copy.deepcopy(original)
            candidate[field] = value
            variants.append(candidate)
        for document in variants:
            with self.subTest(field=document["version"], network=document["network_id"]):
                self.path.write_text(json.dumps(document))
                before = self.path.read_bytes()
                self.unavailable(history.PaymentHistory, self.directory, WALLET)
                self.assertEqual(self.path.read_bytes(), before)

    def test_v1_migration_atomic_replace_failure_preserves_prior_pending_journal(self):
        self.pending()
        original = self.make_legacy_journal()
        before = self.path.read_bytes()
        with mock.patch.object(history.os, "replace", side_effect=OSError("synthetic migration failure")):
            self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.assertEqual(self.path.read_bytes(), before)
        self.reopen()
        self.assertEqual(self.store.records(), original["records"])
        self.assertTrue(self.store.blocked)

    def test_v1_migration_directory_sync_failure_after_publish_remains_recoverable(self):
        self.pending()
        original = self.make_legacy_journal()
        fsync = os.fsync

        def fail_directory_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic migration directory sync failure")
            return fsync(fd)

        with mock.patch.object(history.os, "fsync", side_effect=fail_directory_sync):
            self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.assertEqual(json.loads(self.path.read_bytes())["version"], 4)
        self.reopen()
        self.assertEqual(self.store.records(), original["records"])
        self.assertTrue(self.store.blocked)

    def pending_with_transaction(self):
        operation = self.store.begin("send", **DETAILS)
        self.store.before_broadcast(operation, CONFLICT_BROADCAST)
        return operation

    def test_v2_migration_preserves_receive_and_pending_outgoing_records(self):
        self.store.observe_received(RECEIVED)
        outgoing = self.store.begin("send", operation_id="ab" * 16, **DETAILS)
        self.store.before_broadcast(outgoing, {**BROADCAST, "txid": "88" * 32})
        original = self.make_legacy_journal(version=2)
        self.reopen()
        self.assertEqual(json.loads(self.path.read_bytes())["version"], 4)
        self.assertEqual(self.store.records(), original["records"])
        self.assertTrue(self.store.blocked)
        self.unavailable(self.store.begin, "send", operation_id=outgoing)

    def test_v2_rejects_injected_transaction_or_conflict_without_migration(self):
        self.pending_with_transaction()
        original = self.make_legacy_journal(version=2)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.assertEqual(json.loads(self.path.read_bytes()), original)
        original["records"][0].update(status="conflicted", conflict=CONFLICT_PROOF, confirmed_nodes=4)
        self.path.write_text(json.dumps(original))
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.assertEqual(json.loads(self.path.read_bytes()), original)

    def test_conflict_requires_durable_original_and_four_node_proof(self):
        operation = self.pending_with_transaction()
        self.store.update(operation, CONFLICT_STATUS)
        self.assertFalse(self.store.blocked)
        self.reopen()
        entry = self.store.records()[0]
        self.assertEqual(entry["status"], "conflicted")
        self.assertEqual(entry["transaction"], TRANSACTION)
        self.assertEqual(entry["conflict"], CONFLICT_PROOF)
        self.assertEqual(entry["confirmed_nodes"], 4)
        self.assertFalse(self.store.blocked)
        self.unavailable(self.store.begin, "send", operation_id=operation)

    def test_conflicted_reorg_returns_pending_and_preserves_historical_hint(self):
        operation = self.pending_with_transaction()
        self.store.update(operation, CONFLICT_STATUS)
        self.store.update(operation, {"status": "pending", "status_reason": "network_unavailable"})
        self.assertTrue(self.store.blocked)
        entry = self.store.records()[0]
        self.assertEqual(entry["conflict"], CONFLICT_PROOF)
        self.assertNotIn("confirmed_nodes", entry)
        self.reopen()
        self.assertTrue(self.store.blocked)
        self.assertEqual(self.store.records()[0]["transaction"], TRANSACTION)
        self.store.update(operation, CONFLICT_STATUS)
        self.assertFalse(self.store.blocked)
        self.store.finish(operation, {**CONFLICT_BROADCAST, "block": BLOCK, "confirmed_nodes": 4})
        entry = self.store.records()[0]
        self.assertEqual(entry["status"], "confirmed")
        self.assertEqual(entry["conflict"], CONFLICT_PROOF)
        self.assertEqual(entry["block"], BLOCK)

    def test_legacy_record_cannot_gain_conflict_authority_after_broadcast(self):
        operation = self.store.begin("send", **DETAILS)
        legacy = {key: value for key, value in CONFLICT_BROADCAST.items() if key != "transaction"}
        self.store.before_broadcast(operation, legacy)
        before = self.path.read_bytes()
        self.unavailable(self.store.update, operation, CONFLICT_STATUS)
        self.unavailable(self.store.update, operation, {key: value for key, value in CONFLICT_STATUS.items() if key != "transaction"})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.store.blocked)

    def test_conflict_malformed_proof_and_transaction_mutation_do_not_unblock(self):
        operation = self.pending_with_transaction()
        variants = [
            {**CONFLICT_STATUS, "confirmed_nodes": 3},
            {**CONFLICT_STATUS, "confirmed_nodes": True},
            {**CONFLICT_STATUS, "transaction": TRANSACTION + "00"},
            {**CONFLICT_STATUS, "status_reason": "not_found"},
        ]
        for field, value in (("txid", ORIGINAL.txid_hex), ("height", True), ("height", -1),
                             ("block", "not-a-block"), ("raw_transaction", "forbidden"),
                             ("input", {"txid": "88" * 32, "vout": 2}),
                             ("input", {"txid": "55" * 32, "vout": 3})):
            variants.append({**CONFLICT_STATUS, "conflict": {**CONFLICT_PROOF, field: value}})
        before = self.path.read_bytes()
        for status in variants:
            self.unavailable(self.store.update, operation, status)
            self.assertEqual(self.path.read_bytes(), before)
            self.assertTrue(self.store.blocked)

    def test_pending_update_cannot_introduce_or_replace_conflict_hint(self):
        operation = self.pending_with_transaction()
        self.unavailable(self.store.update, operation, {"status": "pending", "conflict": CONFLICT_PROOF})
        self.store.update(operation, CONFLICT_STATUS)
        changed = {**CONFLICT_PROOF, "txid": "99" * 32}
        self.unavailable(self.store.update, operation, {"status": "pending", "conflict": changed})
        self.assertEqual(self.store.records()[0]["conflict"], CONFLICT_PROOF)

    def test_non_witness_transaction_is_bounded_txid_bound_and_never_public(self):
        for transaction in (TRANSACTION + "00", TRANSACTION.upper(), "00" * 8193, "bad-encoding"):
            operation = self.store.begin("send", **DETAILS)
            self.unavailable(self.store.before_broadcast, operation, {**CONFLICT_BROADCAST, "transaction": transaction})
            self.store.fail_before_broadcast(operation)
        operation = self.pending_with_transaction()
        self.assertNotIn("transaction", self.store.public_records()[0])
        self.assertEqual(self.store.records()[-1]["transaction"], TRANSACTION)
        self.store.update(operation, CONFLICT_STATUS)
        self.assertNotIn("transaction", self.store.public_records()[0])

    def test_conflict_write_failure_cannot_report_unblocked(self):
        operation = self.pending_with_transaction()
        with mock.patch.object(history.os, "replace", side_effect=OSError("synthetic conflict write failure")):
            self.unavailable(self.store.update, operation, CONFLICT_STATUS)
        self.assertTrue(self.store.blocked)
        self.reopen()
        self.assertTrue(self.store.blocked)
        self.assertEqual(self.store.records()[0]["status"], "pending")

    def test_receive_cannot_store_transaction_or_conflict(self):
        operation = self.store.observe_received(RECEIVED)["operation_id"]
        self.unavailable(self.store.update, operation, CONFLICT_STATUS)
        self.unavailable(self.store.update, operation, {**RECEIVED, "status": "confirmed", "transaction": TRANSACTION})

    def test_received_observation_is_durable_without_recipient_fee(self):
        receipt = self.store.observe_received(RECEIVED)
        self.assertEqual(receipt["kind"], "receive")
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["amount"], "0.10000000")
        self.assertNotIn("fee", receipt)
        receipt["amount"] = "modified copy"
        self.reopen()
        entry = self.store.records()[0]
        self.assertEqual(entry["amount"], "0.10000000")
        self.assertNotIn("fee", entry)
        self.assertNotIn("fee", self.store.public_records()[0])
        self.assertNotIn("start_height", self.store.public_records()[0])
        self.assertFalse(self.store.blocked)

    def test_received_observation_deduplicates_stably_without_another_write(self):
        first = self.store.observe_received(RECEIVED)
        self.reopen()
        before = self.path.read_bytes()
        with mock.patch.object(history.os, "replace", side_effect=AssertionError("duplicate receive write")):
            second = self.store.observe_received({**RECEIVED, "status": "confirmed"})
        self.assertEqual(first, second)
        self.assertEqual(self.path.read_bytes(), before)
        with history.PaymentHistory(self.directory, OTHER) as other:
            other_receipt = {**RECEIVED, "recipient": history.protocol.address_for({"key_commitment": OTHER})}
            self.assertEqual(other.observe_received(other_receipt)["operation_id"], first["operation_id"])

    def test_received_recipient_must_match_this_journals_wallet(self):
        other_address = history.protocol.address_for({"key_commitment": OTHER})
        before = self.path.read_bytes()
        self.unavailable(self.store.observe_received, {**RECEIVED, "recipient": other_address})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.store.records(), [])
        # Even a duplicate outgoing txid cannot admit another wallet's receipt.
        self.pending()
        before = self.path.read_bytes()
        self.unavailable(self.store.observe_received, {**RECEIVED, "recipient": other_address})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.store.blocked)

    def test_received_recipient_is_checked_when_loading_confirmed_and_pending_records(self):
        self.store.observe_received(RECEIVED)
        document = json.loads(self.path.read_bytes())
        self.store.close()
        document["records"][0]["recipient"] = history.protocol.address_for({"key_commitment": OTHER})
        for status in ("confirmed", "pending"):
            with self.subTest(status=status):
                document["records"][0]["status"] = status
                self.path.write_text(json.dumps(document))
                before = self.path.read_bytes()
                self.unavailable(history.PaymentHistory, self.directory, WALLET)
                self.assertEqual(self.path.read_bytes(), before)

    def test_received_observation_deduplicates_existing_send_and_funding(self):
        for kind in ("send", "funding"):
            for confirmed in (False, True):
                with self.subTest(kind=kind, confirmed=confirmed):
                    directory = self.parent / (kind + str(confirmed))
                    with history.PaymentHistory(directory, WALLET) as store:
                        operation = store.begin(kind)
                        store.before_broadcast(operation, BROADCAST)
                        if confirmed:
                            store.finish(operation, RECEIPT)
                        before = store.records()[0]
                        with mock.patch.object(history.os, "replace", side_effect=AssertionError("self duplicate write")):
                            observed = store.observe_received(RECEIVED)
                        self.assertEqual(observed, before)
                        self.assertEqual(len(store.records()), 1)
                        self.assertEqual(store.blocked, not confirmed)

    def test_received_reorganization_never_blocks_unrelated_outgoing_payment(self):
        operation = self.store.observe_received(RECEIVED)["operation_id"]
        for reason in history.REASONS:
            self.store.update(operation, {"status": "pending", "status_reason": reason})
            self.assertFalse(self.store.blocked)
        self.reopen()
        self.assertFalse(self.store.blocked)
        self.assertEqual(self.store.records()[0]["block"], BLOCK)
        outgoing = self.store.begin("send", recipient="another recipient", amount="0.2")
        self.assertTrue(self.store.blocked)
        self.store.fail_before_broadcast(outgoing)
        receipt = self.store.observe_received({**RECEIVED, "block": "55" * 32, "start_height": 101})
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["block"], "55" * 32)
        self.assertEqual(receipt["start_height"], RECEIVED["start_height"])
        self.assertNotIn("status_reason", receipt)
        self.assertFalse(self.store.blocked)

    def test_received_observation_does_not_clear_existing_outgoing_block(self):
        self.pending()
        received = self.store.observe_received({**RECEIVED, "txid": "77" * 32})
        self.assertEqual(received["kind"], "receive")
        self.assertEqual(len(self.store.records()), 2)
        self.assertTrue(self.store.blocked)
        self.store.update(received["operation_id"], {"status": "pending", "status_reason": "not_found"})
        self.assertTrue(self.store.blocked)

    def test_received_requires_strict_four_node_receipt_without_fee_or_secrets(self):
        variants = []
        for field, value in (("fee", "0.001"), ("confirmed_nodes", 3), ("confirmed_nodes", True),
                             ("amount", "0"), ("txid", "invalid"), ("block", "invalid"),
                             ("recipient", "bad\naddress"), ("start_height", True),
                             ("status", "pending"), ("status_reason", "mempool"),
                             ("master_seed", "forbidden"), ("kind", "receive")):
            variants.append({**RECEIVED, field: value})
        variants.extend({key: value for key, value in RECEIVED.items() if key != removed}
                        for removed in RECEIVED)
        before = self.path.read_bytes()
        for receipt in variants:
            self.unavailable(self.store.observe_received, receipt)
            self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.store.records(), [])

    def test_received_reconciliation_preserves_identity_and_rejects_fee(self):
        operation = self.store.observe_received(RECEIVED)["operation_id"]
        before = self.path.read_bytes()
        for field, value in (("txid", "77" * 32), ("recipient", "different recipient"),
                             ("amount", "0.2"), ("start_height", 101), ("fee", "0.001")):
            with self.subTest(field=field):
                receipt = {**RECEIVED, field: value, "status": "confirmed"}
                self.unavailable(self.store.update, operation, receipt)
                if field not in ("txid", "start_height"):
                    self.unavailable(self.store.observe_received, receipt)
                self.assertEqual(self.path.read_bytes(), before)
        self.unavailable(self.store.update, operation, {"status": "pending", "fee": "0"})
        self.unavailable(self.store.update, operation, {"status": "not_sent"})

    def test_received_observations_cannot_enter_outgoing_authorization_methods(self):
        self.unavailable(self.store.begin, "receive")
        operation = self.store.observe_received(RECEIVED)["operation_id"]
        before = self.path.read_bytes()
        self.unavailable(self.store.before_broadcast, operation, BROADCAST)
        self.unavailable(self.store.finish, operation, RECEIVED)
        self.unavailable(self.store.fail_before_broadcast, operation)
        self.assertEqual(self.path.read_bytes(), before)

    def test_received_operation_collision_does_not_overwrite_outgoing_identity(self):
        operation = history._receive_operation(TXID)
        self.store.begin("send", operation_id=operation)
        self.store.fail_before_broadcast(operation)
        before = self.path.read_bytes()
        self.unavailable(self.store.observe_received, RECEIVED)
        self.assertEqual(self.path.read_bytes(), before)

    def test_received_schema_rejects_invalid_states_and_duplicate_transaction(self):
        self.store.observe_received(RECEIVED)
        original = json.loads(self.path.read_bytes())
        self.store.close()
        variants = []
        for field, value in (("status", "preparing"), ("status", "not_sent"),
                             ("fee", "0.00100000"), ("operation_id", "ab" * 16)):
            document = copy.deepcopy(original)
            document["records"][0][field] = value
            variants.append(document)
        for outgoing_first in (False, True):
            document = copy.deepcopy(original)
            duplicate = {**document["records"][0], "kind": "send", "operation_id": "ab" * 16,
                         "fee": "0.00100000"}
            document["records"].insert(0 if outgoing_first else 1, duplicate)
            variants.append(document)
        for document in variants:
            self.path.write_text(json.dumps(document))
            before = self.path.read_bytes()
            self.unavailable(history.PaymentHistory, self.directory, WALLET)
            self.assertEqual(self.path.read_bytes(), before)

    def test_received_capacity_keeps_existing_records_and_still_deduplicates(self):
        with mock.patch.object(history, "MAX_RECORDS", 1):
            first = self.store.observe_received(RECEIVED)
            before = self.path.read_bytes()
            with self.assertRaises(history.HistoryError) as raised:
                self.store.observe_received({**RECEIVED, "txid": "77" * 32})
            self.assertEqual(raised.exception.code, "history_full")
            self.assertEqual(self.store.observe_received(RECEIVED), first)
            self.assertEqual(self.path.read_bytes(), before)

    def test_confirmed_lifecycle_survives_restart(self):
        operation = self.confirmed()
        self.assertFalse(self.store.blocked)
        self.reopen()
        record = self.store.records()[0]
        self.assertEqual(record["operation_id"], operation)
        self.assertEqual(record["status"], "confirmed")
        self.assertEqual(record["txid"], TXID)
        self.assertEqual(record["block"], BLOCK)
        self.assertEqual(record["amount"], "0.10000000")
        self.assertFalse(self.store.blocked)

    def test_pending_survives_reopen_and_blocks_new_payment(self):
        self.pending()
        self.reopen()
        self.assertTrue(self.store.blocked)
        with self.assertRaises(history.HistoryError) as raised:
            self.store.begin("funding")
        self.assertEqual(raised.exception.code, "payment_pending")
        self.assertNotIn("block", self.store.records()[0])

    def test_preparing_crash_marker_recovers_as_not_sent(self):
        operation = self.store.begin("send", **DETAILS)
        self.assertTrue(self.store.blocked)
        self.reopen()
        self.assertEqual(self.store.records()[0]["operation_id"], operation)
        self.assertEqual(self.store.records()[0]["status"], "not_sent")
        self.assertFalse(self.store.blocked)
        self.reopen()
        self.assertEqual(self.store.records()[0]["status"], "not_sent")

    def abruptly_exit_writer(self, after_broadcast_marker):
        directory = self.parent / "abrupt-writer"
        script = """
from pathlib import Path
import os
import sys
from qlu.payment_history import PaymentHistory
store = PaymentHistory(Path(sys.argv[1]), sys.argv[2])
operation = store.begin('send', operation_id='ef' * 16,
                        recipient='synthetic private recipient', amount='0.1', fee='0.001')
if sys.argv[3] == 'pending':
    store.before_broadcast(operation, {'txid': '33' * 32, 'recipient': 'synthetic private recipient',
                                      'amount': '0.1', 'fee': '0.001', 'start_height': 100})
os._exit(17)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(directory), WALLET,
             "pending" if after_broadcast_marker else "preparing"],
            cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        return directory

    def test_abrupt_process_exit_after_begin_reopens_not_sent(self):
        directory = self.abruptly_exit_writer(False)
        with history.PaymentHistory(directory, WALLET) as recovered:
            self.assertEqual(recovered.records()[0]["status"], "not_sent")
            self.assertEqual(recovered.records()[0]["operation_id"], "ef" * 16)
            self.assertFalse(recovered.blocked)

    def test_abrupt_process_exit_after_broadcast_marker_reopens_blocked(self):
        directory = self.abruptly_exit_writer(True)
        with history.PaymentHistory(directory, WALLET) as recovered:
            self.assertEqual(recovered.records()[0]["status"], "pending")
            self.assertEqual(recovered.records()[0]["txid"], TXID)
            self.assertTrue(recovered.blocked)
            with self.assertRaises(history.HistoryError) as raised:
                recovered.begin("funding")
            self.assertEqual(raised.exception.code, "payment_pending")

    def test_not_sent_only_before_broadcast(self):
        first = self.store.begin("send")
        self.store.fail_before_broadcast(first)
        self.assertEqual(self.store.records()[0]["status"], "not_sent")
        second = self.pending()
        self.store.fail_before_broadcast(second)
        self.assertEqual(self.store.records()[1]["status"], "pending")
        self.assertTrue(self.store.blocked)
        self.store.finish(second, RECEIPT)
        self.store.fail_before_broadcast(second)
        self.assertEqual(self.store.records()[1]["status"], "confirmed")

    def test_supplied_operation_id_is_unique_and_never_reused(self):
        operation = "ab" * 16
        self.assertEqual(self.store.begin("send", operation_id=operation), operation)
        self.store.fail_before_broadcast(operation)
        self.unavailable(self.store.begin, "send", operation_id=operation)
        self.assertEqual(len(self.store.records()), 1)

    def test_before_broadcast_rejects_changed_intent(self):
        for field, replacement in (("recipient", "different recipient"), ("amount", "0.2"), ("fee", "0.002")):
            with self.subTest(field=field):
                operation = self.store.begin("send", **DETAILS)
                self.unavailable(self.store.before_broadcast, operation, {**BROADCAST, field: replacement})
                self.assertEqual(self.store.records()[-1]["status"], "preparing")
                self.store.fail_before_broadcast(operation)

    def test_finish_requires_durable_transaction_and_exact_intent(self):
        operation = self.pending()
        changes = {"txid": "ff" * 32, "recipient": "different recipient", "amount": "0.2",
                   "fee": "0.002", "start_height": 101, "confirmed_nodes": 3}
        for field, replacement in changes.items():
            with self.subTest(field=field):
                self.unavailable(self.store.finish, operation, {**RECEIPT, field: replacement})
                self.assertEqual(self.store.records()[0]["status"], "pending")
        self.assertTrue(self.store.blocked)

    def test_records_are_copies_and_public_records_are_bounded_newest_first(self):
        first = self.confirmed()
        second = self.confirmed()
        copied = self.store.records()
        copied[0]["status"] = "not_sent"
        public = self.store.public_records(1)
        self.assertEqual(public[0]["operation_id"], second)
        self.assertNotIn("start_height", public[0])
        self.assertEqual(self.store.records()[0]["operation_id"], first)
        self.assertEqual(self.store.records()[0]["status"], "confirmed")

    def test_absence_never_makes_a_payment_safe_to_retry(self):
        operation = self.pending()
        for reason in history.REASONS:
            self.store.update(operation, {**BROADCAST, "status": "pending", "status_reason": reason})
            self.assertTrue(self.store.blocked)
            self.assertEqual(self.store.records()[0]["status"], "pending")
        self.unavailable(self.store.update, operation, {"status": "not_sent"})

    def test_reorganization_reopens_confirmed_payment_as_pending(self):
        operation = self.confirmed()
        self.store.update(operation, {**BROADCAST, "status": "pending", "status_reason": "not_found"})
        self.assertTrue(self.store.blocked)
        self.assertEqual(self.store.records()[0]["block"], BLOCK)
        self.assertNotIn("confirmed_nodes", self.store.records()[0])
        self.store.finish(operation, {**RECEIPT, "block": "55" * 32})
        self.assertFalse(self.store.blocked)
        self.assertEqual(self.store.records()[0]["block"], "55" * 32)

    def test_transient_failure_preserves_confirmed_block_hint_across_restart(self):
        operation = self.confirmed()
        self.store.update(operation, {**BROADCAST, "status": "pending", "status_reason": "network_unavailable"})
        self.reopen()
        self.assertEqual(self.store.records()[0]["block"], BLOCK)
        self.assertEqual(self.store.records()[0]["status"], "pending")
        self.assertTrue(self.store.blocked)
        self.store.update(operation, {**BROADCAST, "status": "pending", "status_reason": "scan_limit"})
        self.assertEqual(self.store.records()[0]["block"], BLOCK)
        self.store.finish(operation, RECEIPT)
        self.assertFalse(self.store.blocked)

    def test_unchanged_reconciliation_does_not_write_or_touch_timestamp(self):
        operation = self.pending()
        pending = {**BROADCAST, "status": "pending", "status_reason": "mempool"}
        self.store.update(operation, pending)
        before = self.path.read_bytes()
        with mock.patch.object(history.os, "replace", side_effect=AssertionError("unnecessary write")):
            self.store.update(operation, pending)
        self.assertEqual(self.path.read_bytes(), before)
        self.store.finish(operation, RECEIPT)
        before = self.path.read_bytes()
        with mock.patch.object(history.os, "replace", side_effect=AssertionError("unnecessary write")):
            self.store.finish(operation, RECEIPT)
        self.assertEqual(self.path.read_bytes(), before)

    def test_failed_atomic_replace_poisoned_instance_cannot_resume(self):
        before = self.path.read_bytes()
        with mock.patch.object(history.os, "replace", side_effect=OSError("synthetic write failure")):
            self.unavailable(self.store.begin, "send", **DETAILS)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.store.blocked)
        self.unavailable(self.store.begin, "send")
        self.unavailable(self.store.records)
        self.reopen()
        self.assertEqual(self.store.records(), [])

    def test_failed_broadcast_marker_never_returns_success(self):
        operation = self.store.begin("send", **DETAILS)
        with mock.patch.object(history.os, "replace", side_effect=OSError("synthetic write failure")):
            self.unavailable(self.store.before_broadcast, operation, BROADCAST)
        self.assertTrue(self.store.blocked)
        self.reopen()
        self.assertEqual(self.store.records()[0]["status"], "not_sent")

    def test_directory_fsync_failure_after_publish_keeps_pending_on_reopen(self):
        operation = self.store.begin("send", **DETAILS)
        original = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory sync failure")
            return original(fd)

        with mock.patch.object(history.os, "fsync", side_effect=fsync):
            self.unavailable(self.store.before_broadcast, operation, BROADCAST)
        self.assertTrue(self.store.blocked)
        self.reopen()
        self.assertEqual(self.store.records()[0]["status"], "pending")
        self.assertTrue(self.store.blocked)

    def test_initialization_failure_leaves_fail_closed_marker(self):
        directory = self.parent / "incomplete"
        with mock.patch.object(history.os, "link", side_effect=OSError("synthetic publication failure")):
            self.unavailable(history.PaymentHistory, directory, WALLET)
        self.assertTrue((directory / (WALLET + ".lock")).exists())
        self.assertFalse((directory / (WALLET + ".json")).exists())
        self.unavailable(history.PaymentHistory, directory, WALLET)

    def test_same_identity_cannot_open_concurrently_but_restored_copy_sees_history(self):
        self.pending()
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        with history.PaymentHistory(self.directory, OTHER) as other:
            self.assertEqual(other.records(), [])
        self.reopen()
        self.assertEqual(self.store.records()[0]["txid"], TXID)
        self.assertTrue(self.store.blocked)

    def test_exclusive_lock_applies_to_another_process(self):
        script = "from pathlib import Path; import sys; from qlu.payment_history import PaymentHistory, HistoryError\ntry:\n PaymentHistory(Path(sys.argv[1]), sys.argv[2])\nexcept HistoryError:\n sys.exit(7)\nsys.exit(8)"
        result = subprocess.run([sys.executable, "-c", script, str(self.directory), WALLET],
                                cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_missing_journal_is_fail_closed_while_open_and_after_reopen(self):
        self.pending()
        self.path.unlink()
        self.unavailable(self.store.records)
        self.assertTrue(self.store.blocked)
        self.store.close()
        self.unavailable(history.PaymentHistory, self.directory, WALLET)

    def test_modified_journal_poisons_instance_even_if_bytes_are_restored(self):
        original = self.path.read_bytes()
        self.path.write_bytes(b"corrupt")
        self.unavailable(self.store.records)
        self.path.write_bytes(original)
        self.assertTrue(self.store.blocked)
        self.unavailable(self.store.records)
        self.reopen()
        self.assertEqual(self.store.records(), [])

    def test_invalid_constructor_values_use_safe_errors(self):
        self.unavailable(history.PaymentHistory, 123, WALLET)
        self.unavailable(history.PaymentHistory, self.parent / "bad-wallet", "../invalid")
        self.unavailable(history.PaymentHistory, self.parent / "bad-wallet", None)

    def test_replaced_lock_or_journal_is_not_adopted(self):
        for name in (WALLET + ".json", WALLET + ".lock"):
            with self.subTest(name=name):
                target = self.directory / name
                data = target.read_bytes()
                replacement = self.directory / "replacement"
                replacement.write_bytes(data)
                replacement.chmod(0o600)
                replacement.replace(target)
                self.unavailable(self.store.records)
                self.assertTrue(self.store.blocked)
                self.reopen()

    def test_links_and_unsafe_permissions_are_rejected(self):
        self.store.close()
        original = self.path.read_bytes()
        for mode in (0o644, 0o400, 0o660):
            with self.subTest(mode=mode):
                self.path.chmod(mode)
                self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.path.chmod(0o600)
        linked = self.parent / "linked"
        os.link(self.path, linked)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        linked.unlink()
        self.path.unlink()
        linked.write_bytes(original)
        linked.chmod(0o600)
        self.path.symlink_to(linked)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.path.unlink()
        self.path.write_bytes(original)
        self.path.chmod(0o600)
        self.directory.chmod(0o755)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.directory.chmod(0o700)

    def test_symlink_directory_and_parent_are_rejected(self):
        alias = self.parent / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        self.unavailable(history.PaymentHistory, alias, OTHER)
        root_alias = self.parent / "root-alias"
        root_alias.symlink_to(self.parent, target_is_directory=True)
        self.unavailable(history.PaymentHistory, root_alias / "new-history", OTHER)

    def test_lock_file_links_are_rejected(self):
        self.store.close()
        lock = self.directory / (WALLET + ".lock")
        alias = self.parent / "lock-alias"
        os.link(lock, alias)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        lock.unlink()
        lock.symlink_to(alias)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)

    def test_malformed_network_schema_and_secret_fields_are_rejected(self):
        self.confirmed()
        original = json.loads(self.path.read_bytes())
        self.store.close()
        variants = []
        for field, value in (("network_id", "mainnet"), ("genesis_hash", "00" * 32),
                             ("wallet_id", OTHER), ("version", True), ("master_seed", "forbidden")):
            document = copy.deepcopy(original)
            document[field] = value
            variants.append(document)
        for field, value in (("status", "not_sent"), ("raw_transaction", "forbidden"),
                             ("passphrase", "forbidden"), ("confirmed_nodes", True)):
            document = copy.deepcopy(original)
            document["records"][0][field] = value
            variants.append(document)
        document = copy.deepcopy(original)
        document["records"].append(copy.deepcopy(document["records"][0]))
        variants.append(document)
        for document in variants:
            self.path.write_text(json.dumps(document))
            self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.path.write_text('{"format":"qlu-payment-history","format":"duplicate"}')
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        self.path.write_bytes(b"\xff")
        self.unavailable(history.PaymentHistory, self.directory, WALLET)

    def test_unknown_or_secret_fields_are_not_written(self):
        self.unavailable(self.store.begin, "send", master_seed="forbidden")
        operation = self.store.begin("send", **DETAILS)
        self.unavailable(self.store.before_broadcast, operation, {**BROADCAST, "raw_transaction": "forbidden"})
        data = self.path.read_text()
        self.assertNotIn("master_seed", data)
        self.assertNotIn("raw_transaction", data)
        self.assertNotIn("forbidden", data)

    def test_history_capacity_fails_closed_without_deleting_records(self):
        with mock.patch.object(history, "MAX_RECORDS", 2):
            self.confirmed()
            self.confirmed()
            before = self.path.read_bytes()
            with self.assertRaises(history.HistoryError) as raised:
                self.store.begin("send")
            self.assertEqual(raised.exception.code, "history_full")
            self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(len(self.store.records()), 2)

    def test_oversized_record_count_and_file_are_rejected(self):
        self.confirmed()
        document = json.loads(self.path.read_bytes())
        self.store.close()
        document["records"] *= history.MAX_RECORDS + 1
        self.path.write_text(json.dumps(document))
        self.unavailable(history.PaymentHistory, self.directory, WALLET)
        with self.path.open("wb") as stream:
            stream.truncate(history.MAX_BYTES + 1)
        self.unavailable(history.PaymentHistory, self.directory, WALLET)


if __name__ == "__main__":
    unittest.main()
