"""Native-wallet bridge boundaries; real encrypted vaults, no actual test nodes."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest import mock

from qlu import wallet_app
from qlu.tests.test_payment_history import make_outbox
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut

PASS = "local fixture river candle garden"
OTHER_PASS = "local fixture violet orange planet"
TXID = "ab" * 32


class Prepared:
    def __init__(self, recipient, amount):
        self.recipient, self.amount = recipient, amount
    def public(self):
        return {"recipient": self.recipient, "amount": self.amount,
                "fee": "0.00100000", "total": "1.00100000"}


class Network:
    def __init__(self):
        self.running = False
        self.starts = 0
        self.stops = 0
        self.scans = []
        self.prepared = []
        self.sent = []
        self.funded = []
        self.send_error = None
        self.balance_error = None
        self.status_result = None
        self.status_by_txid = {}
        self.send_guards = []
        self.funding_guards = []
        self.guard_error = None
        self.receipts = {}
        self.incoming_receipt = None
        self.incoming_checks = []
        self.reconciliation_deadlines = []
        self.resume_prepared = []
        self.resumed = []
        self.resume_prepare_error = None
        self.resume_error = None
        self.resume_guards = []
    @contextmanager
    def reconciliation_budget(self, deadline):
        self.reconciliation_deadlines.append(deadline)
        yield
    def start(self):
        self.starts += 1
        self.running = True
    def stop(self):
        self.stops += 1
        self.running = False
    def balance(self, script):
        self.scans.append(script)
        if self.balance_error: raise self.balance_error
        return {"balance": "1.00000000", "immature_balance": "2.00000000", "utxos": []}
    def prepare(self, keys, recipient, amount):
        result = Prepared(recipient, amount)
        self.prepared.append((keys, result))
        return result
    def send(self, session, prepared, *, before_broadcast=None, conflict_records=()):
        self.send_guards.append(copy.deepcopy(conflict_records))
        if self.guard_error: raise self.guard_error
        self.sent.append((session, prepared))
        receipt = self.receipt(prepared.recipient, prepared.amount)
        if before_broadcast and (not self.send_error or isinstance(self.send_error, wallet_app.PaymentPending)):
            before_broadcast({key: receipt[key] for key in ("txid", "recipient", "amount", "fee", "start_height")})
        if self.send_error: raise self.send_error
        self.receipts[TXID] = receipt
        return receipt
    def faucet(self, address, *, before_broadcast=None, conflict_records=()):
        self.funding_guards.append(copy.deepcopy(conflict_records))
        if self.guard_error: raise self.guard_error
        self.funded.append(address)
        receipt = self.receipt(address)
        if before_broadcast:
            before_broadcast({key: receipt[key] for key in ("txid", "recipient", "amount", "fee", "start_height")})
        self.receipts[TXID] = receipt
        return receipt
    def prepare_resume(self, record, own_script):
        wallet_app.payment_resume.validate_resume_record(record, own_script)
        if self.resume_prepare_error: raise self.resume_prepare_error
        prepared = copy.deepcopy(record)
        self.resume_prepared.append(prepared)
        return prepared
    def resume(self, prepared, *, before_broadcast, conflict_records=()):
        self.resume_guards.append(copy.deepcopy(conflict_records))
        before_broadcast()
        self.resumed.append(copy.deepcopy(prepared))
        if self.resume_error: raise self.resume_error
        before_broadcast()
        receipt = {key: prepared[key] for key in ("txid", "recipient", "amount", "fee", "start_height")}
        receipt.update(block="cd" * 32, confirmed_nodes=4)
        self.receipts[receipt["txid"]] = receipt
        return receipt
    def payment_status(self, record, *, finish=False):
        if self.status_result is not None: return self.status_result
        if record["txid"] in self.status_by_txid: return dict(self.status_by_txid[record["txid"]])
        receipt = self.receipts.get(record["txid"])
        return {**receipt, "status": "confirmed"} if receipt else {"status": "pending", "status_reason": "not_found"}
    def verify_received_payment(self, txid, own_script):
        self.incoming_checks.append((txid, own_script))
        if self.incoming_receipt is None:
            raise wallet_app.NetworkError("Fixture payment not received", "incoming_not_received")
        return dict(self.incoming_receipt)
    @staticmethod
    def receipt(recipient, amount="1.00000000"):
        return {"txid": TXID, "block": "cd" * 32, "amount": amount, "fee": "0.00100000",
                "recipient": recipient, "confirmed_nodes": 4, "start_height": 1}


class WalletAppTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.network = Network()
        self.app = wallet_app.WalletApp(self.root, self.network)
        self.request_id = 0
        self.backup = self.root / "backup.json"

    def tearDown(self):
        self.app.close()
        self.temporary.cleanup()

    def request(self, command, **params):
        self.request_id += 1
        if command == "faucet": params.setdefault("operation_id", uuid.uuid4().hex)
        return self.app.handle({"id": self.request_id, "command": command, "params": params})

    def success(self, command, **params):
        result = self.request(command, **params)
        self.assertTrue(result["ok"], result)
        return result["result"]

    def create(self):
        return self.success("create", passphrase=PASS, confirmation=PASS)

    def backed_up(self):
        self.create()
        code = self.success("backup_create", backup_path=str(self.backup))["code"]
        self.success("backup_verify", backup_path=str(self.backup), code=code)
        return code

    def review(self):
        if not self.network.running: self.success("network_start")
        return self.success("prepare_send", recipient=wallet_app.protocol.address_for(self.app.keys), amount="1.00000000")

    def pending_outbox(self, *, kind="send"):
        address = wallet_app.protocol.address_for(self.app.keys)
        data = make_outbox(self.app.keys if kind == "send" else None, recipient=address)
        operation = self.app.history.begin(kind, **{key: data[key] for key in ("recipient", "amount", "fee")})
        self.app.history.before_broadcast(operation, data)
        return operation, data

    def test_resume_review_preserves_original_payment_and_redacts_outbox(self):
        self.backed_up()
        operation, data = self.pending_outbox()
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        self.assertEqual(review["operation_id"], operation)
        for field in ("txid", "recipient", "amount", "fee"):
            self.assertEqual(review[field], data[field])
        self.assertTrue(review["state"]["payment_blocked"])
        self.assertEqual(review["expires_in"], 120)
        self.assertTrue(review["is_self_transfer"])
        self.assertEqual(review["wallet_debit"], data["fee"])
        self.assertEqual(review["wallet_credit"], "0.00000000")
        self.assertEqual(len(self.app.history.records()), 1)
        for response in (review, self.success("status")):
            rendered = json.dumps(response)
            self.assertNotIn(data["signed_transaction"], rendered)
            self.assertNotIn("signed_transaction", rendered)
            self.assertNotIn("spent_outputs", rendered)
        self.assertEqual(self.network.resumed, [])
        self.assertEqual(self.network.sent, [])

    def test_resume_reuses_exact_outbox_after_restart_without_signing_or_new_operation(self):
        code = self.backed_up()
        operation, data = self.pending_outbox()
        self.reopen(code)
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        with mock.patch.object(self.app.session, "sign", side_effect=AssertionError("Resume must not sign")), \
                mock.patch.object(self.network, "send", side_effect=AssertionError("Resume must not create payment")):
            result = self.success("confirm_resume", resume_id=review["resume_id"])
        self.assertEqual(result["payment"]["txid"], data["txid"])
        self.assertEqual(len(self.app.history.records()), 1)
        self.assertEqual(self.app.history.records()[0]["operation_id"], operation)
        self.assertEqual(self.app.history.records()[0]["status"], "confirmed")
        self.assertEqual(len(self.network.resumed), 1)
        self.assertEqual(self.network.resumed[0]["signed_transaction"], data["signed_transaction"])
        self.assertEqual(self.network.resumed[0]["spent_outputs"], data["spent_outputs"])
        self.assertNotIn("signed_transaction", json.dumps(result))
        self.assertNotIn("spent_outputs", json.dumps(result))
        self.assertEqual(self.request("confirm_resume", resume_id=review["resume_id"])["error"]["code"], "resume_invalid")
        self.assertEqual(len(self.network.resumed), 1)

    def test_funding_resume_uses_original_faucet_outbox_without_new_funding(self):
        self.backed_up()
        operation, data = self.pending_outbox(kind="funding")
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        self.assertEqual(review["kind"], "funding")
        self.assertEqual(review["wallet_debit"], "0.00000000")
        self.assertEqual(review["wallet_credit"], data["amount"])
        self.assertFalse(review["is_self_transfer"])
        with mock.patch.object(self.network, "faucet", side_effect=AssertionError("No replacement funding")):
            result = self.success("confirm_resume", resume_id=review["resume_id"])
        self.assertEqual(result["payment"]["txid"], data["txid"])
        self.assertEqual(self.network.resumed[0]["signed_transaction"], data["signed_transaction"])
        self.assertEqual(self.app.history.records()[0]["kind"], "funding")

    def test_resume_uncertainty_consumes_review_and_preserves_same_durable_payment(self):
        self.backed_up()
        operation, data = self.pending_outbox()
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        self.network.resume_error = wallet_app.PaymentPending(data["txid"])
        response = self.request("confirm_resume", resume_id=review["resume_id"])
        self.assertEqual(response["error"]["code"], "payment_pending")
        self.assertEqual(response["error"]["txid"], data["txid"])
        self.assertTrue(self.app.history.blocked)
        self.assertIsNone(self.app._preview)
        self.assertEqual(len(self.app.history.records()), 1)
        self.assertEqual(self.request("confirm_resume", resume_id=review["resume_id"])["error"]["code"], "resume_invalid")
        self.assertEqual(len(self.network.resumed), 1)
        self.network.resume_error = None
        fresh = self.success("prepare_resume", operation_id=operation)
        self.success("confirm_resume", resume_id=fresh["resume_id"])
        self.assertEqual([row["txid"] for row in self.network.resumed], [data["txid"], data["txid"]])
        self.assertEqual(len(self.app.history.records()), 1)

    def test_status_refresh_and_check_never_resume_saved_bytes(self):
        self.backed_up()
        self.pending_outbox()
        self.success("network_start")
        with mock.patch.object(self.network, "resume", side_effect=AssertionError("No automatic resume")):
            for command in ("status", "refresh", "recover_payments"):
                self.assertTrue(self.success(command)["payment_blocked"])
        self.assertEqual(self.network.sent, [])
        self.assertEqual(self.network.funded, [])

    def test_legacy_confirmed_and_conflicted_payments_cannot_be_resumed(self):
        self.backed_up()
        operation, data = self.pending_outbox()
        self.success("network_start")
        self.app.history.finish(operation, {**data, "block": "cd" * 32, "confirmed_nodes": 4})
        self.app.history.update(operation, {"status": "pending", "status_reason": "not_found"})
        self.assertEqual(self.request("prepare_resume", operation_id=operation)["error"]["code"], "resume_unavailable")
        self.app.history.finish(operation, {**data, "block": "cd" * 32, "confirmed_nodes": 4})
        legacy = self.app.history.begin("send")
        self.app.history.before_broadcast(legacy, {key: value for key, value in data.items()
                                                 if key not in {"signed_transaction", "spent_outputs"}})
        self.assertEqual(self.request("prepare_resume", operation_id=legacy)["error"]["code"], "resume_unavailable")
        self.assertEqual(self.network.resumed, [])

    def test_resume_review_expiry_lock_cancel_and_other_endpoint_prevent_broadcast(self):
        self.backed_up()
        operation, _ = self.pending_outbox()
        self.success("network_start")
        for action in ("expired", "lock", "cancel", "send-endpoint"):
            review = self.success("prepare_resume", operation_id=operation)
            if action == "expired": self.app._preview["deadline"] = 0
            if action == "lock":
                self.success("lock")
                self.success("unlock", passphrase=PASS)
            if action == "cancel": self.success("cancel_send")
            if action == "send-endpoint":
                self.assertEqual(self.request("confirm_send", preview_id=review["resume_id"])["error"]["code"], "preview_invalid")
            self.assertEqual(self.request("confirm_resume", resume_id=review["resume_id"])["error"]["code"], "resume_invalid")
        self.assertEqual(self.network.resumed, [])
        self.assertTrue(self.app.history.blocked)

    def test_resume_confirmation_reconciles_changed_original_before_submission(self):
        self.backed_up()
        operation, data = self.pending_outbox()
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        self.network.status_result = {**{key: data[key] for key in ("txid", "recipient", "amount", "fee", "start_height")},
                                      "status": "confirmed", "block": "cd" * 32, "confirmed_nodes": 4}
        self.assertEqual(self.request("confirm_resume", resume_id=review["resume_id"])["error"]["code"], "resume_unavailable")
        self.assertEqual(self.app.history.records()[0]["status"], "confirmed")
        self.assertEqual(self.network.resumed, [])

    def test_resume_rechecks_durable_history_before_broadcast_and_keeps_pending_on_failure(self):
        self.backed_up()
        operation, _ = self.pending_outbox()
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        with mock.patch.object(self.app.history, "assert_resume", side_effect=wallet_app.HistoryError()):
            response = self.request("confirm_resume", resume_id=review["resume_id"])
        self.assertEqual(response["error"]["code"], "history_unavailable")
        self.assertEqual(self.network.resumed, [])
        self.assertTrue(self.app.history.blocked)
        self.assertIsNone(self.app._preview)

    def test_resume_rechecks_other_outgoing_uncertainty_after_reconciliation(self):
        self.backed_up()
        original, original_data, _ = self.conflict_fixture()
        operation, _ = self.pending_outbox()
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        self.network.status_by_txid[original_data["txid"]] = {"status": "pending", "status_reason": "not_found"}
        response = self.request("confirm_resume", resume_id=review["resume_id"])
        self.assertEqual(response["error"]["code"], "resume_unavailable")
        self.assertEqual(self.request("prepare_resume", operation_id=operation)["error"]["code"], "resume_unavailable")
        self.assertEqual(self.network.resumed, [])
        self.assertTrue(self.app.history.blocked)
        self.assertEqual(next(row for row in self.app.history.records() if row["operation_id"] == original)["status"], "pending")

    def test_resume_callback_rechecks_other_outgoing_guard_immediately_before_broadcast(self):
        self.backed_up()
        original, _, _ = self.conflict_fixture()
        operation, _ = self.pending_outbox()
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        resumed = self.network.resume
        def reorg_before_callback(prepared, **kwargs):
            self.app.history.update(original, {"status": "pending", "status_reason": "not_found"})
            return resumed(prepared, **kwargs)
        with mock.patch.object(self.network, "resume", side_effect=reorg_before_callback):
            response = self.request("confirm_resume", resume_id=review["resume_id"])
        self.assertEqual(response["error"]["code"], "resume_unavailable")
        self.assertEqual(self.network.resumed, [])
        self.assertTrue(self.app.history.blocked)

    def test_incoming_pending_does_not_block_review_of_original_outgoing(self):
        self.backed_up()
        incoming = self.app.history.observe_received(self.receive_fixture())["operation_id"]
        self.app.history.update(incoming, {"status": "pending", "status_reason": "not_found"})
        operation, _ = self.pending_outbox()
        self.success("network_start")
        review = self.success("prepare_resume", operation_id=operation)
        self.success("confirm_resume", resume_id=review["resume_id"])
        self.assertEqual(len(self.network.resumed), 1)

    def test_resume_prepare_failure_leaves_no_review_and_keeps_pending(self):
        self.backed_up()
        operation, _ = self.pending_outbox()
        self.success("network_start")
        self.network.resume_prepare_error = wallet_app.NetworkError("synthetic stale snapshot", "stale_payment")
        response = self.request("prepare_resume", operation_id=operation)
        self.assertEqual(response["error"]["code"], "stale_payment")
        self.assertIsNone(self.app._preview)
        self.assertFalse(self.app.network_healthy)
        self.assertTrue(self.app.history.blocked)
        self.assertEqual(self.network.resumed, [])

    def test_starts_empty_locked_without_network_or_files(self):
        state = self.success("status")
        self.assertFalse(state["wallet_open"])
        self.assertTrue(state["locked"])
        self.assertIsNone(state["address"])
        self.assertEqual(state["network"], "qludev")
        self.assertFalse(state["network_running"])
        self.assertFalse(state["network_healthy"])
        self.assertEqual(self.network.starts, 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_create_encrypted_managed_vault_address_gated_until_code_check(self):
        state = self.create()
        self.assertFalse(state["locked"])
        self.assertFalse(state["backup_verified"])
        self.assertIsNone(state["address"])
        path = Path(state["wallet_path"])
        self.assertEqual(path.parent, self.root / ".local/wallet-app/wallets")
        self.assertRegex(path.name, r"^[0-9a-f]{32}\.vault\.json$")
        blob = path.read_bytes()
        self.assertNotIn(PASS.encode(), blob)
        self.assertNotIn(b"master_seed", blob)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for command, params in (("faucet", {}), ("prepare_send", {"recipient": "x", "amount": "1"})):
            self.assertEqual(self.request(command, **params)["error"]["code"], "backup_required")
        backup = self.success("backup_create", backup_path=str(self.backup))
        self.assertEqual(set(backup), {"code", "backup_path"})
        self.assertFalse(self.success("status")["backup_verified"])
        state = self.success("backup_verify", backup_path=str(self.backup), code=backup["code"])
        self.assertTrue(state["backup_verified"])
        self.assertTrue(state["address"].startswith("qlud1"))

    def test_mismatched_or_invalid_password_never_creates(self):
        for phrase, confirmation, code in ((PASS, OTHER_PASS, "passphrase_mismatch"),
                                          ("short", "short", "passphrase_invalid")):
            result = self.request("create", passphrase=phrase, confirmation=confirmation)
            self.assertEqual(result["error"]["code"], code)
            self.assertFalse(self.app.state()["wallet_open"])
        self.assertFalse((self.root / ".local").exists())

    def test_backup_file_never_overwritten_and_old_verification_retained(self):
        self.backed_up()
        prior = self.backup.read_bytes()
        result = self.request("backup_create", backup_path=str(self.backup))
        self.assertFalse(result["ok"])
        self.assertEqual(prior, self.backup.read_bytes())
        self.assertTrue(self.app.backup_verified)

    def test_backup_persisted_bytes_checked_before_code_response(self):
        self.create()
        with mock.patch.object(wallet_app.recovery, "read_private", return_value=b"tampered"):
            result = self.request("backup_create", backup_path=str(self.backup))
        self.assertFalse(result["ok"])
        self.assertNotIn("code", result.get("result", {}))
        self.assertFalse(self.app.backup_verified)
        self.assertTrue(self.app.session.locked)

    def test_wrong_code_or_other_wallet_backup_cannot_open_gate(self):
        code = self.backed_up()
        self.create()
        for attempted in ("not a recovery code", code):
            result = self.request("backup_verify", backup_path=str(self.backup), code=attempted)
            self.assertFalse(result["ok"])
            self.assertFalse(self.app.backup_verified)
            self.success("unlock", passphrase=PASS)
        self.assertIsNone(self.app.state()["address"])

    def test_open_starts_locked_then_authenticates_remembered_check_and_preserves_vault(self):
        code = self.backed_up()
        path = self.app.wallet_path
        initial = path.read_bytes()
        old_session = self.app.session
        state = self.success("open", path=str(path))
        self.assertTrue(old_session.locked)
        self.assertTrue(state["locked"])
        self.assertFalse(state["backup_verified"])
        self.assertIsNone(state["address"])
        state = self.success("unlock", passphrase=PASS)
        self.assertTrue(state["backup_verified"])
        self.assertEqual(state["backup_verification_status"], "remembered")
        self.assertIsNotNone(self.app.state()["address"])
        self.assertEqual(path.read_bytes(), initial)

    def test_wrong_unlock_locks_and_redacts_passphrase(self):
        self.backed_up()
        preview = self.review()
        result = self.request("unlock", passphrase=OTHER_PASS)
        self.assertFalse(result["ok"])
        self.assertNotIn(OTHER_PASS, json.dumps(result))
        self.assertTrue(self.app.session.locked)
        self.assertFalse(self.app.backup_verified)
        self.assertIsNone(self.app._preview)
        self.success("unlock", passphrase=PASS)
        self.assertFalse(self.request("confirm_send", preview_id=preview["preview_id"])["ok"])
        self.assertFalse(self.network.sent)

    def test_verification_survives_new_owner_without_backup_or_code(self):
        self.backed_up()
        path, address = self.app.wallet_path, self.app.state()["address"]
        self.backup.rename(self.root / "offline-backup.json")
        self.app.close()
        self.app = wallet_app.WalletApp(self.root, self.network)
        self.success("open", path=str(path))
        with mock.patch.object(wallet_app.vault.WalletSession, "verify_backup", side_effect=AssertionError), \
             mock.patch.object(wallet_app.recovery, "restore_backup", side_effect=AssertionError):
            state = self.success("unlock", passphrase=PASS)
        self.assertTrue(state["backup_verified"])
        self.assertEqual(state["address"], address)
        self.assertEqual(state["backup_verification_status"], "remembered")

    def test_missing_receipt_requires_once_only_verification(self):
        self.create()
        code = self.success("backup_create", backup_path=str(self.backup))["code"]
        path = self.app.wallet_path
        self.success("open", path=str(path))
        state = self.success("unlock", passphrase=PASS)
        self.assertFalse(state["backup_verified"])
        self.assertEqual(state["backup_verification_status"], "required")
        self.assertEqual(self.request("faucet")["error"]["code"], "backup_required")
        self.success("backup_verify", backup_path=str(self.backup), code=code)
        self.success("open", path=str(path))
        self.assertTrue(self.success("unlock", passphrase=PASS)["backup_verified"])

    def test_untrusted_receipt_never_opens_gate_and_real_reverification_repairs(self):
        code = self.backed_up()
        path = self.app.wallet_path
        directory = self.app.app_dir / "backup-verifications"
        receipt = directory / (self.app.session.vault_digest + ".json")
        receipt.write_bytes(b'{"backup_verified":true}')
        self.success("open", path=str(path))
        state = self.success("unlock", passphrase=PASS)
        self.assertFalse(state["backup_verified"])
        self.assertEqual(state["backup_verification_status"], "unavailable")
        self.assertEqual(self.request("faucet")["error"]["code"], "backup_required")
        self.assertFalse(self.network.funded)
        self.success("backup_verify", backup_path=str(self.backup), code=code)
        self.success("open", path=str(path))
        self.assertTrue(self.success("unlock", passphrase=PASS)["backup_verified"])

    def test_receipt_storage_failure_locks_and_does_not_claim_success(self):
        self.create()
        code = self.success("backup_create", backup_path=str(self.backup))["code"]
        with mock.patch.object(wallet_app.backup_verification, "save_receipt",
                               side_effect=wallet_app.backup_verification.VerificationError()):
            result = self.request("backup_verify", backup_path=str(self.backup), code=code)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "verification_save_failed")
        self.assertTrue(self.app.session.locked)
        self.assertFalse(self.app.backup_verified)
        self.assertNotIn(code, json.dumps(result))
        self.assertFalse(self.success("unlock", passphrase=PASS)["backup_verified"])

    def test_receipt_readback_must_authenticate_before_success(self):
        self.create()
        code = self.success("backup_create", backup_path=str(self.backup))["code"]
        with mock.patch.object(wallet_app.backup_verification, "load_receipt", return_value=b"changed"):
            result = self.request("backup_verify", backup_path=str(self.backup), code=code)
        self.assertEqual(result["error"]["code"], "verification_save_failed")
        self.assertTrue(self.app.session.locked)
        self.assertFalse(self.app.backup_verified)

    def test_lock_during_receipt_persistence_cannot_mark_current_session_verified(self):
        self.create()
        code = self.success("backup_create", backup_path=str(self.backup))["code"]
        save = wallet_app.backup_verification.save_receipt
        def save_then_lock(*args):
            save(*args)
            self.app.session.lock()
        with mock.patch.object(wallet_app.backup_verification, "save_receipt", side_effect=save_then_lock):
            result = self.request("backup_verify", backup_path=str(self.backup), code=code)
        self.assertFalse(result["ok"])
        self.assertTrue(self.app.session.locked)
        self.assertFalse(self.app.backup_verified)
        # Complete historical proof can be used after a NEW explicit unlock.
        self.assertTrue(self.success("unlock", passphrase=PASS)["backup_verified"])

    def test_unsafe_receipt_store_cannot_reuse_cached_verification_on_unlock(self):
        self.backed_up()
        self.success("lock")
        with mock.patch.object(wallet_app.backup_verification, "load_receipt",
                               side_effect=wallet_app.backup_verification.VerificationError()):
            state = self.success("unlock", passphrase=PASS)
        self.assertFalse(state["backup_verified"])
        self.assertEqual(state["backup_verification_status"], "unavailable")

    def test_new_wallet_cannot_reuse_other_wallet_receipt(self):
        self.backed_up()
        directory = self.app.app_dir / "backup-verifications"
        receipt = (directory / (self.app.session.vault_digest + ".json")).read_bytes()
        self.create()
        path = self.app.wallet_path
        impostor = directory / (self.app.session.vault_digest + ".json")
        impostor.write_bytes(receipt)
        impostor.chmod(0o600)
        self.success("open", path=str(path))
        self.assertFalse(self.success("unlock", passphrase=PASS)["backup_verified"])

    def test_restore_into_fresh_encrypted_file_same_address_with_new_password(self):
        code = self.backed_up()
        old_path, old_address = self.app.wallet_path, self.app.state()["address"]
        old_blob = old_path.read_bytes()
        restored = self.success("restore", backup_path=str(self.backup), code=code,
                                passphrase=OTHER_PASS, confirmation=OTHER_PASS)
        self.assertTrue(restored["backup_verified"])
        self.assertEqual(restored["address"], old_address)
        self.assertNotEqual(restored["wallet_path"], str(old_path))
        self.assertEqual(old_path.read_bytes(), old_blob)
        self.assertNotIn(b"master_seed", Path(restored["wallet_path"]).read_bytes())
        self.success("lock")
        self.success("unlock", passphrase=OTHER_PASS)
        self.assertEqual(self.app.state()["address"], old_address)
        self.app.close()
        self.app = wallet_app.WalletApp(self.root, self.network)
        self.success("open", path=restored["wallet_path"])
        self.assertTrue(self.success("unlock", passphrase=OTHER_PASS)["backup_verified"])

    def test_bad_restore_code_creates_no_new_vault(self):
        self.backed_up()
        before = set((self.root / ".local/wallet-app/wallets").iterdir())
        result = self.request("restore", backup_path=str(self.backup), code="invalid code",
                              passphrase=PASS, confirmation=PASS)
        self.assertFalse(result["ok"])
        self.assertEqual(before, set((self.root / ".local/wallet-app/wallets").iterdir()))
        self.assertFalse(self.app.state()["wallet_open"])

    def test_status_and_refresh_never_derive_keys_or_touch_idle_deadline(self):
        self.backed_up()
        self.success("network_start")
        session = self.app.session
        deadline = session._deadline
        with mock.patch.object(session, "public_keys", side_effect=AssertionError("No key polling")), \
                mock.patch.object(session, "address", side_effect=AssertionError("No key polling")):
            self.success("status")
            self.success("refresh")
            self.assertEqual(deadline, session._deadline)
            # Use the real monotonic expiry check, with no sleeping test dependency.
            with session._mutex: session._deadline = time.monotonic() - 1
            self.assertTrue(self.success("status")["locked"])
            state = self.success("refresh")
            self.assertTrue(state["locked"])
            self.assertEqual(state["balance"], "1.00000000")
        self.assertTrue(session.locked)

    def test_preview_consumed_on_success_and_no_automatic_resend(self):
        self.backed_up()
        review = self.review()
        self.assertEqual(set(review), {"preview_id", "recipient", "amount", "fee", "total", "expires_in"})
        result = self.success("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(result["payment"]["txid"], TXID)
        self.assertEqual(len(self.network.sent), 1)
        again = self.request("confirm_send", preview_id=review["preview_id"])
        self.assertTrue(again["ok"])
        self.assertEqual(again["result"]["payment"]["txid"], TXID)
        self.assertEqual(len(self.network.sent), 1)

    def test_preview_expiry_and_wrong_identifier_consume_without_signing(self):
        self.backed_up()
        for expired in (False, True):
            review = self.review()
            if expired: self.app._preview["deadline"] = time.monotonic() - 1
            result = self.request("confirm_send", preview_id=review["preview_id"] if expired else "wrong")
            self.assertEqual(result["error"]["code"], "preview_invalid")
            self.assertIsNone(self.app._preview)
        self.assertFalse(self.network.sent)

    def test_wallet_change_lock_cancel_and_generation_change_invalidate_review(self):
        self.backed_up()
        for action in ("cancel", "lock", "generation", "wallet"):
            review = self.review()
            if action == "cancel": self.success("cancel_send")
            if action == "lock":
                self.success("lock")
                self.success("unlock", passphrase=PASS)
            if action == "generation": self.app._generation = "changed"
            if action == "wallet": self.create()
            self.assertFalse(self.request("confirm_send", preview_id=review["preview_id"])["ok"])
        self.assertFalse(self.network.sent)

    def test_network_failure_consumes_review_and_never_leaks_backend_error(self):
        self.backed_up()
        review = self.review()
        self.network.send_error = wallet_app.NetworkError("secret backend example " + PASS)
        result = self.request("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(result["error"]["code"], "network_error")
        self.assertNotIn(PASS, json.dumps(result))
        self.assertIsNone(self.app._preview)
        self.request("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(len(self.network.sent), 1)

    def test_pending_payment_keeps_only_public_txid_and_consumes_review(self):
        self.backed_up()
        review = self.review()
        # Use the actual typed error, without relying on its constructor details.
        error = wallet_app.PaymentPending.__new__(wallet_app.PaymentPending)
        Exception.__init__(error, "secret pending error " + PASS)
        error.txid = TXID
        self.network.send_error = error
        result = self.request("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(result["error"]["code"], "payment_pending")
        self.assertEqual(result["error"]["txid"], TXID)
        self.assertNotIn(PASS, json.dumps(result))
        self.assertEqual(self.app.state()["recent_payment"]["txid"], TXID)
        self.assertIsNone(self.app._preview)

    def test_confirmed_receipt_not_lost_if_following_balance_scan_fails(self):
        self.backed_up()
        self.success("network_start")
        review = self.review()
        self.network.balance_error = RuntimeError("disposable internal detail")
        result = self.success("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(result["payment"]["txid"], TXID)
        self.assertEqual(result["state"]["recent_payment"]["txid"], TXID)
        self.assertIsNone(result["state"]["balance"])
        self.assertFalse(result["state"]["network_healthy"])
        self.assertEqual(result["state"]["payment_history"][0]["status"], "confirmed")

    def test_failed_refresh_clears_cached_balance_health_and_payment_review(self):
        self.backed_up()
        self.review()
        self.assertTrue(self.success("status")["network_healthy"])
        self.assertIsNotNone(self.app.balance)
        self.network.balance_error = wallet_app.NetworkError("synthetic private detail", "balance_failed")
        result = self.request("refresh")
        self.assertEqual(result["error"]["code"], "balance_failed")
        self.assertNotIn("synthetic private detail", json.dumps(result))
        state = self.success("status")
        self.assertTrue(state["network_running"])
        self.assertFalse(state["network_healthy"])
        self.assertIsNone(state["balance"])
        self.assertIsNone(state["immature_balance"])
        self.assertIsNone(self.app._preview)
        self.assertFalse(self.network.sent or self.network.funded)
        self.network.balance_error = None
        recovered = self.success("refresh")
        self.assertTrue(recovered["network_healthy"])
        self.assertEqual(recovered["balance"], "1.00000000")
        self.assertIsNone(self.app._preview)

    def test_missing_node_failure_during_review_invalidates_old_network_proof(self):
        self.backed_up()
        self.review()
        with mock.patch.object(self.network, "prepare", side_effect=wallet_app.NetworkError(
                "synthetic missing node", "network_identity")):
            result = self.request("prepare_send", recipient=wallet_app.protocol.address_for(self.app.keys), amount="0.1")
        self.assertEqual(result["error"]["code"], "network_identity")
        state = self.success("status")
        self.assertFalse(state["network_healthy"])
        self.assertIsNone(state["balance"])
        self.assertIsNone(self.app._preview)
        self.assertFalse(self.network.sent)

    def test_insufficient_funds_discards_disproved_cached_availability(self):
        self.backed_up()
        self.review()
        with mock.patch.object(self.network, "prepare", side_effect=wallet_app.NetworkError(
                "synthetic competing spend", "insufficient_funds")):
            result = self.request("prepare_send", recipient=wallet_app.protocol.address_for(self.app.keys), amount="0.1")
        self.assertEqual(result["error"]["code"], "insufficient_funds")
        state = self.success("status")
        self.assertFalse(state["network_healthy"])
        self.assertIsNone(state["balance"])
        self.assertIsNone(state["immature_balance"])
        self.assertIsNone(self.app._preview)
        self.assertFalse(self.network.sent or self.network.funded)

    def test_invalid_amount_or_address_does_not_discard_checked_balance(self):
        self.backed_up()
        self.review()
        for code in ("invalid_amount", "invalid_address"):
            with self.subTest(code=code):
                with mock.patch.object(self.network, "prepare", side_effect=wallet_app.NetworkError(
                        "synthetic invalid input", code)):
                    result = self.request("prepare_send", recipient=wallet_app.protocol.address_for(self.app.keys), amount="0.1")
                self.assertEqual(result["error"]["code"], code)
                state = self.success("status")
                self.assertTrue(state["network_healthy"])
                self.assertEqual(state["balance"], "1.00000000")
                self.assertEqual(state["immature_balance"], "2.00000000")
                self.assertIsNone(self.app._preview)
        self.assertFalse(self.network.sent or self.network.funded)

    def test_reorg_and_failed_balance_keep_durable_duplicate_guard_until_recovery(self):
        self.backed_up()
        review = self.review()
        self.success("confirm_send", preview_id=review["preview_id"])
        self.network.status_result = {"status": "pending", "status_reason": "not_found"}
        self.network.balance_error = wallet_app.NetworkError("synthetic missing node", "network_identity")
        self.assertFalse(self.request("refresh")["ok"])
        state = self.success("status")
        self.assertFalse(state["network_healthy"])
        self.assertIsNone(state["balance"])
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["pending_payment"]["txid"], TXID)
        self.assertEqual(self.request("confirm_send", preview_id=review["preview_id"])["error"]["code"], "payment_pending")
        self.assertEqual(len(self.network.sent), 1)
        self.network.status_result = None
        self.network.balance_error = None
        state = self.success("recover_payments")
        self.assertTrue(state["network_healthy"])
        self.assertFalse(state["payment_blocked"])
        self.assertEqual(state["payment_history"][0]["txid"], TXID)
        self.assertEqual(len(self.network.sent), 1)

    def test_unavailable_reconciliation_clears_balance_but_keeps_pending_reference(self):
        self.backed_up()
        review = self.review()
        self.success("confirm_send", preview_id=review["preview_id"])
        with mock.patch.object(self.network, "payment_status", side_effect=wallet_app.NetworkError(
                "synthetic missing node", "network_identity")):
            self.app._reconcile()
        state = self.success("status")
        self.assertFalse(state["network_healthy"])
        self.assertIsNone(state["balance"])
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["pending_payment"]["txid"], TXID)

    def test_network_stop_invalidates_health_and_review(self):
        self.backed_up()
        self.review()
        state = self.success("network_stop")
        self.assertFalse(state["network_running"])
        self.assertFalse(state["network_healthy"])
        self.assertIsNone(state["balance"])
        self.assertIsNone(self.app._preview)

    def reopen(self, code):
        path = self.app.wallet_path
        self.app.close()
        self.app = wallet_app.WalletApp(self.root, self.network)
        self.success("open", path=str(path))
        self.assertTrue(self.success("unlock", passphrase=PASS)["backup_verified"])

    def test_history_and_exact_send_replay_survive_full_app_restart(self):
        code = self.backed_up()
        review = self.review()
        first = self.success("confirm_send", preview_id=review["preview_id"])
        self.reopen(code)
        state = self.success("status")
        self.assertFalse(state["network_running"])
        self.assertTrue(state["history_loaded"])
        self.assertEqual(state["payment_history"][0]["txid"], first["payment"]["txid"])
        self.success("network_start")
        replay = self.success("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(replay["payment"]["txid"], TXID)
        self.assertEqual(len(self.network.sent), 1)
        self.assertEqual(replay["state"]["history_count"], 1)

    def receive_fixture(self):
        txid = "ef" * 32
        receipt = {"txid": txid, "block": "cd" * 32, "amount": "0.10000000",
                   "recipient": self.app.state()["address"], "confirmed_nodes": 4, "start_height": 1}
        self.network.incoming_receipt = receipt
        self.network.receipts[txid] = receipt
        return receipt

    def test_received_payment_is_saved_once_and_survives_passphrase_only_restart(self):
        self.backed_up()
        self.success("network_start")
        receipt = self.receive_fixture()
        first = self.success("verify_received", txid=receipt["txid"])
        again = self.success("verify_received", txid=receipt["txid"])
        self.assertEqual(first["received"]["operation_id"], again["received"]["operation_id"])
        self.assertEqual(again["state"]["history_count"], 1)
        self.assertEqual(again["state"]["payment_history"][0]["direction"], "received")
        self.assertNotIn("fee", first["received"])
        self.assertFalse(self.network.sent or self.network.funded)
        self.reopen(None)
        state = self.success("status")
        self.assertEqual(state["payment_history"][0]["txid"], receipt["txid"])
        self.assertFalse(state["payment_blocked"])
        self.success("network_start")
        result = self.request("confirm_send", preview_id=first["received"]["operation_id"])
        self.assertEqual(result["error"]["code"], "preview_invalid")
        self.assertFalse(self.network.sent)

    def test_incoming_uncertainty_never_blocks_outgoing_or_offers_it_as_pending_send(self):
        self.backed_up()
        self.success("network_start")
        receipt = self.receive_fixture()
        self.success("verify_received", txid=receipt["txid"])
        self.network.status_result = {"status": "pending", "status_reason": "not_found"}
        state = self.success("refresh")
        self.assertEqual(state["payment_history"][0]["status"], "pending")
        self.assertFalse(state["payment_blocked"])
        self.assertIsNone(state["pending_payment"])
        self.assertIn("preview_id", self.review())

    def test_incoming_check_requires_unlock_backup_and_network(self):
        txid = "ef" * 32
        self.create()
        self.assertEqual(self.request("verify_received", txid=txid)["error"]["code"], "backup_required")
        code = self.success("backup_create", backup_path=str(self.backup))["code"]
        self.success("backup_verify", backup_path=str(self.backup), code=code)
        self.assertEqual(self.request("verify_received", txid=txid)["error"]["code"], "network_stopped")
        self.success("lock")
        self.assertEqual(self.request("verify_received", txid=txid)["error"]["code"], "locked")
        self.assertFalse(self.network.incoming_checks)

    def test_slow_incoming_batch_shares_one_budget_and_outgoing_has_priority(self):
        self.backed_up()
        self.success("network_start")
        receipt = self.receive_fixture()
        for index in range(5):
            self.app.history.observe_received({**receipt, "txid": f"{index + 1:064x}"})
        # Add an outgoing record after incoming ones to exercise priority order.
        token = self.app.history.begin("send", recipient=receipt["recipient"],
                                      amount="0.01000000", fee="0.00100000")
        outgoing = self.network.receipt(receipt["recipient"], "0.01000000")
        self.app.history.before_broadcast(token, {key: outgoing[key] for key in
            ("txid", "recipient", "amount", "fee", "start_height")})
        now = [100.0]
        checked = []
        def slow_status(record, *, finish=False):
            checked.append(record["kind"])
            if record["kind"] != "receive":
                return {**outgoing, "status": "confirmed"}
            now[0] += wallet_app.RECONCILIATION_SECONDS + 1
            raise wallet_app.NetworkError("Synthetic slow lookup", "incoming_unavailable")
        with mock.patch.object(wallet_app.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(self.network, "payment_status", side_effect=slow_status):
            self.app._reconcile()
        self.assertEqual(checked, ["send", "receive"])
        self.assertEqual(self.network.reconciliation_deadlines[-1],
                         100.0 + wallet_app.RECONCILIATION_SECONDS)
        state = self.app.state()
        self.assertFalse(state["payment_blocked"])
        self.assertIsNone(state["pending_payment"])
        incoming = [row for row in state["payment_history"] if row["kind"] == "receive"]
        self.assertEqual(len(incoming), 5)
        self.assertTrue(all(row["status"] == "pending" for row in incoming))
        self.assertTrue(all(row["block"] == receipt["block"] for row in incoming))

    def test_outgoing_authorization_defers_incoming_checks(self):
        self.backed_up()
        self.success("network_start")
        receipt = self.receive_fixture()
        for index in range(3):
            self.app.history.observe_received({**receipt, "txid": f"{index + 1:064x}"})
        with mock.patch.object(self.network, "payment_status", side_effect=AssertionError("Must defer incoming")) as check:
            self.assertIn("preview_id", self.review())
            self.app._payments_ready()
            check.assert_not_called()

    def test_status_recovery_reconciles_only_once(self):
        self.backed_up()
        self.success("network_start")
        self.app.history.observe_received(self.receive_fixture())
        with mock.patch.object(self.app, "_reconcile", wraps=self.app._reconcile) as reconcile:
            self.success("recover_payments")
        reconcile.assert_called_once_with(finish=True)

    def test_invalid_or_unrelated_received_payment_never_enters_history(self):
        self.backed_up()
        self.success("network_start")
        for value in ("a" * 63, "g" * 64, "A" * 64, " " + "a" * 64):
            self.assertEqual(self.request("verify_received", txid=value)["error"]["code"], "invalid_transaction")
        self.assertFalse(self.network.incoming_checks)
        result = self.request("verify_received", txid="ef" * 32)
        self.assertEqual(result["error"]["code"], "incoming_not_received")
        self.assertEqual(self.app.state()["history_count"], 0)

    def test_history_distinguishes_self_transfer_from_payment_to_another_wallet(self):
        self.backed_up()
        review = self.review()
        result = self.success("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(result["state"]["payment_history"][0]["direction"], "self")
        self.success("prepare_send", recipient="other fixture address", amount="0.1")
        result = self.success("confirm_send", preview_id=self.app._preview["id"])
        self.assertEqual(result["state"]["payment_history"][0]["direction"], "sent")

    def test_funding_operation_token_replay_does_not_fund_twice(self):
        code = self.backed_up()
        self.success("network_start")
        token = uuid.uuid4().hex
        self.success("faucet", operation_id=token)
        self.reopen(code)
        self.success("network_start")
        replay = self.success("faucet", operation_id=token)
        self.assertEqual(replay["payment"]["txid"], TXID)
        self.assertEqual(len(self.network.funded), 1)
        self.assertEqual(replay["state"]["history_count"], 1)

    def test_pending_survives_restart_and_blocks_backend_send_and_funding(self):
        code = self.backed_up()
        review = self.review()
        self.network.send_error = wallet_app.PaymentPending(TXID)
        self.assertFalse(self.request("confirm_send", preview_id=review["preview_id"])["ok"])
        self.reopen(code)
        state = self.success("network_start")
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["payment_history"][0]["txid"], TXID)
        self.assertEqual(self.request("prepare_send", recipient=state["address"], amount="0.1")["error"]["code"], "payment_pending")
        self.assertEqual(self.request("faucet")["error"]["code"], "payment_pending")
        self.assertTrue(self.success("recover_payments")["payment_blocked"])
        self.assertEqual(len(self.network.sent), 1)
        self.assertEqual(len(self.network.funded), 0)

    def test_status_recovery_confirms_existing_payment_without_resigning(self):
        self.backed_up()
        review = self.review()
        self.network.send_error = wallet_app.PaymentPending(TXID)
        self.request("confirm_send", preview_id=review["preview_id"])
        self.network.receipts[TXID] = self.network.receipt(review["recipient"])
        with mock.patch.object(self.app.session, "sign", side_effect=AssertionError("Must not sign again")):
            state = self.success("recover_payments")
        self.assertFalse(state["payment_blocked"])
        self.assertEqual(state["payment_history"][0]["status"], "confirmed")
        self.assertEqual(len(self.network.sent), 1)

    def test_confirmed_payment_reorg_blocks_new_backend_payment(self):
        self.backed_up()
        review = self.review()
        self.success("confirm_send", preview_id=review["preview_id"])
        self.network.status_result = {"status": "pending", "status_reason": "not_found"}
        self.assertEqual(self.request("faucet")["error"]["code"], "payment_pending")
        self.assertTrue(self.success("status")["payment_blocked"])
        self.assertFalse(self.network.funded)

    def conflict_fixture(self, kind="send"):
        address = wallet_app.protocol.address_for(self.app.keys)
        transaction = CTransaction()
        transaction.vin = [CTxIn(COutPoint(int("55" * 32, 16), 2), nSequence=0xffffffff)]
        transaction.vout = [CTxOut(100_000_000, wallet_app.protocol.script_for(self.app.keys))]
        details = {"recipient": address, "amount": "1.00000000", "fee": "0.00100000"}
        metadata = {**details, "txid": transaction.txid_hex, "start_height": 1,
                    "transaction": transaction.serialize_without_witness().hex()}
        conflict = {"txid": "66" * 32, "block": "77" * 32, "height": 2,
                    "input": {"txid": "55" * 32, "vout": 2}}
        operation = self.app.history.begin(kind, **details)
        self.app.history.before_broadcast(operation, metadata)
        status = {**metadata, "status": "conflicted", "conflict": conflict, "confirmed_nodes": 4}
        self.app.history.update(operation, status)
        self.network.status_by_txid[metadata["txid"]] = status
        return operation, metadata, conflict

    def test_conflicted_operation_replay_is_explicit_and_never_submits_again(self):
        self.backed_up()
        self.success("network_start")
        operation, metadata, _ = self.conflict_fixture()
        for command, field in (("confirm_send", "preview_id"), ("faucet", "operation_id")):
            result = self.request(command, **{field: operation})
            self.assertEqual(result["error"]["code"], "payment_conflicted")
            self.assertNotIn(metadata["transaction"], json.dumps(result))
        self.assertFalse(self.network.sent or self.network.funded)
        self.assertFalse(self.success("status")["payment_blocked"])

    def test_new_send_and_funding_pass_all_reconciled_conflicts_to_network_guards(self):
        self.backed_up()
        self.success("network_start")
        operation, metadata, conflict = self.conflict_fixture()
        review = self.review()
        self.success("confirm_send", preview_id=review["preview_id"])
        self.success("faucet")
        for records in (self.network.send_guards[-1], self.network.funding_guards[-1]):
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["operation_id"], operation)
            self.assertEqual(records[0]["transaction"], metadata["transaction"])
            self.assertEqual(records[0]["conflict"], conflict)
        self.assertEqual(len(self.network.sent), 1)
        self.assertEqual(len(self.network.funded), 1)

    def test_conflict_guard_failure_precedes_broadcast_and_reorg_restores_block(self):
        self.backed_up()
        self.success("network_start")
        _, metadata, _ = self.conflict_fixture()
        review = self.review()
        self.network.guard_error = wallet_app.NetworkError("synthetic moved conflict proof", "stale_payment")
        result = self.request("confirm_send", preview_id=review["preview_id"])
        self.assertEqual(result["error"]["code"], "stale_payment")
        self.assertFalse(self.network.sent)
        self.assertEqual(self.app.history.records()[-1]["status"], "not_sent")
        self.assertFalse(self.success("status")["network_healthy"])
        self.network.status_by_txid[metadata["txid"]] = {"status": "pending", "status_reason": "not_found"}
        self.network.guard_error = None
        result = self.request("prepare_send", recipient=metadata["recipient"], amount="0.1")
        self.assertEqual(result["error"]["code"], "payment_pending")
        self.assertTrue(self.success("status")["payment_blocked"])
        self.assertFalse(self.network.sent or self.network.funded)

    def test_restarted_conflict_requires_new_network_proof_before_any_payment(self):
        code = self.backed_up()
        self.success("network_start")
        operation, metadata, conflict = self.conflict_fixture()
        self.reopen(code)
        state = self.success("status")
        self.assertFalse(state["network_healthy"])
        self.assertEqual(state["payment_history"][0]["status"], "conflicted")
        self.network.status_by_txid[metadata["txid"]] = {"status": "pending", "status_reason": "network_unavailable"}
        state = self.success("network_start")
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["pending_payment"]["operation_id"], operation)
        self.assertEqual(state["pending_payment"]["conflict"], conflict)
        self.assertNotIn("transaction", state["pending_payment"])
        result = self.request("faucet")
        self.assertEqual(result["error"]["code"], "payment_pending")
        self.assertFalse(self.network.sent or self.network.funded)

    def test_restored_session_does_not_authorize_from_saved_conflict_alone(self):
        code = self.backed_up()
        self.success("network_start")
        _, metadata, _ = self.conflict_fixture()
        state = self.success("restore", backup_path=str(self.backup), code=code,
                             passphrase=OTHER_PASS, confirmation=OTHER_PASS)
        self.assertFalse(state["network_healthy"])
        self.network.status_by_txid[metadata["txid"]] = {"status": "pending", "status_reason": "not_found"}
        result = self.request("prepare_send", recipient=metadata["recipient"], amount="0.1")
        self.assertEqual(result["error"]["code"], "payment_pending")
        self.assertTrue(self.success("status")["payment_blocked"])
        self.assertFalse(self.network.sent or self.network.funded)

    def test_internal_transaction_is_not_exposed_by_confirmed_replay_or_state(self):
        self.backed_up()
        self.success("network_start")
        operation, metadata, conflict = self.conflict_fixture()
        confirmed = {**metadata, "status": "confirmed", "block": "88" * 32, "confirmed_nodes": 4}
        self.app.history.update(operation, confirmed)
        self.network.status_by_txid[metadata["txid"]] = confirmed
        result = self.success("confirm_send", preview_id=operation)
        self.assertEqual(result["payment"]["txid"], metadata["txid"])
        self.assertNotIn('"transaction"', json.dumps(result))
        self.assertNotIn(metadata["transaction"], json.dumps(result))
        self.assertEqual(self.app.history.records()[0]["transaction"], metadata["transaction"])
        self.assertEqual(self.app.history.records()[0]["conflict"], conflict)
        self.assertFalse(self.network.sent)

    def test_restored_copy_loads_same_history_and_duplicate_guard(self):
        code = self.backed_up()
        review = self.review()
        self.network.send_error = wallet_app.PaymentPending(TXID)
        self.request("confirm_send", preview_id=review["preview_id"])
        state = self.success("restore", backup_path=str(self.backup), code=code,
                             passphrase=OTHER_PASS, confirmation=OTHER_PASS)
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["history_count"], 1)
        self.assertEqual(state["payment_history"][0]["operation_id"], review["preview_id"])

    def test_competing_wallet_process_cannot_acquire_same_history(self):
        self.backed_up()
        other = wallet_app.WalletApp(self.root, Network())
        try:
            other.execute("open", {"path": str(self.app.wallet_path)})
            result = other.handle({"id": 1, "command": "unlock", "params": {"passphrase": PASS}})
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "history_unavailable")
            self.assertTrue(other.session.locked)
        finally:
            other.close()

    def test_interrupted_prebroadcast_intent_is_not_sent_after_reopen(self):
        code = self.backed_up()
        token = self.app.history.begin("send", recipient=wallet_app.protocol.address_for(self.app.keys), amount="0.1", fee="0.001")
        self.reopen(code)
        entry = self.success("status")["payment_history"][0]
        self.assertEqual(entry["operation_id"], token)
        self.assertEqual(entry["status"], "not_sent")
        self.assertNotIn("txid", entry)
        self.assertFalse(self.success("status")["payment_blocked"])

    def test_history_write_failure_prevents_submission_and_receipt_loss_blocks_retry(self):
        self.backed_up()
        review = self.review()
        with mock.patch.object(self.app.history, "before_broadcast", side_effect=wallet_app.HistoryError()):
            result = self.request("confirm_send", preview_id=review["preview_id"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "history_unavailable")
        self.assertFalse(self.network.receipts)
        self.success("unlock", passphrase=PASS)
        review = self.review()
        with mock.patch.object(self.app.history, "finish", side_effect=wallet_app.HistoryError()):
            result = self.request("confirm_send", preview_id=review["preview_id"])
        self.assertFalse(result["ok"])
        self.assertTrue(self.app.history.blocked)
        self.assertIn(TXID, self.network.receipts)

    def test_missing_history_is_not_silently_reset_on_reopen(self):
        code = self.backed_up()
        path = self.app.wallet_path
        journal = self.app.app_dir / "payment-history" / (self.app.keys["key_commitment"] + ".json")
        self.app.close()
        journal.unlink()  # Only this isolated temporary fixture.
        self.app = wallet_app.WalletApp(self.root, self.network)
        self.success("open", path=str(path))
        result = self.request("unlock", passphrase=PASS)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "history_unavailable")
        self.assertFalse(journal.exists())

    def test_termination_after_durable_marker_remains_pending_and_propagates(self):
        self.backed_up()
        review = self.review()
        durable = self.app.history.before_broadcast
        def terminate(operation_id, details):
            durable(operation_id, details)
            raise KeyboardInterrupt()
        with mock.patch.object(self.app.history, "before_broadcast", side_effect=terminate):
            with self.assertRaises(KeyboardInterrupt):
                self.request("confirm_send", preview_id=review["preview_id"])
        self.assertTrue(self.app.history.blocked)
        self.assertFalse(self.network.receipts)

    def test_pending_record_outside_latest_twenty_still_has_public_reference(self):
        self.backed_up()
        self.success("network_start")
        address = wallet_app.protocol.address_for(self.app.keys)
        for _ in range(21):
            operation = self.app.history.begin("send", recipient=address, amount="1", fee="0.001")
            receipt = self.network.receipt(address)
            self.app.history.before_broadcast(operation, {key: receipt[key] for key in ("txid", "recipient", "amount", "fee", "start_height")})
            self.app.history.finish(operation, receipt)
        oldest = self.app.history.records()[0]["operation_id"]
        self.app.history.update(oldest, {"status": "pending", "status_reason": "not_found"})
        state = self.success("status")
        self.assertEqual(len(state["payment_history"]), 20)
        self.assertTrue(state["payment_blocked"])
        self.assertEqual(state["pending_payment"]["operation_id"], oldest)
        self.assertEqual(state["pending_payment"]["txid"], TXID)

    def test_wallet_listing_managed_only_skips_symlinks_hardlinks_and_unsafe_files(self):
        self.create()
        path = self.app.wallet_path
        directory = path.parent
        (directory / ("a" * 32 + ".vault.json")).symlink_to(path)
        copied = directory / ("b" * 32 + ".vault.json")
        copied.write_bytes(path.read_bytes()); copied.chmod(0o644)
        hardlinked = directory / ("c" * 32 + ".vault.json")
        os.link(path, hardlinked)
        # Hardlinking also makes the original unsafe until that link is removed.
        self.assertEqual(self.success("wallets")["wallets"], [])
        hardlinked.unlink()
        listed = self.success("wallets")["wallets"]
        self.assertEqual([entry["path"] for entry in listed], [str(path)])
        self.assertEqual(set(listed[0]), {"path", "name"})

    def test_open_rejects_traversal_relative_symlink_wrong_extension_and_wrong_chain(self):
        self.create()
        path = self.app.wallet_path
        linked = self.root / "linked.vault.json"; linked.symlink_to(path)
        invalid = ("relative.vault.json", str(self.root / "../bad.vault.json"), str(linked), str(self.backup))
        for value in invalid:
            self.assertFalse(self.request("open", path=value)["ok"])
        altered = self.root / "altered.vault.json"
        envelope = json.loads(path.read_bytes()); envelope["network_id"] = "main"
        altered.write_text(json.dumps(envelope)); altered.chmod(0o600)
        self.assertFalse(self.request("open", path=str(altered))["ok"])

    def test_invalid_managed_directory_is_not_followed_or_permission_repaired(self):
        target = self.root / "external"; target.mkdir(mode=0o700)
        (self.root / ".local").symlink_to(target, target_is_directory=True)
        self.assertFalse(self.request("create", passphrase=PASS, confirmation=PASS)["ok"])
        self.assertEqual(list(target.iterdir()), [])

    def test_unknown_fields_commands_types_and_secrets_are_never_reflected(self):
        invalid = [
            {"id": 1, "command": PASS, "params": {}},
            {"id": True, "command": "status", "params": {}},
            {"id": -1, "command": "status", "params": {}},
            {"id": 1, "command": "status", "params": {"passphrase": PASS}},
            {"id": 1, "command": "status", "params": {}, "secret": PASS},
            {"id": 1, "command": "unlock", "params": {"passphrase": [PASS]}},
            {"id": 1, "command": "unlock", "params": {"passphrase": "\ud800"}},
            {"id": 1, "command": "unlock", "params": {"passphrase": "a" * 1025}},
            [PASS], None,
        ]
        for request in invalid:
            result = self.app.handle(request)
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "invalid_request")
            self.assertNotIn(PASS, json.dumps(result))

    def test_backup_code_only_returned_for_explicit_backup_create(self):
        self.create()
        code = self.success("backup_create", backup_path=str(self.backup))["code"]
        responses = [self.success("status"), self.success("wallets"),
                     self.success("backup_verify", backup_path=str(self.backup), code=code),
                     self.success("lock"), self.success("unlock", passphrase=PASS)]
        self.assertNotIn(code, json.dumps(responses))
        self.assertNotIn(code, repr(self.app.__dict__))
        self.assertNotIn(PASS, repr(self.app.__dict__))

    def test_unexpected_error_locks_and_redacts(self):
        self.create()
        with mock.patch.object(self.app, "execute", side_effect=RuntimeError(PASS)):
            result = self.request("status")
        self.assertEqual(result["error"]["code"], "internal_error")
        self.assertTrue(self.app.session.locked)
        self.assertNotIn(PASS, json.dumps(result))

    def test_quit_waits_for_cleanup_and_failed_cleanup_allows_retry(self):
        self.create()
        session = self.app.session
        self.network.start()
        with mock.patch.object(self.network, "stop", side_effect=wallet_app.NetworkError(PASS, "cleanup_failed")):
            result = self.request("quit")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "cleanup_failed")
        self.assertNotIn(PASS, json.dumps(result))
        self.assertTrue(session.locked)
        self.assertFalse(self.app.closed)
        self.assertTrue(self.success("status")["network_running"])
        result = self.success("quit")
        self.assertEqual(result, {"closed": True})
        self.assertTrue(self.app.closed)
        self.assertFalse(self.network.running)
        self.assertEqual(self.network.stops, 1)
        self.app.close()
        self.assertEqual(self.network.stops, 1)

    def test_network_errors_show_fixed_actionable_messages_without_details(self):
        with mock.patch.object(self.network, "start", side_effect=wallet_app.NetworkError(PASS, "start_failed")):
            result = self.request("network_start")
        self.assertEqual(result["error"]["code"], "start_failed")
        self.assertNotIn(PASS, result["error"]["message"])
        with mock.patch.object(self.network, "start", side_effect=wallet_app.NetworkError(PASS, "unknown-private-code")):
            result = self.request("network_start")
        self.assertEqual(result["error"]["code"], "network_error")
        self.assertNotIn("unknown-private-code", json.dumps(result))

    def test_isolated_app_directory_for_tests_not_arbitrary_external_storage(self):
        app = wallet_app.WalletApp(self.root, Network(), app_dir=self.root / ".local/private-drill")
        try:
            self.assertEqual(app._new_path().parent, self.root / ".local/private-drill/wallets")
        finally: app.close()
        with self.assertRaises(wallet_app.AppError):
            wallet_app.WalletApp(self.root, Network(), app_dir=self.root / "external")


class BridgeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.network = Network()
        self.app = wallet_app.WalletApp(self.root, self.network)
    def tearDown(self):
        self.app.close()
        self.temporary.cleanup()
    def serve(self, data):
        output = io.BytesIO()
        wallet_app.serve(self.app, io.BytesIO(data), output)
        return [json.loads(line) for line in output.getvalue().splitlines()]
    def test_eof_and_quit_lock_and_stop_after_protocol_only_response(self):
        self.app.execute("create", {"passphrase": PASS, "confirmation": PASS})
        session = self.app.session
        result = self.serve(b'{"id":1,"command":"status","params":{}}\n'
                            b'{"id":2,"command":"quit","params":{}}\n'
                            b'{"id":3,"command":"network_start","params":{}}\n')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[1], {"id": 2, "ok": True, "result": {"closed": True}})
        self.assertTrue(session.locked)
        self.assertTrue(self.app.closed)
        self.assertEqual(self.network.starts, 0)
        self.assertEqual(self.network.stops, 1)
    def test_duplicate_keys_invalid_utf8_nan_malformed_json_are_rejected_then_continue(self):
        lines = [b'{"id":1,"id":2,"command":"status","params":{}}',
                 b'{"id":1,"command":"unlock","params":{"passphrase":"a","passphrase":"b"}}',
                 b'{"id":1,"command":"status","params":{},"secret":NaN}',
                 b'\xff', b'not json']
        result = self.serve(b'\n'.join(lines + [b'{"id":8,"command":"status","params":{}}']) + b'\n')
        self.assertEqual(len(result), 6)
        self.assertTrue(all(not item["ok"] for item in result[:-1]))
        self.assertTrue(result[-1]["ok"])
        self.assertTrue(self.app.closed)
    def test_oversized_line_stops_without_interpreting_remainder(self):
        result = self.serve(b'x' * (wallet_app.MAX_LINE_BYTES + 1) + b'\n'
                            b'{"id":2,"command":"network_start","params":{}}\n')
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]["ok"])
        self.assertEqual(self.network.starts, 0)
        self.assertEqual(self.network.stops, 1)
    def test_unterminated_line_is_rejected_and_empty_eof_still_cleans_up(self):
        result = self.serve(b'{"id":1,"command":"status","params":{}}')
        self.assertFalse(result[0]["ok"])
        self.assertTrue(self.app.closed)
    def test_broken_output_still_locks_and_stops(self):
        class Broken(io.BytesIO):
            def write(self, value): raise BrokenPipeError
        self.app.execute("create", {"passphrase": PASS, "confirmation": PASS})
        session = self.app.session
        with self.assertRaises(BrokenPipeError):
            wallet_app.serve(self.app, io.BytesIO(b'{"id":1,"command":"status","params":{}}\n'), Broken())
        self.assertTrue(session.locked)
        self.assertEqual(self.network.stops, 1)
    def test_cli_never_echoes_secret_unknown_argument(self):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = wallet_app.main(["--stdio", PASS])
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(PASS, error.getvalue())


if __name__ == "__main__":
    unittest.main()
