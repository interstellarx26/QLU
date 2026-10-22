#!/usr/bin/env python3
"""Private JSON-lines bridge for QLU's local native wallet experiment.

The native parent owns these anonymous pipes; there is no listening HTTP/RPC
server. Passphrases and recovery codes travel only over the private pipes, never
argv, environment variables, logs, or exception strings. Python cannot guarantee
memory erasure. A local authenticated receipt remembers a completed backup
check for the exact encrypted vault. It is trusted only after passphrase unlock;
it is neither a replacement backup nor proof of continuing offline safekeeping.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol
import recovery
import vault
import backup_verification
import payment_resume
from wallet_app_network import NetworkError, PaymentPending, WalletAppNetwork
from payment_history import HistoryError, PaymentHistory

MAX_LINE_BYTES = 65536
MAX_ID = 2**53 - 1
PREVIEW_SECONDS = 120
RECONCILIATION_SECONDS = 25
COMMANDS = {
    "status": set(), "wallets": set(), "create": {"passphrase", "confirmation"},
    "open": {"path"}, "unlock": {"passphrase"}, "lock": set(),
    "backup_create": {"backup_path"}, "backup_verify": {"backup_path", "code"},
    "restore": {"backup_path", "code", "passphrase", "confirmation"},
    "network_start": set(), "network_stop": set(), "refresh": set(),
    "faucet": {"operation_id"}, "prepare_send": {"recipient", "amount"},
    "recover_payments": set(), "prepare_resume": {"operation_id"}, "confirm_resume": {"resume_id"},
    "verify_received": {"txid"},
    "confirm_send": {"preview_id"}, "cancel_send": set(), "quit": set(),
}
MESSAGES = {
    "invalid_request": "The wallet request is invalid. Please try again.",
    "resume_unavailable": "This payment cannot be resumed safely. Keep its transaction ID and check its status; do not create a replacement payment.",
    "resume_invalid": "This resume review has expired or changed. Review the original payment again before resuming it.",
    "no_wallet": "Create or open a wallet first.",
    "locked": "Unlock your wallet to continue.",
    "backup_required": "Verify your saved backup before receiving or sending test QLU.",
    "passphrase_mismatch": "The passphrases do not match. Preserve spaces exactly.",
    "passphrase_invalid": "Use a separate passphrase of at least 15 characters and no more than 1024 UTF-8 bytes.",
    "wallet_failed": "The wallet action failed. Check your passphrase, recovery materials, and private file location.",
    "wallet_changed": "The selected wallet file changed. Wallet access is closed. Open the wallet file again to check its own identity and payment history.",
    "invalid_path": "Choose a supported private file location. Existing files are never replaced.",
    "backup_failed": "The backup could not be saved or verified. Check its file and separate recovery code.",
    "verification_save_failed": "Your backup check could not be remembered safely. Keep your backup and recovery code, unlock the wallet, and verify again.",
    "preview_invalid": "This payment review has expired or changed. Review the payment again.",
    "network_error": "The private test network action failed. Check its status before trying again.",
    "invalid_amount": "Enter a positive QLU amount with at most eight decimal places.",
    "invalid_address": "Enter a valid QLU private-network receiving address.",
    "invalid_transaction": "Enter the complete 64-character transaction ID from the sender.",
    "incoming_not_found": "This payment is not confirmed within the private network's searchable history. Check the transaction ID and try again after confirmation.",
    "incoming_not_received": "This transaction is not a payment from another wallet to this address. Transfers to yourself and change are not new income.",
    "incoming_unavailable": "This incoming payment could not be verified on all four private nodes. Its received status has not been confirmed.",
    "invalid_wallet": "The wallet's private-network identity could not be verified.",
    "network_stopped": "Start the private test network first.",
    "already_running": "This wallet network is already started or still needs cleanup.",
    "start_failed": "The private network could not start. Another test may be running, or the local build needs attention.",
    "cleanup_failed": "Some private wallet nodes could not be stopped. Retry stopping the network before closing the app.",
    "network_identity": "The private nodes failed their identity or localhost checks. No payment was authorized by this check.",
    "balance_failed": "Wallet balance could not be verified. Refresh after the private nodes agree.",
    "stale_payment": "The payment or its available funds changed. Review a fresh payment.",
    "insufficient_funds": "There is not enough spendable test QLU for the amount and fee within the 16-input limit.",
    "faucet_failed": "Test QLU could not be prepared. The existing private chain was preserved.",
    "faucet_exhausted": "This laboratory's mining rewards cannot fund another 1 QLU payment. The chain was preserved.",
    "signing_failed": "The wallet could not sign this payment. Unlock it and review again.",
    "payment_rejected": "The payment was rejected before broadcast. Review its available funds and fee.",
    "wallet_locked": "Unlock your wallet before sending.",
    "payment_pending": "The original payment is pending. Check its status or review the original payment to resume it; do not create a replacement.",
    "payment_conflicted": "At the last check, another confirmed payment spent these coins. This original payment will not be submitted again.",
    "history_unavailable": "Payment history could not be safely opened or saved. Sending is paused. Keep the existing history files and close any other copy of this wallet.",
    "history_full": "This private wallet's payment history is full. Sending is paused; keep the history files.",
    "internal_error": "The wallet action could not be completed. Your wallet has been locked.",
}

NETWORK_CODES = {
    "network_error", "invalid_amount", "invalid_address", "invalid_wallet", "network_stopped",
    "already_running", "start_failed", "cleanup_failed", "network_identity", "balance_failed",
    "stale_payment", "insufficient_funds", "faucet_failed", "faucet_exhausted", "signing_failed",
    "payment_rejected", "wallet_locked",
    "invalid_transaction", "incoming_not_found", "incoming_not_received", "incoming_unavailable",
    "resume_unavailable", "resume_invalid",
}
NETWORK_CHECK_FAILURES = {
    "network_error", "network_stopped", "start_failed", "cleanup_failed",
    "network_identity", "balance_failed", "stale_payment", "faucet_failed",
    "payment_rejected", "incoming_unavailable", "insufficient_funds",
}


class AppError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(MESSAGES[code])


def _safe_path(value, *, vault_file=False):
    if type(value) is not str or not value or len(value.encode("utf-8")) > 4096:
        raise AppError("invalid_path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise AppError("invalid_path")
    if vault_file and not path.name.endswith(".vault.json"):
        raise AppError("invalid_path")
    return path


def _private_directory(path):
    """Create one owner-only directory without following any symlink component."""
    parent, name = recovery._open_parent(path)
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            metadata = os.fstat(child)
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise AppError("invalid_path")
        finally:
            os.close(child)
    finally:
        os.close(parent)


def _check_vault_file(path):
    # File safety and public envelope identity can be checked before a password.
    # Authentication and bounded KDF validation still happen in WalletSession.
    blob = recovery.read_private(path, vault.MAX_VAULT_BYTES)
    envelope = recovery._parse(blob, vault.MAX_VAULT_BYTES)
    if (envelope.keys() != vault.HEADER_FIELDS | {"ciphertext"}
            or envelope["format"] != "qlu-local-vault"
            or type(envelope["version"]) is not int or envelope["version"] != 1
            or envelope["network_id"] != protocol.NETWORK
            or envelope["genesis_hash"] != protocol.GENESIS
            or envelope["policy"] != recovery.POLICY):
        raise AppError("invalid_path")
    # Selection identity only. Authentication still requires the passphrase.
    return hashlib.sha256(blob).hexdigest()


def _matching_passphrases(params):
    phrase = params["passphrase"]
    try:
        encoded = vault._passphrase(phrase)
        confirmation = params["confirmation"].encode("utf-8")
    except Exception:
        raise AppError("passphrase_invalid") from None
    if not hmac.compare_digest(encoded, confirmation):
        raise AppError("passphrase_mismatch")
    return phrase


def _request(request):
    if (type(request) is not dict or request.keys() != {"id", "command", "params"}
            or type(request["id"]) is not int or not 0 < request["id"] <= MAX_ID
            or type(request["command"]) is not str or request["command"] not in COMMANDS
            or type(request["params"]) is not dict
            or request["params"].keys() != COMMANDS[request["command"]]):
        raise AppError("invalid_request")
    for key, value in request["params"].items():
        if type(value) is not str:
            raise AppError("invalid_request")
        limit = 4096 if key in {"path", "backup_path"} else 1024
        if key == "code": limit = recovery.MAX_CODE_BYTES
        if key in {"recipient", "preview_id", "resume_id", "operation_id", "amount"}: limit = 128
        try:
            if not value or len(value.encode("utf-8")) > limit:
                raise AppError("invalid_request")
        except UnicodeError:
            raise AppError("invalid_request") from None
        if key in {"operation_id", "resume_id"} and re.fullmatch(r"[0-9a-f]{32}", value) is None:
            raise AppError("invalid_request")
        if key == "txid" and re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise AppError("invalid_transaction")
    return request


class WalletApp:
    """Serial owner of one encrypted wallet session and one isolated test network."""
    def __init__(self, root=protocol.ROOT, network=None, *, app_dir=None):
        self.root = Path(root).resolve()
        self.app_dir = self.root / ".local" / "wallet-app" if app_dir is None else Path(app_dir)
        if (not self.app_dir.is_absolute() or ".." in self.app_dir.parts
                or self.app_dir.parent != self.root / ".local"):
            raise AppError("invalid_path")
        self.network = network if network is not None else WalletAppNetwork(root=self.root)
        self.session = None
        self.wallet_path = None
        self.keys = None
        self.backup_verified = False
        self.backup_verification_status = "unchecked"
        self.balance = None
        self.immature_balance = None
        self.network_healthy = False
        self.recent_payment = None
        self.history = None
        self._selected_vault_digest = None
        self._wallet_commitment = None
        self._generation = None
        self._preview = None
        self.closed = False

    def _managed(self):
        path = self.root / ".local"
        for component in (None, self.app_dir.name, "wallets"):
            if component is not None: path /= component
            _private_directory(path)
        return path

    def _new_path(self):
        return self._managed() / (uuid.uuid4().hex + ".vault.json")

    def _clear_authentication(self):
        """Drop cached authority while keeping the explicitly selected file pin."""
        if self.session is not None: self.session.lock()
        if self.history is not None: self.history.close()
        self.history = None
        self.keys = None
        self.backup_verified = False
        self.backup_verification_status = "unchecked"
        self.balance = None
        self.immature_balance = None
        self.network_healthy = False
        self.recent_payment = None
        self._generation = uuid.uuid4().hex if self.session is not None else None
        self._preview = None

    def _clear_wallet(self):
        self._clear_authentication()
        self.session = None
        self.wallet_path = None
        self._selected_vault_digest = None
        self._wallet_commitment = None
        self._generation = None

    def _check_identity_binding(self):
        """A journal and cached public identity must belong to this selection.

        Locks retain the public pin; they never allow another encrypted blob to
        silently become this wallet. This does not continuously monitor the path.
        """
        valid = True
        if self.session is None:
            valid = all(value is None for value in (
                self.keys, self.history, self._selected_vault_digest, self._wallet_commitment))
        else:
            pin = self._selected_vault_digest
            valid = type(pin) is str and re.fullmatch(r"[0-9a-f]{64}", pin) is not None
            authenticated = self.session.vault_digest
            if authenticated is not None:
                valid = valid and hmac.compare_digest(authenticated, pin)
            if self.keys is not None:
                valid = valid and self.keys.get("key_commitment") == self._wallet_commitment
            if self.history is not None:
                valid = valid and self.keys is not None and self.history.wallet_id == self._wallet_commitment
        if not valid:
            self._clear_wallet()
            raise AppError("wallet_changed")

    def _adopt(self, session, path):
        self.session = session
        self.wallet_path = path
        self._generation = uuid.uuid4().hex
        try:
            self._selected_vault_digest = session.vault_digest
            self.keys = session.public_keys()
            self._wallet_commitment = self.keys["key_commitment"]
            self._load_history()
        except BaseException:
            self._clear_wallet()
            raise

    def _load_history(self):
        self._check_identity_binding()
        if self.history is None and self.keys is not None:
            self._managed()
            self.history = PaymentHistory(self.app_dir / "payment-history", self.keys["key_commitment"])
        self._check_identity_binding()

    def _load_verification(self):
        # No receipt or cached boolean can unlock a wallet. Always derive its
        # identity from this successful passphrase-authenticated session first.
        self.backup_verified = False
        self.backup_verification_status = "required"
        try:
            receipt = backup_verification.load_receipt(
                self.app_dir / "backup-verifications", self.session.vault_digest)
        except backup_verification.VerificationError:
            self.backup_verification_status = "unavailable"
            return
        if receipt is not None:
            self.backup_verified = self.session.accept_verification_receipt(receipt)
            self.backup_verification_status = "remembered" if self.backup_verified else "unavailable"

    def _remember_verification(self, blob, code):
        self.backup_verified = False
        self.backup_verification_status = "required"
        receipt = self.session.create_verification_receipt(blob, code)
        directory = self.app_dir / "backup-verifications"
        digest = self.session.vault_digest
        backup_verification.save_receipt(directory, digest, receipt)
        # Report success only after durable publication and authenticated readback.
        saved = backup_verification.load_receipt(directory, digest)
        if saved is None or not self.session.accept_verification_receipt(saved):
            raise backup_verification.VerificationError()
        self.backup_verified = True
        self.backup_verification_status = "remembered"

    def _reconcile(self, *, finish=False, include_received=True):
        self._check_identity_binding()
        if self.history is None or not self.network.running:
            return
        # Re-check confirmed entries too: a restart/reorg must not turn a lost
        # confirmation into permission for a second payment. No signing here.
        # One budget covers the whole batch, including nested identity checks.
        # Outgoing uncertainty has priority. Incoming checks are read-only and
        # are deferred entirely during authorization of a new outgoing payment.
        deadline = time.monotonic() + RECONCILIATION_SECONDS
        records = sorted(self.history.records(), key=lambda row: row["kind"] == "receive")
        with self.network.reconciliation_budget(deadline):
            for record in records:
                if (record["status"] not in {"pending", "confirmed", "conflicted"}
                        or (record["kind"] == "receive" and not include_received)):
                    continue
                result = {"status": "pending", "status_reason": "network_unavailable"}
                if time.monotonic() < deadline:
                    try:
                        result = self.network.payment_status(record, finish=finish)
                    except Exception:
                        pass
                if type(result) is dict and result.get("status_reason") == "network_unavailable":
                    self._invalidate_network_check()
                self.history.update(record["operation_id"], result)

    def _payments_ready(self):
        self._load_history()
        if self.history is None: raise AppError("history_unavailable")
        if not self.network.running: raise AppError("network_stopped")
        self._reconcile(include_received=False)
        if self.history.blocked: raise AppError("payment_pending")

    def _previous_operation(self, operation_id):
        self._check_identity_binding()
        if self.history is None: raise AppError("history_unavailable")
        for record in self.history.records():
            if record["operation_id"] == operation_id:
                if record["kind"] == "receive":
                    raise AppError("preview_invalid")
                if record["status"] == "conflicted":
                    raise AppError("payment_conflicted")
                if record["status"] == "confirmed":
                    return self._payment(record)
                if record["status"] in {"pending", "preparing"}:
                    raise AppError("payment_pending")
                raise AppError("preview_invalid")
        return None

    def _submit_payment(self, operation_id, kind, details, submit):
        self._payments_ready()
        conflicts = tuple(record for record in self.history.records()
                          if record["kind"] in {"send", "funding"} and record["status"] == "conflicted")
        self.history.begin(kind, operation_id=operation_id, **details)
        try:
            receipt = submit(lambda data: self.history.before_broadcast(operation_id, data), conflicts)
            self.history.finish(operation_id, receipt)
        except BaseException as failure:
            # Only an intent with NO durable txid can be marked not sent. Once
            # broadcast is possible, every failure stays pending across restart.
            try:
                self.history.fail_before_broadcast(operation_id)
            except HistoryError:
                if isinstance(failure, Exception): raise
                # A termination signal still owns shutdown even if the journal
                # has failed. Its durable preparing/pending state stays intact.
            raise
        return self._payment(receipt)

    def _resume_record(self, operation_id):
        self._load_history()
        if self.history is None: raise AppError("history_unavailable")
        records = self.history.records()
        record = next((item for item in records if item["operation_id"] == operation_id), None)
        another_pending = any(item["operation_id"] != operation_id and item["kind"] in {"send", "funding"}
                              and item["status"] in {"preparing", "pending"} for item in records)
        if record is None or another_pending or not payment_resume.locally_resumable(record):
            raise AppError("resume_unavailable")
        try:
            payment_resume.validate_resume_record(record, protocol.script_for(self.keys))
        except (ValueError, TypeError):
            raise AppError("resume_unavailable") from None
        return record

    @staticmethod
    def _outbox_digest(record):
        value = {key: record[key] for key in ("signed_transaction", "spent_outputs")}
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()

    def _unlocked(self, *, backed_up=False):
        self._check_identity_binding()
        if self.session is None: raise AppError("no_wallet")
        if self.session.locked:
            self._preview = None
            raise AppError("locked")
        if backed_up and not self.backup_verified: raise AppError("backup_required")
        return self.session

    def state(self):
        self._check_identity_binding()
        # Polling has no key operation and cannot extend the five-minute deadline.
        locked = self.session is None or self.session.locked
        if locked: self._preview = None
        records = self.history.public_records() if self.history is not None else []
        all_records = self.history.records() if self.history is not None else []
        pending = next((row for row in all_records if row["kind"] != "receive"
                        and row["status"] in {"pending", "preparing"}), None)
        if pending is not None:
            resumable = payment_resume.locally_resumable(pending) and not any(
                row["operation_id"] != pending["operation_id"] and row["kind"] in {"send", "funding"}
                and row["status"] in {"preparing", "pending"} for row in all_records)
            pending.pop("start_height", None)
            pending.pop("transaction", None)
            pending.pop("signed_transaction", None)
            pending.pop("spent_outputs", None)
            pending["resume_available"] = resumable
        own_address = protocol.address_for(self.keys) if self.keys else None
        for row in records:
            row["direction"] = (
                "received" if row["kind"] == "receive" else
                "funding" if row["kind"] == "funding" else
                "self" if own_address and row.get("recipient", "").lower() == own_address else "sent")
        if records: self.recent_payment = records[0]
        return {
            "wallet_open": self.session is not None,
            "locked": locked,
            "backup_verified": self.backup_verified,
            "backup_verification_status": self.backup_verification_status,
            "address": protocol.address_for(self.keys) if self.backup_verified and self.keys else None,
            "wallet_path": str(self.wallet_path) if self.wallet_path is not None else None,
            "network": protocol.NETWORK,
            "network_running": self.network.running,
            "network_healthy": self.network.running and self.network_healthy,
            "balance": self.balance if self.network.running and self.network_healthy else None,
            "immature_balance": self.immature_balance if self.network.running and self.network_healthy else None,
            "recent_payment": self.recent_payment,
            "payment_history": records,
            "history_loaded": self.history is not None,
            "history_count": len(all_records),
            "payment_blocked": self.history.blocked if self.history is not None else False,
            "pending_payment": pending,
        }

    def _invalidate_network_check(self):
        self.network_healthy = False
        self.balance = self.immature_balance = None
        self._preview = None

    def _refresh(self, *, reconcile=True):
        self._check_identity_binding()
        # Cached balances are not a current availability proof. A failed scan
        # must not leave the preceding successful amount available to the UI.
        self.network_healthy = False
        self.balance = self.immature_balance = None
        try:
            if reconcile: self._reconcile()
            if self.network.running and self.keys is not None and self.backup_verified:
                balance = self.network.balance(protocol.script_for(self.keys))
                self.balance = balance["balance"]
                self.immature_balance = balance["immature_balance"]
                self.network_healthy = True
        except BaseException:
            self._invalidate_network_check()
            raise
        return self.state()

    def _payment(self, receipt):
        receipt = {key: value for key, value in receipt.items() if key not in {"transaction", "signed_transaction", "spent_outputs"}}
        self.recent_payment = receipt
        # Confirmation must remain visible even if a following balance scan fails.
        try:
            state = self._refresh()
        except Exception:
            self.balance = self.immature_balance = None
            state = self.state()
        return {"payment": receipt, "state": state}

    def execute(self, command, params):
        if self.closed: raise AppError("invalid_request")
        if command not in {"open", "create", "restore", "quit", "wallets"}:
            self._check_identity_binding()
        if command == "status": return self.state()
        if command == "wallets":
            result = []
            for path in sorted(self._managed().iterdir()):
                if re.fullmatch(r"[0-9a-f]{32}\.vault\.json", path.name):
                    try:
                        _check_vault_file(path)
                    except Exception:
                        continue
                    result.append({"path": str(path), "name": "Wallet " + path.name[:8]})
            return {"wallets": result}
        if command == "create":
            phrase = _matching_passphrases(params)
            self._clear_wallet()
            path = self._new_path()
            self._adopt(vault.WalletSession.create(path, phrase), path)
            return self.state()
        if command == "open":
            self._clear_wallet()
            path = _safe_path(params["path"], vault_file=True)
            self._selected_vault_digest = _check_vault_file(path)
            self.session = vault.WalletSession(path)
            self.wallet_path = path
            self._generation = uuid.uuid4().hex
            return self.state()
        if command == "unlock":
            if self.session is None: raise AppError("no_wallet")
            self._clear_authentication()
            try:
                self.session.unlock(params["passphrase"], expected_digest=self._selected_vault_digest)
                keys = self.session.public_keys()
                if (self.session.vault_digest != self._selected_vault_digest
                        or (self._wallet_commitment is not None
                            and keys["key_commitment"] != self._wallet_commitment)):
                    raise vault.VaultChangedError("The selected wallet identity changed")
                self.keys = keys
                self._wallet_commitment = keys["key_commitment"]
                self._load_history()
                self._load_verification()
            except vault.VaultChangedError:
                self._clear_wallet()
                raise AppError("wallet_changed") from None
            except BaseException:
                self._clear_authentication()
                raise
            return self.state()
        if command == "lock":
            self._preview = None
            if self.session is not None: self.session.lock()
            return self.state()
        if command == "backup_create":
            session = self._unlocked()
            path = _safe_path(params["backup_path"])
            blob, code = session.backup()
            recovery.write_private(path, blob)
            # Authenticate what actually reached disk before showing its code.
            if session.verify_backup(recovery.read_private(path), code) is not True:
                raise AppError("backup_failed")
            # This proves file integrity, not that the person has stored the code.
            # Only the separate backup_verify request unlocks the receive/send gate.
            return {"code": code, "backup_path": str(path)}
        if command == "backup_verify":
            session = self._unlocked()
            path = _safe_path(params["backup_path"])
            self._remember_verification(recovery.read_private(path), params["code"])
            return self.state()
        if command == "restore":
            phrase = _matching_passphrases(params)
            path = _safe_path(params["backup_path"])
            blob = recovery.read_private(path)
            self._clear_wallet()
            destination = self._new_path()
            self._adopt(vault.WalletSession.restore(destination, blob, params["code"], phrase), destination)
            self._remember_verification(blob, params["code"])
            return self.state()
        if command == "network_start":
            self.network.start()
            return self._refresh()
        if command == "network_stop":
            self._invalidate_network_check()
            self.network.stop()
            return self.state()
        if command == "refresh": return self._refresh()
        if command == "verify_received":
            self._unlocked(backed_up=True)
            self._preview = None
            self._load_history()
            if self.history is None: raise AppError("history_unavailable")
            if not self.network.running: raise AppError("network_stopped")
            receipt = self.network.verify_received_payment(params["txid"], protocol.script_for(self.keys))
            recorded = self.history.observe_received(receipt)
            recorded = {key: value for key, value in recorded.items() if key not in {"transaction", "signed_transaction", "spent_outputs"}}
            return {"received": recorded, "state": self._refresh()}
        if command == "recover_payments":
            if self.history is None: raise AppError("no_wallet")
            if not self.network.running: raise AppError("network_stopped")
            self._preview = None
            self._reconcile(finish=True)
            return self._refresh(reconcile=False)
        if command == "prepare_resume":
            self._unlocked(backed_up=True)
            self._preview = None
            self._resume_record(params["operation_id"])
            if not self.network.running: raise AppError("network_stopped")
            self._refresh()
            record = self._resume_record(params["operation_id"])
            prepared = self.network.prepare_resume(record, protocol.script_for(self.keys))
            self._unlocked(backed_up=True)
            resume_id = secrets.token_hex(16)
            self._preview = {
                "kind": "resume", "id": resume_id, "generation": self._generation,
                "commitment": self.keys["key_commitment"], "operation_id": record["operation_id"],
                "outbox_digest": self._outbox_digest(record),
                "deadline": time.monotonic() + PREVIEW_SECONDS, "prepared": prepared,
            }
            # Construct the review from the immutable journal intent; no signed
            # bytes, spent-output metadata or spending authority cross the pipe.
            public = {key: record[key] for key in ("operation_id", "kind", "txid", "recipient", "amount", "fee")}
            funding = record["kind"] == "funding"
            same_wallet = not funding and record["recipient"] == protocol.address_for(self.keys)
            total = format(Decimal(record["amount"]) + Decimal(record["fee"]), ".8f")
            public.update(is_self_transfer=same_wallet, total=total,
                          wallet_debit="0.00000000" if funding else record["fee"] if same_wallet else total,
                          wallet_credit=record["amount"] if funding else "0.00000000")
            return {**public, "resume_id": resume_id, "expires_in": PREVIEW_SECONDS, "state": self.state()}
        if command == "confirm_resume":
            self._unlocked(backed_up=True)
            preview, self._preview = self._preview, None
            if (preview is None or preview.get("kind") != "resume"
                    or not hmac.compare_digest(preview["id"], params["resume_id"])
                    or preview["generation"] != self._generation
                    or preview["commitment"] != self.keys["key_commitment"]
                    or time.monotonic() >= preview["deadline"]):
                raise AppError("resume_invalid")
            self._reconcile(include_received=False)
            record = self._resume_record(preview["operation_id"])
            if self._outbox_digest(record) != preview["outbox_digest"]:
                raise AppError("resume_invalid")
            conflicts = tuple(item for item in self.history.records()
                              if item["kind"] in {"send", "funding"} and item["status"] == "conflicted")
            def before_resume():
                self._unlocked(backed_up=True)
                current = self._resume_record(record["operation_id"])
                if self._outbox_digest(current) != preview["outbox_digest"]:
                    raise AppError("resume_invalid")
                self.history.assert_resume(record["operation_id"], record["signed_transaction"])
            receipt = self.network.resume(preview["prepared"], before_broadcast=before_resume,
                                          conflict_records=conflicts)
            self.history.finish(record["operation_id"], receipt)
            return self._payment(receipt)
        if command == "faucet":
            self._unlocked(backed_up=True)
            self._preview = None
            self._reconcile(include_received=False)
            previous = self._previous_operation(params["operation_id"])
            if previous is not None: return previous
            address = protocol.address_for(self.keys)
            return self._submit_payment(params["operation_id"], "funding",
                {"recipient": address, "amount": "1.00000000", "fee": "0.00100000"},
                lambda callback, conflicts: self.network.faucet(address, before_broadcast=callback,
                                                                 conflict_records=conflicts))
        if command == "prepare_send":
            self._unlocked(backed_up=True)
            self._preview = None
            self._payments_ready()
            prepared = self.network.prepare(self.keys, params["recipient"], params["amount"])
            preview_id = secrets.token_hex(16)
            self._preview = {
                "kind": "send", "id": preview_id, "generation": self._generation,
                "commitment": self.keys["key_commitment"],
                "deadline": time.monotonic() + PREVIEW_SECONDS, "prepared": prepared,
            }
            return {"preview_id": preview_id, **prepared.public(), "expires_in": PREVIEW_SECONDS}
        if command == "confirm_send":
            session = self._unlocked(backed_up=True)
            self._reconcile(include_received=False)
            previous = self._previous_operation(params["preview_id"])
            if previous is not None: return previous
            # Consume before any signing/broadcast attempt. Retries always require
            # a fresh review, especially after a possibly successful broadcast.
            preview, self._preview = self._preview, None
            if (preview is None or preview.get("kind") != "send"
                    or not hmac.compare_digest(preview["id"], params["preview_id"])
                    or preview["generation"] != self._generation
                    or preview["commitment"] != self.keys["key_commitment"]
                    or time.monotonic() >= preview["deadline"]):
                raise AppError("preview_invalid")
            prepared = preview["prepared"]
            return self._submit_payment(preview["id"], "send",
                {key: prepared.public()[key] for key in ("recipient", "amount", "fee")},
                lambda callback, conflicts: self.network.send(session, prepared, before_broadcast=callback,
                                                              conflict_records=conflicts))
        if command == "cancel_send":
            self._preview = None
            return self.state()
        if command == "quit":
            self.close()
            return {"closed": True}
        raise AppError("invalid_request")

    def handle(self, request):
        request_id = None
        if type(request) is dict and type(request.get("id")) is int and 0 < request["id"] <= MAX_ID:
            request_id = request["id"]
        command = None
        try:
            _request(request)
            command = request["command"]
            return {"id": request_id, "ok": True, "result": self.execute(command, request["params"])}
        except PaymentPending as error:
            # Only a syntactically valid public transaction identifier may cross.
            txid = error.txid
            self._invalidate_network_check()
            if type(txid) is str and re.fullmatch(r"[0-9a-f]{64}", txid):
                self.recent_payment = {"txid": txid, "status": "pending", "message": MESSAGES["payment_pending"]}
                return {"id": request_id, "ok": False, "error": {
                    "code": "payment_pending", "message": MESSAGES["payment_pending"], "txid": txid}}
            code = "network_error"
        except AppError as error:
            code = error.code
        except HistoryError as error:
            code = error.code if error.code in {"payment_pending", "history_full"} else "history_unavailable"
            self._preview = None
            if self.session is not None: self.session.lock()
        except backup_verification.VerificationError:
            self.backup_verified = False
            self.backup_verification_status = "unavailable"
            self._preview = None
            if self.session is not None: self.session.lock()
            code = "verification_save_failed"
        except NetworkError as error:
            # Map only known public codes to local fixed text, never echo details.
            code = error.code if error.code in NETWORK_CODES else "network_error"
            if code in NETWORK_CHECK_FAILURES:
                self._invalidate_network_check()
        except (vault.VaultError, recovery.RecoveryError, OSError, ValueError, TypeError):
            if self.session is not None: self.session.lock()
            self._preview = None
            code = "backup_failed" if command in {"backup_create", "backup_verify"} else "wallet_failed"
        except Exception:
            if self.session is not None: self.session.lock()
            self._preview = None
            code = "internal_error"
        return {"id": request_id, "ok": False, "error": {"code": code, "message": MESSAGES[code]}}

    def close(self):
        if self.closed: return
        try:
            self._clear_wallet()
        finally:
            # Marking closed before this succeeds would hide a cleanup failure.
            # Keep the bridge alive for explicit stop/quit retries on failure.
            self.network.stop()
        self.closed = True


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise AppError("invalid_request")
        result[key] = value
    return result


def _invalid_constant(_):
    raise AppError("invalid_request")


def serve(app, source, destination):
    """Read bounded binary lines serially; malformed/oversized input never echoes."""
    try:
        while not app.closed:
            line = source.readline(MAX_LINE_BYTES + 1)
            if not line: break
            stop = len(line) > MAX_LINE_BYTES or not line.endswith(b"\n")
            request = None
            try:
                if stop: raise AppError("invalid_request")
                request = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                                     parse_constant=_invalid_constant)
                response = app.handle(request)
            except Exception:
                response = {"id": None, "ok": False, "error": {
                    "code": "invalid_request", "message": MESSAGES["invalid_request"]}}
            finally:
                # Drop references promptly; this is not a memory-erasure claim.
                request = None
                line = b""
            destination.write(json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")
            destination.flush()
            response = None  # Includes the one explicit backup-code response.
            if stop: break  # Do not interpret a suffix of an oversized request.
    finally:
        app.close()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    # Do not let argparse repeat an unknown argument containing a pasted secret.
    if argv != ["--stdio"] or sys.stdin.isatty() or sys.stdout.isatty():
        print("QLU wallet requires private application pipes and --stdio.", file=sys.stderr)
        return 2
    os.umask(0o077)
    app = None
    previous = signal.getsignal(signal.SIGTERM)
    def terminate(_number, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        app = WalletApp()
        serve(app, sys.stdin.buffer, sys.stdout.buffer)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("QLU wallet bridge stopped. Wallet access is closed.", file=sys.stderr)
        return 1
    finally:
        try:
            if app is not None and not app.closed: app.close()
        except Exception:
            print("QLU private network cleanup needs attention.", file=sys.stderr)
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
