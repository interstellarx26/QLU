#!/usr/bin/env python3
"""Private JSON-lines bridge for QLU's local native wallet experiment.

The native parent owns these anonymous pipes; there is no listening HTTP/RPC
server. Passphrases and recovery codes travel only over the private pipes, never
argv, environment variables, logs, or exception strings. Python cannot guarantee
memory erasure. Backup verification is deliberately session-local: reopening an
existing vault requires checking its portable backup again before receiving or
sending. This conservative prototype does not persist a trusted backup receipt.
"""
from __future__ import annotations

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
from wallet_app_network import NetworkError, PaymentPending, WalletAppNetwork

MAX_LINE_BYTES = 65536
MAX_ID = 2**53 - 1
PREVIEW_SECONDS = 120
COMMANDS = {
    "status": set(), "wallets": set(), "create": {"passphrase", "confirmation"},
    "open": {"path"}, "unlock": {"passphrase"}, "lock": set(),
    "backup_create": {"backup_path"}, "backup_verify": {"backup_path", "code"},
    "restore": {"backup_path", "code", "passphrase", "confirmation"},
    "network_start": set(), "network_stop": set(), "refresh": set(),
    "faucet": set(), "prepare_send": {"recipient", "amount"},
    "confirm_send": {"preview_id"}, "cancel_send": set(), "quit": set(),
}
MESSAGES = {
    "invalid_request": "The wallet request is invalid. Please try again.",
    "no_wallet": "Create or open a wallet first.",
    "locked": "Unlock your wallet to continue.",
    "backup_required": "Verify your saved backup before receiving or sending test QLU.",
    "passphrase_mismatch": "The passphrases do not match. Preserve spaces exactly.",
    "passphrase_invalid": "Use a separate passphrase of at least 15 characters and no more than 1024 UTF-8 bytes.",
    "wallet_failed": "The wallet action failed. Check your passphrase, recovery materials, and private file location.",
    "invalid_path": "Choose a supported private file location. Existing files are never replaced.",
    "backup_failed": "The backup could not be saved or verified. Check its file and separate recovery code.",
    "preview_invalid": "This payment review has expired or changed. Review the payment again.",
    "network_error": "The private test network action failed. Check its status before trying again.",
    "invalid_amount": "Enter a positive QLU amount with at most eight decimal places.",
    "invalid_address": "Enter a valid QLU private-network receiving address.",
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
    "payment_pending": "A payment may have been broadcast. Keep its transaction ID and check the network before sending again.",
    "internal_error": "The wallet action could not be completed. Your wallet has been locked.",
}

NETWORK_CODES = {
    "network_error", "invalid_amount", "invalid_address", "invalid_wallet", "network_stopped",
    "already_running", "start_failed", "cleanup_failed", "network_identity", "balance_failed",
    "stale_payment", "insufficient_funds", "faucet_failed", "faucet_exhausted", "signing_failed",
    "payment_rejected", "wallet_locked",
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
        if key in {"recipient", "preview_id", "amount"}: limit = 128
        try:
            if not value or len(value.encode("utf-8")) > limit:
                raise AppError("invalid_request")
        except UnicodeError:
            raise AppError("invalid_request") from None
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
        self.balance = None
        self.immature_balance = None
        self.recent_payment = None
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

    def _clear_wallet(self):
        if self.session is not None: self.session.lock()
        self.session = None
        self.wallet_path = None
        self.keys = None
        self.backup_verified = False
        self.balance = None
        self.immature_balance = None
        self.recent_payment = None
        self._generation = None
        self._preview = None

    def _adopt(self, session, path):
        self.session = session
        self.wallet_path = path
        self._generation = uuid.uuid4().hex
        self.keys = session.public_keys()

    def _unlocked(self, *, backed_up=False):
        if self.session is None: raise AppError("no_wallet")
        if self.session.locked:
            self._preview = None
            raise AppError("locked")
        if backed_up and not self.backup_verified: raise AppError("backup_required")
        return self.session

    def state(self):
        # Polling has no key operation and cannot extend the five-minute deadline.
        locked = self.session is None or self.session.locked
        if locked: self._preview = None
        return {
            "wallet_open": self.session is not None,
            "locked": locked,
            "backup_verified": self.backup_verified,
            "address": protocol.address_for(self.keys) if self.backup_verified and self.keys else None,
            "wallet_path": str(self.wallet_path) if self.wallet_path is not None else None,
            "network": protocol.NETWORK,
            "network_running": self.network.running,
            "balance": self.balance if self.network.running else None,
            "immature_balance": self.immature_balance if self.network.running else None,
            "recent_payment": self.recent_payment,
        }

    def _refresh(self):
        if self.network.running and self.keys is not None and self.backup_verified:
            balance = self.network.balance(protocol.script_for(self.keys))
            self.balance = balance["balance"]
            self.immature_balance = balance["immature_balance"]
        else:
            self.balance = self.immature_balance = None
        return self.state()

    def _payment(self, receipt):
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
            _check_vault_file(path)
            self.session = vault.WalletSession(path)
            self.wallet_path = path
            self._generation = uuid.uuid4().hex
            return self.state()
        if command == "unlock":
            if self.session is None: raise AppError("no_wallet")
            self._preview = None
            self.session.unlock(params["passphrase"])
            self.keys = self.session.public_keys()
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
            if session.verify_backup(recovery.read_private(path), params["code"]) is not True:
                raise AppError("backup_failed")
            self.backup_verified = True
            return self.state()
        if command == "restore":
            phrase = _matching_passphrases(params)
            path = _safe_path(params["backup_path"])
            blob = recovery.read_private(path)
            self._clear_wallet()
            destination = self._new_path()
            self._adopt(vault.WalletSession.restore(destination, blob, params["code"], phrase), destination)
            if self.session.verify_backup(blob, params["code"]) is not True:
                raise AppError("backup_failed")
            self.backup_verified = True
            return self.state()
        if command == "network_start":
            self.network.start()
            return self._refresh()
        if command == "network_stop":
            self._preview = None
            self.network.stop()
            self.balance = self.immature_balance = None
            return self.state()
        if command == "refresh": return self._refresh()
        if command == "faucet":
            self._unlocked(backed_up=True)
            self._preview = None
            return self._payment(self.network.faucet(protocol.address_for(self.keys)))
        if command == "prepare_send":
            self._unlocked(backed_up=True)
            self._preview = None
            prepared = self.network.prepare(self.keys, params["recipient"], params["amount"])
            preview_id = secrets.token_hex(16)
            self._preview = {
                "id": preview_id, "generation": self._generation,
                "commitment": self.keys["key_commitment"],
                "deadline": time.monotonic() + PREVIEW_SECONDS, "prepared": prepared,
            }
            return {"preview_id": preview_id, **prepared.public(), "expires_in": PREVIEW_SECONDS}
        if command == "confirm_send":
            session = self._unlocked(backed_up=True)
            # Consume before any signing/broadcast attempt. Retries always require
            # a fresh review, especially after a possibly successful broadcast.
            preview, self._preview = self._preview, None
            if (preview is None or not hmac.compare_digest(preview["id"], params["preview_id"])
                    or preview["generation"] != self._generation
                    or preview["commitment"] != self.keys["key_commitment"]
                    or time.monotonic() >= preview["deadline"]):
                raise AppError("preview_invalid")
            return self._payment(self.network.send(session, preview["prepared"]))
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
            self._preview = None
            if type(txid) is str and re.fullmatch(r"[0-9a-f]{64}", txid):
                self.recent_payment = {"txid": txid, "status": "pending", "message": MESSAGES["payment_pending"]}
                return {"id": request_id, "ok": False, "error": {
                    "code": "payment_pending", "message": MESSAGES["payment_pending"], "txid": txid}}
            code = "network_error"
        except AppError as error:
            code = error.code
        except NetworkError as error:
            # Map only known public codes to local fixed text, never echo details.
            code = error.code if error.code in NETWORK_CODES else "network_error"
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
