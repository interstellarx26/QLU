#!/usr/bin/env python3
"""Fresh-process, four-node acceptance of authenticated local backup verification.

Only fresh disposable wallets are used. Worker setup and test credentials use
anonymous stdin/stdout pipes, never command arguments, files, or reports.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import traceback
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import secure_directory
import protocol
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork


def worker():
    """A private test worker, never the default/user wallet-app directory."""
    setup = json.loads(sys.stdin.readline())
    identifier = setup["identifier"]
    if type(identifier) is not str or len(identifier) != 32 or any(c not in "0123456789abcdef" for c in identifier):
        raise ValueError
    directory = protocol.ROOT / ".local" / ("wallet-app-verification-" + identifier)
    network = WalletAppNetwork(data_name="wallet-app-verification-net-" + identifier,
                               process_label="QLUWalletAppVerification")
    app = WalletApp(app_dir=directory, network=network)
    def interrupt(signum, frame):
        raise SystemExit(1)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        print(json.dumps({"ready": True}), flush=True)
        for line in sys.stdin:
            envelope = json.loads(line)
            guarded = envelope.get("guard_payments") is True
            if guarded:
                original_rpc = network.controller.rpc
                calls = {"sign": 0, "broadcast": 0}
                def no_sign(*args, **kwargs):
                    calls["sign"] += 1
                    raise AssertionError("signing forbidden for this test operation")
                def no_broadcast(index, method, *args, **kwargs):
                    if method == "sendrawtransaction":
                        calls["broadcast"] += 1
                        raise AssertionError("new broadcast forbidden for this test operation")
                    return original_rpc(index, method, *args, **kwargs)
                with patch.object(app.session, "sign", side_effect=no_sign), \
                        patch.object(network.controller, "rpc", side_effect=no_broadcast):
                    response = app.handle(envelope["request"])
                output = {"response": response, "guard": calls}
            else:
                output = {"response": app.handle(envelope["request"])}
            print(json.dumps(output), flush=True)
            if app.closed:
                break
    finally:
        app.close()


class WalletProcess:
    def __init__(self, identifier):
        self.counter = 0
        self.last_command = None
        self.last_error_code = None
        self.process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1, cwd=protocol.ROOT)
        self.process.stdin.write(json.dumps({"identifier": identifier}) + "\n")
        self.process.stdin.flush()
        assert json.loads(self.process.stdout.readline()) == {"ready": True}

    def request(self, command, params=None, *, error=None, guarded=False):
        self.counter += 1
        self.last_command = command
        packet = {"guard_payments": guarded, "request": {
            "id": self.counter, "command": command, "params": params or {}}}
        self.process.stdin.write(json.dumps(packet) + "\n")
        self.process.stdin.flush()
        envelope = json.loads(self.process.stdout.readline())
        response = envelope["response"]
        self.last_error_code = response.get("error", {}).get("code")
        if guarded:
            assert envelope["guard"] == {"sign": 0, "broadcast": 0}
        if error is not None:
            assert response.get("ok") is False and self.last_error_code == error, command
            return response["error"]
        assert response.get("ok") is True, command
        return response["result"]

    def close(self):
        if self.process.poll() is None:
            try:
                self.request("quit")
            finally:
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.terminate()  # Worker SIGTERM still runs owned-node cleanup.
                    self.process.wait(timeout=30)
        if self.process.stdin is not None:
            self.process.stdin.close()
        if self.process.stdout is not None:
            self.process.stdout.close()


def run():
    identifier = uuid.uuid4().hex
    directory = protocol.ROOT / ".local/backup-verification-drills"
    secure_directory(directory)
    directory /= identifier
    secure_directory(directory)
    app_dir = protocol.ROOT / ".local" / ("wallet-app-verification-" + identifier)
    report = {"attempt": identifier, "started_at": datetime.now(timezone.utc).isoformat(),
              "passed": False, "checks": {}, "transactions": {},
              "scope": "Separate Python workers and real four-node restarts on one Mac, using only fresh private test wallets; no native UI or physical custody claim."}
    workers = []
    current = None
    def start():
        nonlocal current
        current = WalletProcess(identifier)
        workers.append(current)
        return current
    try:
        password = secrets.token_urlsafe(32)
        backup_path = directory / "backup.json"
        process = start()
        state = process.request("create", {"passphrase": password, "confirmation": password})
        wallet_path = state["wallet_path"]
        assert state["backup_verified"] is False
        process.request("faucet", {"operation_id": uuid.uuid4().hex}, error="backup_required")
        backup = process.request("backup_create", {"backup_path": str(backup_path)})
        offline_code = backup.pop("code")
        assert process.request("status")["backup_verified"] is False
        state = process.request("backup_verify", {"backup_path": str(backup_path), "code": offline_code})
        assert state["backup_verified"] is True
        address = state["address"]
        digest = hashlib.sha256(Path(wallet_path).read_bytes()).hexdigest()
        receipt_path = app_dir / "backup-verifications" / (digest + ".json")
        assert receipt_path.is_file()
        report["checks"]["verification_once_enrolls_vault_bound_receipt"] = True
        process.request("network_start")
        funding_id = uuid.uuid4().hex
        funding = process.request("faucet", {"operation_id": funding_id})["payment"]
        review = process.request("prepare_send", {"recipient": address, "amount": "0.25000000"})
        payment_id = review["preview_id"]
        payment = process.request("confirm_send", {"preview_id": payment_id})["payment"]
        assert process.request("refresh")["balance"] == "0.99900000"
        process.close()

        # A new operating-system process receives only the vault path and daily
        # passphrase. Its original backup path is absent and no recovery code is
        # sent to this worker during normal reopen/unlock/send.
        offline_backup = directory / "offline-backup.json"
        backup_path.rename(offline_backup)
        process = start()
        state = process.request("open", {"path": wallet_path})
        assert state["locked"] is True and state["backup_verified"] is False
        state = process.request("unlock", {"passphrase": password})
        assert state["backup_verified"] is True and state["address"] == address
        assert state["backup_verification_status"] == "remembered"
        state = process.request("network_start")
        assert state["balance"] == "0.99900000" and state["history_count"] == 2
        assert not state["payment_blocked"]
        report["checks"]["new_process_unlock_without_backup_or_code_restores_verification"] = True
        replay_funding = process.request("faucet", {"operation_id": funding_id}, guarded=True)["payment"]
        replay_payment = process.request("confirm_send", {"preview_id": payment_id}, guarded=True)["payment"]
        assert replay_funding["txid"] == funding["txid"] and replay_payment["txid"] == payment["txid"]
        assert process.request("refresh")["balance"] == "0.99900000"
        report["checks"]["history_and_duplicate_guard_survive_passphrase_only_restart"] = True
        review = process.request("prepare_send", {"recipient": address, "amount": "0.10000000"})
        next_payment = process.request("confirm_send", {"preview_id": review["preview_id"]})["payment"]
        assert next_payment["confirmed_nodes"] == 4
        assert process.request("refresh")["balance"] == "0.99800000"
        report["checks"]["new_reviewed_send_works_without_reentering_recovery_materials"] = True
        process.close()

        # Structurally valid local-receipt MAC corruption must close the gate.
        receipt = json.loads(receipt_path.read_bytes())
        tag = receipt["hmac_sha256"]
        receipt["hmac_sha256"] = ("0" if tag[0] != "0" else "1") + tag[1:]
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
        process = start()
        process.request("open", {"path": wallet_path})
        state = process.request("unlock", {"passphrase": password})
        assert state["backup_verified"] is False and state["address"] is None
        process.request("faucet", {"operation_id": uuid.uuid4().hex}, error="backup_required", guarded=True)
        process.request("prepare_send", {"recipient": address, "amount": "0.10000000"},
                        error="backup_required", guarded=True)
        report["checks"]["tampered_receipt_cannot_open_receive_or_send_gate"] = True

        # A genuine backup recovery creates a fresh immutable encrypted vault,
        # checks the supplied backup, and enrolls its own independent receipt.
        restored_password = secrets.token_urlsafe(32)
        state = process.request("restore", {"backup_path": str(offline_backup), "code": offline_code,
                                "passphrase": restored_password, "confirmation": restored_password})
        restored_path = state["wallet_path"]
        assert restored_path != wallet_path and state["backup_verified"] is True and state["address"] == address
        restored_digest = hashlib.sha256(Path(restored_path).read_bytes()).hexdigest()
        restored_receipt = app_dir / "backup-verifications" / (restored_digest + ".json")
        assert restored_digest != digest and restored_receipt.is_file()
        assert receipt_path.is_file() and Path(wallet_path).is_file()
        report["checks"]["genuine_recovery_enrolls_new_vault_and_preserves_original"] = True
        process.close()
        offline_code = None
        offline_backup.rename(directory / "retained-offline-backup.json")
        process = start()
        process.request("open", {"path": restored_path})
        state = process.request("unlock", {"passphrase": restored_password})
        assert state["backup_verified"] is True and state["address"] == address
        assert state["backup_verification_status"] == "remembered"
        state = process.request("network_start")
        assert state["balance"] == "0.99800000" and state["history_count"] == 3
        assert not state["payment_blocked"]
        replay = process.request("confirm_send", {"preview_id": payment_id}, guarded=True)["payment"]
        assert replay["txid"] == payment["txid"]
        report["checks"]["restored_vault_reopens_by_passphrase_only_with_same_history"] = True
        report["transactions"] = {"funding": funding["txid"], "first_send": payment["txid"],
                                  "post_restart_send": next_payment["txid"]}
        process.close()
        report["passed"] = True
    except BaseException as error:
        report["error_type"] = type(error).__name__
        report["error_location"] = [{"file": Path(frame.filename).name, "line": frame.lineno,
                                     "function": frame.name} for frame in traceback.extract_tb(error.__traceback__)]
        if current is not None:
            report["last_operation"] = {"command": current.last_command, "error_code": current.last_error_code}
        raise
    finally:
        cleanup = True
        for process in workers:
            try:
                process.close()
            except BaseException:
                cleanup = False
        report["cleanup"] = "owned-workers-and-nodes-stopped" if cleanup else "needs-attention"
        ports = {}
        for port in (*range(28440, 28444), *range(28540, 28544)):
            with socket.socket() as client:
                ports[str(port)] = client.connect_ex(("127.0.0.1", port)) != 0
        report["ports_free"] = ports
        report["passed"] = report["passed"] and cleanup and all(ports.values())
        report["worker_processes"] = len(workers)
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        report["source_sha256"] = {
            name: hashlib.sha256((protocol.ROOT / "qlu" / name).read_bytes()).hexdigest()
            for name in ("backup_verification.py", "vault.py", "wallet_app.py", "wallet_app_network.py",
                         "payment_history.py", "backup_verification_smoke.py")}
        evidence = protocol.ROOT / ".local/evidence"
        secure_directory(evidence)
        for destination in (directory / "result.json", evidence / "backup-verification-latest.json"):
            destination.write_text(json.dumps(report, indent=2) + "\n")
            destination.chmod(0o600)
    return report


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        worker()
    elif sys.argv[1:]:
        raise SystemExit("This isolated drill takes no arguments.")
    else:
        try:
            result = run()
            print(json.dumps(result, indent=2))
            raise SystemExit(0 if result["passed"] else 1)
        except Exception:
            print("QLU backup-verification drill failed; see its public evidence report.", file=sys.stderr)
            raise SystemExit(1)
