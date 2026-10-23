#!/usr/bin/env python3
"""Real stalled password-helper recovery using disposable private wallets.

Only this test process replaces the helper command and deadline. The replacement
is a real child that consumes its anonymous-pipe input, records only its PID in
the disposable fixture, and stalls. Production sources and binaries are not
modified; no user wallet, passphrase, or recovery code is used.
"""
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import traceback
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import secure_directory
import protocol
import recovery
import vault
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork


class StopBeforeBroadcast(BaseException):
    """End one synthetic authorization after durable publication, before RPC."""


def fixture_paths(identifier):
    if type(identifier) is not str or re.fullmatch(r"[0-9a-f]{32}", identifier) is None:
        raise ValueError("Invalid password-helper fixture identifier")
    return (protocol.ROOT / ".local" / ("wallet-app-kdf-" + identifier),
            protocol.ROOT / ".local/kdf-timeout-drills" / identifier,
            "wallet-app-kdf-net-" + identifier)


def ports_free():
    result = {}
    for port in (*range(28440, 28444), *range(28540, 28544)):
        with socket.socket() as client:
            result[str(port)] = client.connect_ex(("127.0.0.1", port)) != 0
    return result


def write_hung_helper(directory):
    """Create a test helper with no secret-bearing output or retained payload."""
    path = Path(directory) / "hung-password-helper.py"
    source = (
        "import os, sys, time\n"
        "sys.stdin.buffer.read(4096)\n"
        "fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
        "with os.fdopen(fd, 'w') as stream:\n"
        "    stream.write(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    recovery.write_private(path, source.encode("ascii"))
    return path


@contextmanager
def hung_derivation(helper, directory, observations, *, timeout=1.0):
    """Force one real child timeout and verify that exact child was reaped."""
    module = vault.vault_kdf
    deadline_seconds = module.DERIVATION_TIMEOUT_SECONDS if timeout is None else timeout
    marker = Path(directory) / ("started-" + uuid.uuid4().hex + ".pid")
    children = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    started = time.monotonic()
    try:
        with patch.object(module, "_worker_command", return_value=[sys.executable, "-I", str(helper), str(marker)]), \
                (nullcontext() if timeout is None else patch.object(module, "DERIVATION_TIMEOUT_SECONDS", timeout)), \
                patch.object(module.subprocess, "Popen", side_effect=launch):
            yield
        elapsed = time.monotonic() - started
        assert len(children) == 1, "The fault must launch exactly one isolated helper"
        child = children[0]
        assert marker.read_text() == str(child.pid), "The helper must enter its stalled body"
        # Do not poll here: poll() could itself reap a leaked zombie and make
        # deficient production cleanup appear successful.
        assert child.returncode is not None, "The deadline must reap the exact helper"
        try:
            os.waitpid(child.pid, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError("The helper must already be reaped")
        assert elapsed < deadline_seconds + 4, "The deadline must bound failure and cleanup"
        observations.append({"deadline_seconds": deadline_seconds, "production_deadline": timeout is None,
                             "elapsed_seconds": round(elapsed, 3),
                             "helper_started": True, "helper_reaped": True,
                             "returncode": child.returncode})
    finally:
        # Failure cleanup targets only exact children created by this context.
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


@contextmanager
def no_payments(network, calls):
    original_rpc = network.controller.rpc

    def no_sign(*args, **kwargs):
        calls["sign"] += 1
        raise AssertionError("Password failure and retry must not sign")

    def read_only(index, method, *args, **kwargs):
        if method in {"sendrawtransaction", "generateblock", "generatetoaddress"}:
            calls["broadcast_or_mine"] += 1
            raise AssertionError("Password failure and retry must not broadcast or mine")
        return original_rpc(index, method, *args, **kwargs)

    with patch.object(vault.WalletSession, "sign", side_effect=no_sign), \
            patch.object(protocol, "sign_transaction", side_effect=no_sign), \
            patch.object(network.controller, "rpc", side_effect=read_only):
        yield


def run():
    if not __debug__:
        raise RuntimeError("This assertion-based private drill refuses optimized Python")
    identifier = uuid.uuid4().hex
    app_dir, directory, data_name = fixture_paths(identifier)
    secure_directory(directory.parent)
    secure_directory(directory)
    helper = write_hung_helper(directory)
    network = WalletAppNetwork(root=protocol.ROOT, data_name=data_name, process_label="QLUWalletAppKDF")
    app = WalletApp(root=protocol.ROOT, network=network, app_dir=app_dir)
    names = ("kdf_timeout_smoke.py", "vault.py", "vault_kdf.py", "vault_kdf_worker.py", "vault_kdf_lock.py", "wallet_app.py",
             "wallet_app_network.py", "payment_history.py", "payment_resume.py", "backup_verification.py",
             "protocol.py", "recovery.py", "private_net.py", "devnet.py")
    hashes = lambda: {name: hashlib.sha256((protocol.ROOT / "qlu" / name).read_bytes()).hexdigest() for name in names}
    binaries = lambda: {name: hashlib.sha256((protocol.ROOT / "build/qlu-foundation/bin" / name).read_bytes()).hexdigest()
                        for name in ("bitcoind", "bitcoin-cli", "qlu-keytool")}
    report = {"attempt": identifier, "started_at": datetime.now(timezone.utc).isoformat(), "passed": False,
              "checks": {}, "timeouts": [], "source_sha256_at_start": hashes(), "binary_sha256_at_start": binaries(),
              "scope": "Fresh encrypted fixtures, real stalled helper children, and four loopback qludev nodes. "
                       "The production deadline and shorter test-only deadlines exercise production timeout cleanup. "
                       "No user wallets, public peers, native UI, physical-device or power-loss durability claim."}
    counter, last_operation = 0, {}
    calls = {"sign": 0, "broadcast_or_mine": 0}

    def request(command, params=None, *, error=None):
        nonlocal counter, last_operation
        counter += 1
        result = app.handle({"id": counter, "command": command, "params": params or {}})
        last_operation = {"command": command, "error_code": result.get("error", {}).get("code")}
        if error is not None:
            assert result.get("ok") is False and result["error"]["code"] == error, command
            return result["error"]
        assert result.get("ok") is True, command
        return result["result"]

    def locked_and_cleared():
        state = request("status")
        assert state["locked"] and not state["backup_verified"] and state["address"] is None
        assert not state["history_loaded"] and state["payment_history"] == []
        assert state["balance"] is None and state["recent_payment"] is None and state["pending_payment"] is None
        assert app._preview is None and app.keys is None
        return state

    try:
        assert all(ports_free().values())
        password = secrets.token_urlsafe(32)
        with no_payments(network, calls), hung_derivation(helper, directory, report["timeouts"], timeout=None):
            request("create", {"passphrase": password, "confirmation": password}, error="wallet_failed")
        assert list((app_dir / "wallets").iterdir()) == []
        assert not locked_and_cleared()["wallet_open"]
        report["checks"]["stalled_create_returns_without_publishing_vault"] = True

        state = request("create", {"passphrase": password, "confirmation": password})
        wallet_path = Path(state["wallet_path"])
        backup = directory / "backup.json"
        code = request("backup_create", {"backup_path": str(backup)})["code"]
        state = request("backup_verify", {"backup_path": str(backup), "code": code})
        address, commitment = state["address"], app.keys["key_commitment"]
        vault_bytes = wallet_path.read_bytes()
        receipt_path = app_dir / "backup-verifications" / (hashlib.sha256(vault_bytes).hexdigest() + ".json")
        receipt_bytes = receipt_path.read_bytes()
        request("network_start")
        funding = request("faucet", {"operation_id": uuid.uuid4().hex})["payment"]
        preview = request("prepare_send", {"recipient": address, "amount": "0.10000000"})
        confirmed_operation = preview["preview_id"]
        confirmed = request("confirm_send", {"preview_id": confirmed_operation})["payment"]
        assert confirmed["confirmed_nodes"] == 4 and request("refresh")["balance"] == "0.99900000"
        journal_path = app_dir / "payment-history" / (commitment + ".json")
        journal_bytes = journal_path.read_bytes()
        rows = app.history.records()
        stale = request("prepare_send", {"recipient": address, "amount": "0.01000000"})

        with no_payments(network, calls):
            with hung_derivation(helper, directory, report["timeouts"]):
                request("unlock", {"passphrase": password}, error="wallet_failed")
            assert locked_and_cleared()["wallet_open"]
            request("confirm_send", {"preview_id": stale["preview_id"]}, error="locked")
            assert journal_path.read_bytes() == journal_bytes and wallet_path.read_bytes() == vault_bytes
            assert receipt_path.read_bytes() == receipt_bytes
            report["checks"]["stalled_reunlock_revokes_old_authority_preview_and_backup_gate"] = True
            state = request("unlock", {"passphrase": password})
            assert state["address"] == address and app.keys["key_commitment"] == commitment
            assert state["backup_verified"] and state["backup_verification_status"] == "remembered"
            assert app.history.records() == rows and not state["payment_blocked"]
            request("confirm_send", {"preview_id": stale["preview_id"]}, error="preview_invalid")
            assert request("refresh")["balance"] == "0.99900000"
            assert journal_path.read_bytes() == journal_bytes
            report["checks"]["correct_retry_restores_same_wallet_and_receipt_without_reviving_old_review"] = True

        # Preserve an actual signed but unbroadcast operation to exercise its
        # existing duplicate guard across failure, recovery, and app restart.
        pending_review = request("prepare_send", {"recipient": address, "amount": "0.02000000"})
        durable = app.history.before_broadcast

        def stop_after_record(operation, metadata):
            durable(operation, metadata)
            raise StopBeforeBroadcast()

        with patch.object(app.history, "before_broadcast", side_effect=stop_after_record):
            try:
                request("confirm_send", {"preview_id": pending_review["preview_id"]})
            except StopBeforeBroadcast:
                pass
            else:
                raise AssertionError("The durable unbroadcast fixture boundary was not reached")
        assert request("refresh")["payment_blocked"]
        pending_operation = pending_review["preview_id"]
        pending = next(row for row in app.history.records() if row["operation_id"] == pending_operation)
        assert pending["status"] == "pending" and pending["status_reason"] == "not_found"
        assert all(pending["txid"] not in network.controller.rpc(index, "getrawmempool") for index in range(4))
        journal_bytes = journal_path.read_bytes()
        rows = app.history.records()
        with no_payments(network, calls):
            with hung_derivation(helper, directory, report["timeouts"]):
                request("unlock", {"passphrase": password}, error="wallet_failed")
            locked_and_cleared()
            assert journal_path.read_bytes() == journal_bytes
            state = request("unlock", {"passphrase": password})
            assert state["backup_verified"] and state["payment_blocked"] and app.history.records() == rows
            request("prepare_send", {"recipient": address, "amount": "0.01000000"}, error="payment_pending")
            existing_files = set((app_dir / "wallets").iterdir())
            with hung_derivation(helper, directory, report["timeouts"]):
                request("restore", {"backup_path": str(backup), "code": code,
                                    "passphrase": password, "confirmation": password}, error="wallet_failed")
            assert set((app_dir / "wallets").iterdir()) == existing_files
            assert not locked_and_cleared()["wallet_open"]
            assert journal_path.read_bytes() == journal_bytes and wallet_path.read_bytes() == vault_bytes
            assert receipt_path.read_bytes() == receipt_bytes
        report["checks"]["stalled_restore_publishes_nothing_and_preserves_existing_journal_and_receipt"] = True

        app.close()
        assert all(ports_free().values())
        network = WalletAppNetwork(root=protocol.ROOT, data_name=data_name, process_label="QLUWalletAppKDF")
        app = WalletApp(root=protocol.ROOT, network=network, app_dir=app_dir)
        request("open", {"path": str(wallet_path)})
        state = request("unlock", {"passphrase": password})
        assert state["address"] == address and state["backup_verified"] and state["payment_blocked"]
        assert state["backup_verification_status"] == "remembered" and app.history.records() == rows
        assert journal_path.read_bytes() == journal_bytes
        request("network_start")
        with no_payments(network, calls):
            request("prepare_send", {"recipient": address, "amount": "0.01000000"}, error="payment_pending")
            replay = request("confirm_send", {"preview_id": confirmed_operation})["payment"]
            assert replay["txid"] == confirmed["txid"]
            assert request("refresh")["balance"] == "0.99900000"
        report["checks"]["restart_preserves_pending_guard_and_confirmed_payment_identity"] = True

        review = request("prepare_resume", {"operation_id": pending_operation})
        assert review["txid"] == pending["txid"] and review["amount"] == "0.02000000"
        resumed = request("confirm_resume", {"resume_id": review["resume_id"]})["payment"]
        assert resumed["txid"] == pending["txid"] and resumed["confirmed_nodes"] == 4
        assert request("refresh")["balance"] == "0.99800000"
        height = network.controller.rpc(0, "getblockcount")
        rows = app.history.records()
        assert len(rows) == 3 and all(row["status"] == "confirmed" for row in rows)
        with no_payments(network, calls):
            replay = request("confirm_send", {"preview_id": pending_operation})["payment"]
            assert replay["txid"] == pending["txid"]
            request("confirm_resume", {"resume_id": review["resume_id"]}, error="resume_invalid")
            assert request("refresh")["balance"] == "0.99800000" and app.history.records() == rows
            assert network.controller.rpc(0, "getblockcount") == height
        report["checks"]["explicit_review_resumes_exact_payment_once_and_duplicate_retries_are_read_only"] = True
        assert calls == {"sign": 0, "broadcast_or_mine": 0}
        assert wallet_path.read_bytes() == vault_bytes and receipt_path.read_bytes() == receipt_bytes
        report["checks"]["password_failures_and_retries_have_zero_payment_side_effects"] = True
        report["guard_calls"] = calls
        report["transactions"] = {"funding": funding["txid"], "first_send": confirmed["txid"], "resumed": resumed["txid"]}
        report["final_balance"] = "0.99800000"
        report["passed"] = True
    except BaseException as error:
        report["error_type"] = type(error).__name__
        report["error_location"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                    for frame in traceback.extract_tb(error.__traceback__)]
        report["last_operation"] = last_operation
        raise
    finally:
        cleanup = True
        try:
            app.close()
        except BaseException:
            cleanup = False
        report["cleanup"] = "owned-helpers-and-nodes-stopped" if cleanup else "needs-attention"
        report["ports_free"] = ports_free()
        report["source_sha256_at_end"] = hashes()
        report["source_unchanged"] = report["source_sha256_at_start"] == report["source_sha256_at_end"]
        report["binary_sha256_at_end"] = binaries()
        report["binaries_unchanged"] = report["binary_sha256_at_start"] == report["binary_sha256_at_end"]
        report["passed"] = report["passed"] and cleanup and all(report["ports_free"].values()) and report["source_unchanged"] and report["binaries_unchanged"]
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        evidence = protocol.ROOT / ".local/evidence"
        secure_directory(evidence)
        for destination in (directory / "result.json", evidence / "kdf-timeout-latest.json"):
            destination.write_text(json.dumps(report, indent=2) + "\n")
            destination.chmod(0o600)
    return report


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception:
        print("QLU password-helper drill failed; inspect its public evidence report.", file=sys.stderr)
        raise SystemExit(1)
