#!/usr/bin/env python3
"""Exercise the native app's bridge and real four-node payments with fresh fixtures."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import secure_directory
import protocol
import recovery
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork


def run():
    identifier = uuid.uuid4().hex
    directory = protocol.ROOT / ".local/wallet-app-drills"
    secure_directory(directory)
    directory /= identifier
    secure_directory(directory)
    network = WalletAppNetwork(
        root=protocol.ROOT, data_name="wallet-app-drill-" + identifier,
        process_label="QLUWalletAppDrill",
    )
    app = WalletApp(root=protocol.ROOT, network=network,
                    app_dir=protocol.ROOT / ".local" / ("wallet-app-fixture-" + identifier))
    report = {
        "attempt": identifier, "started_at": datetime.now(timezone.utc).isoformat(),
        "passed": False, "checks": {}, "scope": "Automated bridge and four-node drill on one Mac; not physical custody or native UI acceptance",
    }
    counter = 0

    def request(command, params=None, error=None):
        nonlocal counter
        counter += 1
        response = app.handle({"id": counter, "command": command, "params": params or {}})
        if error:
            if response.get("ok") is not False or response.get("error", {}).get("code") != error:
                raise RuntimeError("Expected application refusal was not observed: " + command)
            return response["error"]
        if response.get("ok") is not True:
            raise RuntimeError("Application operation failed: " + command)
        return response["result"]

    try:
        password = secrets.token_urlsafe(32)
        state = request("create", {"passphrase": password, "confirmation": password})
        source_path = Path(state["wallet_path"])
        assert state["address"] is None
        request("faucet", error="backup_required")
        report["checks"]["fresh_encrypted_wallet_gated_by_backup"] = True
        backup_path = directory / "source-backup.json"
        backup = request("backup_create", {"backup_path": str(backup_path)})
        code = backup.pop("code")
        state = request("backup_verify", {"backup_path": str(backup_path), "code": code})
        source_address = state["address"]
        assert source_address.startswith("qlud1")
        report["checks"]["saved_backup_readback_unlocks_receiving"] = True

        request("network_start")
        payment = request("faucet")["payment"]
        assert payment["confirmed_nodes"] == 4 and payment["amount"] == "1.00000000"
        state = request("refresh")
        assert state["balance"] == "1.00000000"
        report["checks"]["receive_test_funds_confirmed_four_nodes"] = True

        # Make a second, independently encrypted recipient wallet via the same app.
        recipient_password = secrets.token_urlsafe(32)
        request("create", {"passphrase": recipient_password, "confirmation": recipient_password})
        recipient_backup_path = directory / "recipient-backup.json"
        recipient_backup = request("backup_create", {"backup_path": str(recipient_backup_path)})
        recipient_state = request("backup_verify", {
            "backup_path": str(recipient_backup_path), "code": recipient_backup.pop("code")})
        recipient = recipient_state["address"]
        recipient_script = protocol.script_for(app.session.public_keys())
        del recipient_password, recipient_backup

        state = request("open", {"path": str(source_path)})
        assert state["locked"] is True and state["backup_verified"] is False
        request("unlock", {"passphrase": "Deliberately incorrect fixture password"}, error="wallet_failed")
        state = request("unlock", {"passphrase": password})
        assert state["address"] is None
        request("backup_verify", {"backup_path": str(backup_path), "code": code})
        report["checks"]["reopen_locked_wrong_password_rejected_backup_rechecked"] = True

        review = request("prepare_send", {"recipient": recipient, "amount": "0.25000000"})
        assert review["fee"] == "0.00100000" and review["total"] == "0.25100000"
        request("cancel_send")
        request("confirm_send", {"preview_id": review["preview_id"]}, error="preview_invalid")
        review = request("prepare_send", {"recipient": recipient, "amount": "0.25000000"})
        request("lock")
        request("confirm_send", {"preview_id": review["preview_id"]}, error="locked")
        request("unlock", {"passphrase": password})
        request("confirm_send", {"preview_id": review["preview_id"]}, error="preview_invalid")
        report["checks"]["cancel_and_lock_invalidate_review"] = True

        review = request("prepare_send", {"recipient": recipient, "amount": "0.25000000"})
        payment = request("confirm_send", {"preview_id": review["preview_id"]})["payment"]
        assert payment["confirmed_nodes"] == 4
        request("confirm_send", {"preview_id": review["preview_id"]}, error="preview_invalid")
        assert request("refresh")["balance"] == "0.74900000"
        report["checks"]["reviewed_payment_exact_fee_change_and_one_use"] = True
        report["first_payment"] = payment

        request("lock")
        # Move only this drill's own encrypted source out of its working location.
        source_path.rename(directory / "retired-source.vault.json")
        restored_password = secrets.token_urlsafe(32)
        state = request("restore", {
            "backup_path": str(backup_path), "code": code,
            "passphrase": restored_password, "confirmation": restored_password,
        })
        del password, restored_password, code
        assert state["address"] == source_address and state["backup_verified"] is True
        assert Path(state["wallet_path"]) != source_path and not source_path.exists()
        assert request("refresh")["balance"] == "0.74900000"
        report["checks"]["restore_to_fresh_encrypted_vault_rediscovers_balance"] = True

        review = request("prepare_send", {"recipient": recipient, "amount": "0.10000000"})
        recovered_payment = request("confirm_send", {"preview_id": review["preview_id"]})["payment"]
        assert recovered_payment["confirmed_nodes"] == 4
        assert request("refresh")["balance"] == "0.64800000"
        assert network.balance(recipient_script)["balance"] == "0.35000000"
        report["checks"]["restored_wallet_sends_confirmed_payment"] = True
        report["recovered_payment"] = recovered_payment
        request("network_stop")
        request("network_start")
        assert request("refresh")["balance"] == "0.64800000"
        assert network.balance(recipient_script)["balance"] == "0.35000000"
        report["checks"]["balances_survive_four_node_restart"] = True
        request("quit")
        app.close()
        assert not network.running
        report["checks"]["quit_locks_and_stops_owned_nodes"] = True
        report["passed"] = True
    except BaseException as error:
        # Exception text is deliberately excluded: fixtures contain secret input.
        report["error_type"] = type(error).__name__
        raise
    finally:
        try:
            app.close()
            report["cleanup"] = "owned-nodes-stopped"
        except Exception:
            report["cleanup"] = "needs-attention"
            report["passed"] = False
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        report["source_sha256"] = {
            name: hashlib.sha256((protocol.ROOT / "qlu" / name).read_bytes()).hexdigest()
            for name in ("wallet_app.py", "wallet_app_network.py", "wallet_app_smoke.py", "vault.py")
        }
        evidence = protocol.ROOT / ".local/evidence"
        secure_directory(evidence)
        for destination in (directory / "result.json", evidence / "wallet-app-latest.json"):
            destination.write_text(json.dumps(report, indent=2) + "\n")
            destination.chmod(0o600)
    return report


if __name__ == "__main__":
    try:
        print(json.dumps(run(), indent=2))
    except Exception:
        print("QLU wallet app drill failed; inspect its public result under .local/evidence.", file=sys.stderr)
        raise SystemExit(1)
