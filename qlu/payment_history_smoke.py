#!/usr/bin/env python3
"""Real four-node payment-history fault drill using only fresh private fixtures."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import socket
import sys
import time
import traceback
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import secure_directory
import protocol
from wallet_app import WalletApp
from wallet_app_network import WalletAppNetwork


class SimulatedCrash(BaseException):
    """Stop execution at a boundary without exposing fixture secret inputs."""


class Fixture:
    def __init__(self, directory, suffix):
        self.identifier = uuid.uuid4().hex
        self.app_dir = protocol.ROOT / ".local" / ("wallet-app-history-" + self.identifier)
        self.data_name = "wallet-app-history-net-" + self.identifier
        self.backup_path = directory / (suffix + "-backup.json")
        self.password = secrets.token_urlsafe(32)
        self.code = None
        self.path = None
        self.address = None
        self.app = None
        self.counter = 0
        self.last_command = None
        self.last_error_code = None
        self.new_owner()

    def new_owner(self):
        self.network = WalletAppNetwork(root=protocol.ROOT, data_name=self.data_name,
                                        process_label="QLUWalletAppHistory")
        self.app = WalletApp(root=protocol.ROOT, network=self.network, app_dir=self.app_dir)

    def request(self, command, params=None, *, error=None):
        self.counter += 1
        result = self.app.handle({"id": self.counter, "command": command, "params": params or {}})
        self.last_command = command
        self.last_error_code = result.get("error", {}).get("code")
        if error is not None:
            assert result.get("ok") is False and result.get("error", {}).get("code") == error, command
            return result["error"]
        assert result.get("ok") is True, command
        return result["result"]

    def create(self):
        state = self.request("create", {"passphrase": self.password, "confirmation": self.password})
        self.path = state["wallet_path"]
        backup = self.request("backup_create", {"backup_path": str(self.backup_path)})
        self.code = backup.pop("code")
        state = self.request("backup_verify", {"backup_path": str(self.backup_path), "code": self.code})
        self.address = state["address"]
        self.request("network_start")

    def restart(self):
        self.close()
        self.new_owner()
        self.request("open", {"path": self.path})
        state = self.request("unlock", {"passphrase": self.password})
        assert state["backup_verified"] is True and state["address"] == self.address
        return self.request("network_start")

    def funding(self):
        operation = uuid.uuid4().hex
        return operation, self.request("faucet", {"operation_id": operation})["payment"]

    def review(self, amount="0.10000000"):
        return self.request("prepare_send", {"recipient": self.address, "amount": amount})["preview_id"]

    def record(self, operation):
        return next(row for row in self.app.history.records() if row["operation_id"] == operation)

    def close(self):
        if self.app is not None:
            self.app.close()
        assert not self.network.running


def wait_pooled(network, txid):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if all(txid in network.controller.rpc(index, "getrawmempool") for index in range(4)):
            return
        time.sleep(0.1)
    raise AssertionError("existing transaction did not reach all private mempools")


def run():
    identifier = uuid.uuid4().hex
    directory = protocol.ROOT / ".local/payment-history-drills"
    secure_directory(directory)
    directory /= identifier
    secure_directory(directory)
    report = {"attempt": identifier, "started_at": datetime.now(timezone.utc).isoformat(),
              "passed": False, "checks": {}, "transactions": {},
              "scope": "Fresh fixture wallets; real four-node restart and injected bridge faults on one Mac. No user wallet, physical custody, or native UI claim."}
    fixtures = []

    def fixture(suffix):
        value = Fixture(directory, suffix)
        fixtures.append(value)
        value.create()
        return value

    try:
        good = fixture("confirmed")
        funding_id, funding = good.funding()
        operation = good.review("0.25000000")
        payment = good.request("confirm_send", {"preview_id": operation})["payment"]
        assert payment["confirmed_nodes"] == 4
        assert good.request("refresh")["balance"] == "0.99900000"
        report["checks"]["funding_and_reviewed_payment_persist"] = True
        state = good.restart()
        assert state["history_count"] == 2 and not state["payment_blocked"]
        assert all(row["status"] == "confirmed" for row in good.app.history.records())
        height = good.network.controller.rpc(0, "getblockcount")
        original_rpc = good.network.controller.rpc
        def forbid_new_payment(index, method, *args, **kwargs):
            assert method != "sendrawtransaction", "recovery must not broadcast a new payment"
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(good.app.session, "sign", side_effect=AssertionError("must not sign")), \
                patch.object(good.network.controller, "rpc", side_effect=forbid_new_payment):
            replay_funding = good.request("faucet", {"operation_id": funding_id})["payment"]
            replay_payment = good.request("confirm_send", {"preview_id": operation})["payment"]
        assert replay_funding["txid"] == funding["txid"] and replay_payment["txid"] == payment["txid"]
        assert good.network.controller.rpc(0, "getblockcount") == height
        assert good.request("refresh")["balance"] == "0.99900000"
        report["checks"]["passphrase_only_restart_preserves_verified_backup_and_exact_token_replay"] = True

        # Spend every output from the first self-payment. Its historical inclusion
        # remains confirmed even though gettxout can no longer find an output.
        later_id = good.review("0.99800000")
        later = good.request("confirm_send", {"preview_id": later_id})["payment"]
        for index in range(4):
            for output in (0, 1):
                assert not good.network.controller.rpc(index, "gettxout", payment["txid"], output, True)
        assert good.network.payment_status(good.record(operation))["status"] == "confirmed"
        report["checks"]["spent_outputs_do_not_erase_historical_confirmation"] = True

        # This affects only this fresh fixture's four owned nodes. The old active
        # confirmation is removed, then the same previously signed txid is mined.
        for index in range(4):
            good.network.controller.rpc(index, "invalidateblock", later["block"])
        good.network.controller.wait_synced()
        wait_pooled(good.network, later["txid"])
        state = good.request("refresh")
        assert state["payment_blocked"] and good.record(later_id)["status"] == "pending"
        good.network._faucet_wallet = good.network._faucet_keys = None
        original_rpc = good.network.controller.rpc
        generated = []
        def same_existing_transaction(index, method, *args, **kwargs):
            assert method != "sendrawtransaction", "must not rebroadcast"
            if method == "generateblock":
                generated.append(args[1])
                assert args[1] == [later["txid"]]
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(good.app.session, "sign", side_effect=AssertionError("must not sign")), \
                patch.object(good.network.controller, "rpc", side_effect=same_existing_transaction):
            state = good.request("recover_payments")
        assert generated == [[later["txid"]]] and not state["payment_blocked"]
        assert good.record(later_id)["status"] == "confirmed"
        assert good.record(later_id)["block"] != later["block"]
        report["checks"]["confirmed_reorg_is_pending_then_same_tx_reconfirmed"] = True
        report["transactions"]["confirmed"] = payment["txid"]
        report["transactions"]["reorg_reconfirmed"] = later["txid"]

        # Corrupt only this fixture's journal. No reset, deletion, or replacement
        # is attempted; the fixture remains for public diagnostic inspection.
        journal = good.app.history.directory / (good.app.history.wallet_id + ".json")
        journal.write_bytes(b'{"injected_corruption":true}\n')
        with patch.object(good.network.controller, "rpc", side_effect=forbid_new_payment):
            good.request("prepare_send", {"recipient": good.address, "amount": "0.10000000"},
                         error="history_unavailable")
        report["checks"]["corrupt_journal_refuses_new_payment"] = True
        good.close()

        before = fixture("before-broadcast")
        before.funding()
        operation = before.review()
        durable = before.app.history.before_broadcast
        def crash_after_record(operation_id, metadata):
            durable(operation_id, metadata)
            raise SimulatedCrash()
        with patch.object(before.app.history, "before_broadcast", side_effect=crash_after_record):
            try:
                before.request("confirm_send", {"preview_id": operation})
            except SimulatedCrash:
                pass
            else:
                raise AssertionError("crash boundary was not reached")
        txid = before.record(operation)["txid"]
        assert all(txid not in before.network.controller.rpc(i, "getrawmempool") for i in range(4))
        state = before.restart()
        assert state["payment_blocked"] and before.record(operation)["status"] == "pending"
        before.request("prepare_send", {"recipient": before.address, "amount": "0.10000000"}, error="payment_pending")
        before.request("faucet", {"operation_id": uuid.uuid4().hex}, error="payment_pending")
        before.request("confirm_send", {"preview_id": operation}, error="payment_pending")
        height = before.network.controller.rpc(0, "getblockcount")
        state = before.request("recover_payments")
        assert state["payment_blocked"] and before.record(operation)["status_reason"] == "not_found"
        assert before.network.controller.rpc(0, "getblockcount") == height
        report["checks"]["crash_after_durable_record_before_broadcast_stays_pending_on_restart"] = True
        report["transactions"]["prebroadcast_uncertain"] = txid
        before.close()

        after = fixture("after-broadcast")
        after.funding()
        operation = after.review()
        original_rpc = after.network.controller.rpc
        def lose_broadcast_response(index, method, *args, **kwargs):
            result = original_rpc(index, method, *args, **kwargs)
            if method == "sendrawtransaction":
                raise TimeoutError()
            return result
        with patch.object(after.network.controller, "rpc", side_effect=lose_broadcast_response):
            result = after.request("confirm_send", {"preview_id": operation}, error="payment_pending")
        txid = result["txid"]
        wait_pooled(after.network, txid)
        state = after.restart()
        wait_pooled(after.network, txid)
        assert state["payment_blocked"]
        original_rpc = after.network.controller.rpc
        generated = []
        def finish_existing(index, method, *args, **kwargs):
            assert method != "sendrawtransaction", "must not rebroadcast"
            if method == "generateblock":
                generated.append(args[1])
                assert args[1] == [txid]
            return original_rpc(index, method, *args, **kwargs)
        with patch.object(after.app.session, "sign", side_effect=AssertionError("must not sign")), \
                patch.object(after.network.controller, "rpc", side_effect=finish_existing):
            state = after.request("recover_payments")
            replay = after.request("confirm_send", {"preview_id": operation})["payment"]
        assert generated == [[txid]] and not state["payment_blocked"]
        assert replay["txid"] == txid and replay["confirmed_nodes"] == 4
        assert after.request("refresh")["balance"] == "0.99900000"
        report["checks"]["broadcast_timeout_survives_restart_and_finishes_same_tx_without_signing"] = True
        report["transactions"]["timeout_recovered"] = txid
        after.close()
        report["passed"] = True
    except BaseException as error:
        report["error_type"] = type(error).__name__
        report["error_location"] = [{"file": Path(frame.filename).name, "line": frame.lineno,
                                     "function": frame.name} for frame in traceback.extract_tb(error.__traceback__)]
        report["last_operations"] = [{"command": item.last_command, "error_code": item.last_error_code}
                                     for item in fixtures]
        raise
    finally:
        cleanup = True
        for item in fixtures:
            try:
                item.close()
            except BaseException:
                cleanup = False
        report["cleanup"] = "owned-nodes-stopped" if cleanup else "needs-attention"
        report["passed"] = report["passed"] and cleanup
        ports = {}
        for port in (*range(28440, 28444), *range(28540, 28544)):
            with socket.socket() as client:
                ports[str(port)] = client.connect_ex(("127.0.0.1", port)) != 0
        report["ports_free"] = ports
        report["passed"] = report["passed"] and all(ports.values())
        report["completed_at"] = datetime.now(timezone.utc).isoformat()
        report["source_sha256"] = {
            name: hashlib.sha256((protocol.ROOT / "qlu" / name).read_bytes()).hexdigest()
            for name in ("payment_history.py", "wallet_app.py", "wallet_app_network.py", "payment_history_smoke.py")}
        evidence = protocol.ROOT / ".local/evidence"
        secure_directory(evidence)
        for destination in (directory / "result.json", evidence / "payment-history-latest.json"):
            destination.write_text(json.dumps(report, indent=2) + "\n")
            destination.chmod(0o600)
    return report


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 1)
    except Exception:
        print("QLU payment-history drill failed; see its public evidence report.", file=sys.stderr)
        raise SystemExit(1)
