"""Native-wallet bridge boundaries; real encrypted vaults, no actual test nodes."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from qlu import wallet_app

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
    def send(self, session, prepared):
        self.sent.append((session, prepared))
        if self.send_error: raise self.send_error
        return self.receipt()
    def faucet(self, address):
        self.funded.append(address)
        return self.receipt()
    @staticmethod
    def receipt():
        return {"txid": TXID, "block": "cd" * 32, "amount": "1.00000000", "fee": "0.00100000",
                "recipient": "public fixture recipient", "confirmed_nodes": 4}


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
        return self.success("prepare_send", recipient="qlud-public-fixture", amount="1.00000000")

    def test_starts_empty_locked_without_network_or_files(self):
        state = self.success("status")
        self.assertFalse(state["wallet_open"])
        self.assertTrue(state["locked"])
        self.assertIsNone(state["address"])
        self.assertEqual(state["network"], "qludev")
        self.assertFalse(state["network_running"])
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

    def test_open_starts_locked_resets_backup_gate_and_preserves_vault(self):
        code = self.backed_up()
        path = self.app.wallet_path
        initial = path.read_bytes()
        old_session = self.app.session
        state = self.success("open", path=str(path))
        self.assertTrue(old_session.locked)
        self.assertTrue(state["locked"])
        self.assertFalse(state["backup_verified"])
        self.assertIsNone(state["address"])
        self.success("unlock", passphrase=PASS)
        self.assertIsNone(self.app.state()["address"])
        self.success("backup_verify", backup_path=str(self.backup), code=code)
        self.assertIsNotNone(self.app.state()["address"])
        self.assertEqual(path.read_bytes(), initial)

    def test_wrong_unlock_locks_and_redacts_passphrase(self):
        self.backed_up()
        preview = self.review()
        result = self.request("unlock", passphrase=OTHER_PASS)
        self.assertFalse(result["ok"])
        self.assertNotIn(OTHER_PASS, json.dumps(result))
        self.assertTrue(self.app.session.locked)
        self.assertIsNone(self.app._preview)
        self.success("unlock", passphrase=PASS)
        self.assertFalse(self.request("confirm_send", preview_id=preview["preview_id"])["ok"])
        self.assertFalse(self.network.sent)

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
        self.assertEqual(again["error"]["code"], "preview_invalid")
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
