"""Safety tests for the controller, separate from the real-node smoke test."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import subprocess
import unittest
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location("devnet", Path(__file__).parents[1] / "devnet.py")
devnet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(devnet)


class DevnetSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.controller = devnet.Devnet(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_config_is_loopback_only_and_has_unique_ports(self):
        ports = set()
        for index in range(4):
            config = devnet.configuration(index)
            for required in ("regtest=1", "discover=0", "dnsseed=0", "fixedseeds=0",
                             "dns=0", "listenonion=0", "i2pacceptincoming=0", "onion=0",
                             "natpmp=0", "privatebroadcast=0", "rpcallowip=127.0.0.1"):
                self.assertIn(required + "\n", config)
            self.assertNotIn("upnp=", config)  # Removed in pinned upstream.
            self.assertNotIn("rpcpassword", config)
            self.assertNotIn("includeconf", config)
            maximum = int(next(line.split("=", 1)[1] for line in config.splitlines() if line.startswith("maxconnections=")))
            # Bitcoin Core reserves eleven outbound/feeler slots even when
            # using connect-only peers; every node needs three inbound slots.
            self.assertGreaterEqual(maximum - (8 + 2 + 1), 3)
            lines = config.splitlines()
            connections = [line.split("=", 1)[1] for line in lines if line.startswith("connect=")]
            self.assertEqual(set(connections), {f"127.0.0.1:{19440 + peer}" for peer in range(4) if peer != index})
            for prefix in ("bind=", "rpcbind="):
                self.assertTrue(next(line for line in lines if line.startswith(prefix)).startswith(prefix + "127.0.0.1:"))
            ports.update((19440 + index, 19540 + index))
        self.assertEqual(len(ports), 8)

    def test_setup_preserves_existing_data_and_private_permissions(self):
        self.controller.setup()
        sentinel = self.controller.node(0) / "keep-me"
        sentinel.write_text("existing data")
        self.controller.setup()
        self.assertEqual(sentinel.read_text(), "existing data")
        self.assertEqual(self.controller.node(0).stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.controller.node(0) / "bitcoin.conf").stat().st_mode & 0o777, 0o600)

    def test_tampered_config_is_not_overwritten(self):
        self.controller.setup()
        config = self.controller.node(0) / "bitcoin.conf"
        config.write_text("regtest=0\n")
        with self.assertRaises(devnet.DevnetError):
            self.controller.setup()
        self.assertEqual(config.read_text(), "regtest=0\n")

    def test_symlink_data_directory_refused(self):
        outside = self.root / "unrelated"
        outside.mkdir()
        (self.root / ".local").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(devnet.DevnetError):
            self.controller.setup()
        self.assertEqual(list(outside.iterdir()), [])

    def test_nested_symlink_refused(self):
        self.controller.setup()
        (self.controller.node(0) / "regtest").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(devnet.DevnetError):
            self.controller.setup()

    def test_hardlinked_configuration_refused_before_permission_changes(self):
        self.controller.setup()
        outside = self.root / "unrelated-config"
        outside.write_text("keep untouched")
        outside.chmod(0o644)
        config = self.controller.node(0) / "bitcoin.conf"
        config.unlink()
        os.link(outside, config)
        with self.assertRaisesRegex(devnet.DevnetError, "Hard links"):
            self.controller.setup()
        self.assertEqual(outside.stat().st_mode & 0o777, 0o644)

    def test_reused_pid_cannot_be_stopped(self):
        self.controller.setup()
        self.controller.save_state({"0": {"pid": 12345, "token": "a" * 32}})
        with patch.object(self.controller, "pid_command", return_value="unrelated-program"), \
                patch.object(self.controller, "rpc") as rpc:
            with self.assertRaisesRegex(devnet.DevnetError, "ownership mismatch"):
                self.controller.stop()
            rpc.assert_not_called()

    def test_matching_pid_and_directory_without_launch_token_is_not_owned(self):
        entry = {"pid": 123, "token": "a" * 32}
        command = f"{self.controller.binary} -datadir={self.controller.node(0)} -regtest"
        with patch.object(self.controller, "pid_command", return_value=command):
            self.assertFalse(self.controller.owned(0, entry))

    def test_complete_process_identity_is_owned(self):
        entry = {"pid": 123, "token": "a" * 32}
        command = (f"{self.controller.binary} -regtest -datadir={self.controller.node(0)} "
                   f"-uacomment=QLUFoundation-{entry['token']}")
        with patch.object(self.controller, "pid_command", return_value=command):
            self.assertTrue(self.controller.owned(0, entry))
        with patch.object(self.controller, "pid_command", return_value=command + "extra"):
            self.assertFalse(self.controller.owned(0, entry))

    def test_zombie_pid_is_treated_as_exited(self):
        result = subprocess.CompletedProcess([], 0, "Z [bitcoind] <defunct>\n", "")
        with patch.object(devnet.subprocess, "run", return_value=result):
            self.assertEqual(self.controller.pid_command(123), "")

    def test_wrong_chain_refused_before_stop(self):
        with patch.object(self.controller, "rpc", return_value={"chain": "main"}) as rpc:
            with self.assertRaisesRegex(devnet.DevnetError, "not regtest"):
                self.controller.verify_node(0)
            self.assertEqual(rpc.call_count, 1)

    def test_wrong_log_path_refused(self):
        with patch.object(self.controller, "rpc", side_effect=[{"chain": "regtest"}, {"logpath": "/tmp/unrelated/debug.log"}]):
            with self.assertRaisesRegex(devnet.DevnetError, "unexpected data directory"):
                self.controller.verify_node(0)

    def test_occupied_port_is_detected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            self.assertFalse(devnet.Devnet.port_free(listener.getsockname()[1]))

    def test_time_wait_does_not_look_like_an_active_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            listener.listen()
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                accepted, _ = listener.accept()
                accepted.shutdown(socket.SHUT_RDWR)
                accepted.close()
                self.assertEqual(client.recv(1), b"")
        self.assertTrue(devnet.Devnet.port_free(port))

    def test_launch_disables_settings_file_even_when_settings_exist(self):
        self.controller.setup()
        network_data = self.controller.node(0) / "regtest"
        network_data.mkdir()
        (network_data / "settings.json").write_text(json.dumps({"bind": "0.0.0.0", "connect": "203.0.113.1"}))
        process = MagicMock()
        process.pid = 12345
        process.poll.return_value = None
        with patch.object(self.controller, "require_binaries"), \
                patch.object(self.controller, "require_stopped"), \
                patch.object(self.controller, "verify_node"), \
                patch.object(self.controller, "wait_connected") as wait_connected, \
                patch.object(devnet.shutil, "disk_usage", return_value=MagicMock(free=2 * 1024 ** 3)), \
                patch.object(devnet.subprocess, "Popen", return_value=process) as popen:
            self.controller.start()
            self.assertEqual(popen.call_count, 4)
            for call in popen.call_args_list:
                self.assertIn("-nosettings", call.args[0])
            wait_connected.assert_called_once()

    def test_peer_mesh_wait_requires_every_distinct_peer_and_completed_handshake(self):
        state = {str(index): {"token": str(index) * 32} for index in range(4)}

        def peer(other, complete=True):
            return {"addr": f"127.0.0.1:{19440 + other}",
                    "subver": f"/Satoshi:31.1(QLUFoundation-{state[str(other)]['token']})/",
                    "bytesrecv_per_msg": {"pong": 29} if complete else {"version": 100}}

        # Having multiple connections to one peer must not count as a mesh,
        # and receiving VERSION alone must not count as a completed handshake.
        observed = {0: [peer(1), peer(1)], 1: [peer(0)], 2: [peer(3)], 3: [peer(2)]}

        def rpc(index, method):
            return observed[index] if method == "getpeerinfo" else None

        with patch.object(self.controller, "rpc", side_effect=rpc), \
                patch.object(devnet.time, "monotonic", side_effect=[0, 0, 2]), \
                patch.object(devnet.time, "sleep"):
            with self.assertRaisesRegex(devnet.DevnetError, "peer mesh was not ready"):
                self.controller.wait_connected(state, timeout=1)

        observed = {i: [peer(other, complete=False) for other in range(4) if other != i] for i in range(4)}
        with patch.object(self.controller, "rpc", side_effect=rpc), \
                patch.object(devnet.time, "monotonic", side_effect=[0, 0, 2]), \
                patch.object(devnet.time, "sleep"):
            with self.assertRaisesRegex(devnet.DevnetError, "peer mesh was not ready"):
                self.controller.wait_connected(state, timeout=1)

        observed = {i: [peer(other) for other in range(4) if other != i] for i in range(4)}
        with patch.object(self.controller, "rpc", side_effect=rpc):
            self.controller.wait_connected(state, timeout=1)

    def test_chain_sync_requires_expected_tip_on_every_node(self):
        with patch.object(self.controller, "rpc", side_effect=["new", "new", "old", "old"]), \
                patch.object(devnet.time, "monotonic", side_effect=[0, 0, 41]), \
                patch.object(devnet.time, "sleep"):
            with self.assertRaisesRegex(devnet.DevnetError, "observed"):
                self.controller.wait_synced("new")
        with patch.object(self.controller, "rpc", return_value="wrong-but-shared"), \
                patch.object(devnet.time, "monotonic", side_effect=[0, 0, 41]), \
                patch.object(devnet.time, "sleep"):
            with self.assertRaises(devnet.DevnetError):
                self.controller.wait_synced("expected")

    def test_failed_smoke_preserves_evidence_and_stops_owned_network(self):
        self.controller.record_smoke({"attempt_id": "previous-success", "passed": True})
        stopped = [{"node": i, "status": "stopped"} for i in range(4)]
        with patch.object(self.controller, "require_binaries"), \
                patch.object(self.controller, "require_stopped"), \
                patch.object(self.controller, "file_sha256", return_value="test-fingerprint"), \
                patch.object(self.controller, "start") as start, \
                patch.object(self.controller, "verify_node", side_effect=devnet.DevnetError("deliberate midrun failure")), \
                patch.object(self.controller, "stop") as stop, \
                patch.object(self.controller, "status", return_value=stopped):
            with self.assertRaisesRegex(devnet.DevnetError, "deliberate midrun failure"):
                self.controller.smoke()
            start.assert_called_once()
            stop.assert_called_once()
        evidence = self.controller.local / "evidence"
        latest = json.loads((evidence / "devnet-smoke.json").read_text())
        self.assertFalse(latest["passed"])
        self.assertEqual(latest["error"]["message"], "deliberate midrun failure")
        self.assertEqual(latest["cleanup"]["status"], "stopped")
        self.assertTrue(latest["cleanup"]["attempted"])
        self.assertEqual(latest["controller_sha256"], "test-fingerprint")
        self.assertIn("tracked_diff_sha256", latest)
        self.assertIn("finished_at", latest)
        self.assertEqual(len(list(evidence.glob("devnet-smoke-*.json"))), 2)
        self.assertTrue(json.loads((evidence / "devnet-smoke-previous-success.json").read_text())["passed"])

    def test_smoke_preflight_failure_is_recorded_without_touching_existing_network(self):
        with patch.object(self.controller, "require_binaries"), \
                patch.object(self.controller, "file_sha256", return_value="test-fingerprint"), \
                patch.object(self.controller, "require_stopped", side_effect=devnet.DevnetError("already running")), \
                patch.object(self.controller, "start") as start, \
                patch.object(self.controller, "stop") as stop:
            with self.assertRaisesRegex(devnet.DevnetError, "already running"):
                self.controller.smoke()
            start.assert_not_called()
            stop.assert_not_called()
        latest = json.loads((self.controller.local / "evidence/devnet-smoke.json").read_text())
        self.assertFalse(latest["passed"])
        self.assertEqual(latest["phase"], "preflight")
        self.assertEqual(latest["cleanup"]["status"], "not-needed-no-network-started")

    def test_evidence_redacts_cookie_credentials(self):
        summary = self.controller.error_summary(devnet.RpcError("bad __cookie__:secretvalue rpcpassword=anothersecret"))
        self.assertNotIn("secretvalue", summary["message"])
        self.assertNotIn("anothersecret", summary["message"])

    def test_provenance_timeout_records_failure_without_starting_nodes(self):
        with patch.object(devnet.subprocess, "run", side_effect=subprocess.TimeoutExpired(["git", "diff"], 30)) as run, \
                patch.object(self.controller, "start") as start, \
                patch.object(self.controller, "stop") as stop:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.controller.smoke()
            self.assertEqual(run.call_args.kwargs["timeout"], 30)
            start.assert_not_called()
            stop.assert_not_called()
        latest = json.loads((self.controller.local / "evidence/devnet-smoke.json").read_text())
        self.assertFalse(latest["passed"])
        self.assertEqual(latest["error"]["type"], "TimeoutExpired")
        self.assertEqual(latest["cleanup"]["status"], "not-needed-no-network-started")

    def test_invalid_ownership_state_rejected(self):
        self.controller.setup()
        self.controller.state_file.write_text(json.dumps({"0": {"pid": 1, "token": "a" * 32}}))
        with self.assertRaisesRegex(devnet.DevnetError, "ownership state"):
            self.controller.read_state()

    def test_rpc_newline_arguments_refused(self):
        with self.assertRaisesRegex(devnet.DevnetError, "newlines"):
            self.controller.rpc(0, "createwallet", "safe\ninjected")


if __name__ == "__main__":
    unittest.main()
