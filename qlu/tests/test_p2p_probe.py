"""Local socket pairs and deterministic fakes exercise the probe's boundaries."""
import socket
import struct
import time
import unittest
from unittest.mock import Mock, patch

from qlu import p2p_probe as wire


class MemorySocket:
    def __init__(self, incoming=b"", *, chunk=65536, tick=None):
        self.incoming = bytearray(incoming)
        self.written = bytearray()
        self.chunk = chunk
        self.tick = tick
        self.read_requests = []
        self.closed = False
        self.connected = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def recv(self, size):
        self.read_requests.append(size)
        if self.tick:
            self.tick()
        result = bytes(self.incoming[:min(size, self.chunk)])
        del self.incoming[:len(result)]
        return result

    def send(self, payload):
        if self.tick:
            self.tick()
        size = min(len(payload), self.chunk)
        self.written.extend(payload[:size])
        return size

    def connect(self, endpoint):
        self.connected = endpoint

    def getpeername(self):
        return self.connected

    def getsockname(self):
        return ("127.0.0.1", 42001)

    def close(self):
        self.closed = True


def private_controller():
    net = object.__new__(wire.QLUPrivateNet)
    net.root = wire.ROOT.resolve()
    net.local = net.root / ".local"
    net.data_name = "p2p-resilience-" + "f" * 32
    net.data = net.local / net.data_name
    net.read_state = Mock(return_value={"0": {"pid": 123, "token": "a" * 32}})
    net.owned = Mock(return_value=True)
    net.rpc = Mock()
    return net


def peer_with_socket(sock, *, budget=None):
    peer = wire.WirePeer(private_controller(), 0, time.monotonic() + 60,
                         budget=budget or wire.WireBudget())
    peer.socket = sock
    return peer


def pong(nonce):
    return wire.frame(b"pong", struct.pack("<Q", nonce))


class FramingTests(unittest.TestCase):
    def test_fixed_corpus_is_small_exact_and_overlength_headers_have_no_body(self):
        cases = wire.wire_cases()
        self.assertEqual(len(cases), 12)
        self.assertEqual(len({case.name for case in cases}), 12)
        self.assertEqual(sum(case.expected == "disconnect" for case in cases), 3)
        self.assertTrue(all(len(case.raw) <= wire.MAX_PAYLOAD + 24 for case in cases))
        lengths = {case.name: struct.unpack("<I", case.raw[16:20])[0] for case in cases}
        for case in cases:
            if case.name.startswith("length-"):
                self.assertEqual(len(case.raw), 24)
            else:
                self.assertEqual(lengths[case.name], len(case.raw) - 24)
        self.assertEqual(lengths["length-4000001"], 4000001)
        self.assertEqual(lengths["length-ffffffff"], 0xffffffff)
        self.assertEqual(len(wire.frame(b"tx", bytes(8192))), 8216)
        for command, payload in ((b"", b""), (b"x" * 13, b""), (b"pi\0ng", b""),
                                 (b"ping\x01", b""), ("ping", b""), (b"tx", bytes(8193))):
            with self.assertRaises(wire.ProbeError):
                wire.frame(command, payload)

    def test_partial_reads_preserve_framing_and_exact_checksum(self):
        sock = MemorySocket(wire.frame(b"tx", b"sample") + pong(17), chunk=1)
        peer = peer_with_socket(sock)
        self.assertEqual(peer.receive_message(), (b"tx", b"sample"))
        self.assertEqual(peer.receive_message(), (b"pong", struct.pack("<Q", 17)))
        self.assertEqual(peer.budget.received[0], 62)
        self.assertEqual(peer.message_count, 2)

    def test_socket_pair_handles_coalesced_messages_and_answers_server_ping(self):
        local, remote = socket.socketpair()
        remote.settimeout(1)
        try:
            peer = peer_with_socket(local)
            remote.sendall(wire.frame(b"ping", struct.pack("<Q", 99)) + pong(13))
            self.assertEqual(peer.receive_message()[0], b"ping")
            self.assertEqual(remote.recv(128), pong(99))
            self.assertEqual(peer.receive_message()[1], struct.pack("<Q", 13))
        finally:
            local.close(); remote.close()

    def test_bad_header_is_rejected_before_any_payload_read(self):
        valid = wire.frame(b"tx", b"body")
        changes = [b"xxxx" + valid[4:], valid[:4] + b"tx\0bad" + bytes(6) + valid[16:],
                   valid[:16] + struct.pack("<I", 65537) + valid[20:],
                   valid[:16] + b"\xff" * 4 + valid[20:]]
        for raw in changes:
            sock = MemorySocket(raw)
            with self.subTest(raw=raw[:24]), self.assertRaises(wire.ProbeError):
                peer_with_socket(sock).receive_message()
            self.assertEqual(sock.read_requests, [24])

    def test_bad_checksum_and_malformed_server_ping_are_errors(self):
        valid = wire.frame(b"tx", b"body")
        for raw in (valid[:-1] + b"x", wire.frame(b"ping", b"short")):
            with self.assertRaises(wire.ProbeError):
                peer_with_socket(MemorySocket(raw)).receive_message()

    def test_receive_frame_boundary_is_exact_and_eof_is_not_success(self):
        payload = bytes(65536)
        header = wire.MAGIC + b"tx".ljust(12, b"\0") + struct.pack("<I", len(payload)) + wire.checksum(payload)
        peer = peer_with_socket(MemorySocket(header + payload))
        self.assertEqual(peer.receive_message(), (b"tx", payload))
        for raw in (b"", header[:7], header + payload[:20]):
            with self.assertRaises(wire.PeerClosed):
                peer_with_socket(MemorySocket(raw)).receive_message()


class BudgetAndDeadlineTests(unittest.TestCase):
    def test_per_node_budget_is_shared_across_connections_and_nodes_are_separate(self):
        budget = wire.WireBudget()
        budget.charge(0, "sent", wire.MAX_SENT_PER_NODE - 2)
        first = peer_with_socket(MemorySocket(), budget=budget)
        first.send_raw(b"ab")
        second = peer_with_socket(MemorySocket(), budget=budget)
        with self.assertRaises(wire.ProbeError):
            second.send_raw(b"c")
        self.assertEqual(second.socket.written, b"")
        budget.charge(1, "sent", 1)
        self.assertEqual(budget.stats()[1], {"node": 1, "sent_bytes": 1, "received_bytes": 0})
        budget.charge(0, "received", wire.MAX_RECEIVED_PER_NODE - 23)
        with self.assertRaises(wire.ProbeError):
            second.receive_message()
        self.assertEqual(second.socket.read_requests, [])

    def test_message_count_rejects_before_reading_next_header(self):
        peer = peer_with_socket(MemorySocket(wire.frame(b"sendheaders")))
        peer.message_count = wire.MAX_MESSAGES
        with self.assertRaises(wire.ProbeError):
            peer.receive_message()
        self.assertEqual(peer.socket.read_requests, [])

    def test_partial_write_is_complete_and_counted(self):
        sock = MemorySocket(chunk=2)
        peer = peer_with_socket(sock)
        raw = wire.frame(b"ping", b"12345678")
        peer.send_raw(raw)
        self.assertEqual(sock.written, raw)
        self.assertEqual(peer.budget.sent[0], len(raw))
        for raw in (bytes(8217), "not bytes"):
            with self.assertRaises(wire.ProbeError):
                peer.send_raw(raw)

    def test_slow_drip_read_and_write_do_not_extend_original_deadline(self):
        for operation in ("read", "write"):
            clock = [100.0]
            def tick(): clock[0] += 1
            with patch.object(wire.time, "monotonic", side_effect=lambda: clock[0]):
                sock = MemorySocket(bytes(20), chunk=1, tick=tick)
                peer = peer_with_socket(sock)
                peer.case_deadline = 103
                with self.assertRaisesRegex(wire.ProbeError, "deadline"):
                    peer._read_exact(20) if operation == "read" else peer.send_raw(bytes(20))
                self.assertEqual(clock[0], 103)
                self.assertEqual(peer.budget.received[0] if operation == "read" else peer.budget.sent[0], 3)

    def test_actual_socket_timeout_and_reset_are_distinct(self):
        local, remote = socket.socketpair()
        try:
            peer = peer_with_socket(local)
            peer.case_deadline = time.monotonic() + .02
            with self.assertRaisesRegex(wire.ProbeError, "deadline"):
                peer.receive_message()
            peer.case_deadline = time.monotonic() + 1
            remote.close()
            with self.assertRaises(wire.PeerClosed):
                peer.receive_message()
        finally:
            local.close(); remote.close()

    def test_explicit_new_case_resets_only_case_deadline_and_keeps_global_budget(self):
        clock = [100.0]
        with patch.object(wire.time, "monotonic", side_effect=lambda: clock[0]):
            peer = peer_with_socket(MemorySocket())
            peer.peer_id = 4
            peer.used_nonces.add(15)
            peer.budget.charge(0, "sent", 100)
            peer.global_deadline = 125
            clock[0] = 119
            peer.begin_case()
            self.assertEqual(peer.case_deadline, 125)
            self.assertEqual(peer.used_nonces, {15})
            self.assertEqual(peer.budget.sent[0], 100)
            clock[0] = 125
            with self.assertRaises(wire.ProbeError):
                peer.begin_case()
        peer.close()
        with self.assertRaises(wire.ProbeError):
            peer.begin_case()


class PingTests(unittest.TestCase):
    def test_exact_nonce_and_fragmented_header_payload_control(self):
        sock = MemorySocket(pong(42), chunk=2)
        peer = peer_with_socket(sock)
        progress = []
        peer.peer_id, peer.endpoint = 9, "127.0.0.1:42001"
        def received(index, method):
            progress.append(bytes(sock.written))
            return [{"id": 9, "addr": peer.endpoint, "subver": peer.subversion,
                     "transport_protocol_type": "v1", "inbound": True, "bytesrecv": len(sock.written)}]
        peer.net.rpc.side_effect = received
        receipts = peer.ping(42, fragmented=True)
        self.assertEqual(sock.written, wire.frame(b"ping", struct.pack("<Q", 42)))
        self.assertEqual([len(prefix) for prefix in progress], [7, 27])
        self.assertEqual(receipts, [{"peer_id": 9, "sent_bytes": size, "peer_bytes_received": size} for size in (7, 27)])
        with self.assertRaises(wire.ProbeError):
            peer.ping(42)

    def test_coalesced_pair_accepts_each_exact_nonce_once(self):
        sock = MemorySocket(pong(12) + pong(11))
        peer_with_socket(sock).ping_pair(11, 12)
        self.assertEqual(sock.written, wire.frame(b"ping", struct.pack("<Q", 11))
                         + wire.frame(b"ping", struct.pack("<Q", 12)))
        for raw in (pong(11) + pong(11), pong(17), wire.frame(b"pong", b"")):
            with self.assertRaises(wire.ProbeError):
                peer_with_socket(MemorySocket(raw)).ping_pair(11, 12)

    def test_forbidden_pong_cannot_be_hidden_by_later_valid_response(self):
        for nonce in (wire.MALFORMED_NONCE, 0):
            peer = peer_with_socket(MemorySocket(pong(nonce) + pong(123)))
            with self.assertRaisesRegex(wire.ProbeError, "incorrectly answered"):
                peer.ping(123, forbidden_pongs=(wire.MALFORMED_NONCE, 0))
        for nonce in (0, -1, 2 ** 64, True, "1"):
            with self.assertRaises(wire.ProbeError):
                peer_with_socket(MemorySocket()).ping(nonce)

    def test_server_disconnect_needs_client_socket_open(self):
        peer = peer_with_socket(MemorySocket())
        peer.wait_disconnect()
        peer.close()
        with self.assertRaisesRegex(wire.ProbeError, "client-closed"):
            peer.wait_disconnect()


class ControllerAndCleanupTests(unittest.TestCase):
    def test_arbitrary_controller_network_ports_and_paths_refused(self):
        for field, value in (("chain", "main"), ("p2p_base", 8333), ("rpc_base", 8332),
                             ("root", wire.ROOT.parent), ("data", wire.ROOT / "user-data")):
            net = private_controller()
            setattr(net, field, value)
            with self.subTest(field=field), self.assertRaises(wire.ProbeError):
                wire.WirePeer(net, 0, time.monotonic() + 60, budget=wire.WireBudget())
        with self.assertRaises(wire.ProbeError):
            wire.WirePeer(object(), 0, time.monotonic() + 60, budget=wire.WireBudget())
        for index in (-1, 4, True, "0"):
            with self.assertRaises(wire.ProbeError):
                wire.WirePeer(private_controller(), index, time.monotonic() + 60, budget=wire.WireBudget())
        for deadline in (0, float("inf"), float("nan"), time.monotonic() + 601):
            with self.assertRaises(wire.ProbeError):
                wire.WirePeer(private_controller(), 0, deadline, budget=wire.WireBudget())

    def test_normal_wallet_network_and_other_fixtures_are_refused(self):
        for name in ("qlu-private-v1", "devnet", "payment-workload-" + "f" * 32,
                     "p2p-resilience-" + "F" * 32, "p2p-resilience-short", "p2p-resilience-" + "f" * 33):
            net = private_controller()
            net.data_name, net.data = name, net.local / name
            with self.subTest(name=name), self.assertRaises(wire.ProbeError):
                wire.WirePeer(net, 0, time.monotonic() + 60, budget=wire.WireBudget())

    def test_receive_progress_requires_exact_peer_and_valid_byte_counter(self):
        peer = peer_with_socket(MemorySocket())
        peer.peer_id, peer.endpoint = 9, "127.0.0.1:42001"
        peer.send_raw(b"partial")
        good = {"id": 9, "addr": peer.endpoint, "subver": peer.subversion,
                "transport_protocol_type": "v1", "inbound": True, "bytesrecv": 7}
        peer.net.rpc.side_effect = [[{**good, "bytesrecv": 3}], [good]]
        self.assertEqual(peer.wait_received(), 7)
        for changes in ({"addr": "127.0.0.1:42002"}, {"id": 10}, {"subver": "/other/"},
                        {"bytesrecv": 8}, {"bytesrecv": -1}, {"bytesrecv": True},
                        {"transport_protocol_type": "v2"}):
            peer.net.rpc.side_effect = None
            peer.net.rpc.return_value = [{**good, **changes}]
            with self.subTest(changes=changes), self.assertRaises(wire.ProbeError):
                peer.wait_received()

    def test_ownership_wrong_chain_genesis_or_datadir_stops_before_connect(self):
        for fault in ("ownership", "chain", "genesis", "datadir"):
            net = private_controller()
            net.owned.return_value = fault != "ownership"
            answers = {"getblockchaininfo": {"chain": "main" if fault == "chain" else "qludev"},
                       "getblockhash": "wrong" if fault == "genesis" else wire.GENESIS,
                       "getrpcinfo": {"logpath": str(wire.ROOT / "wrong" if fault == "datadir"
                                                     else net.node(0) / "qludev/debug.log")}}
            net.rpc.side_effect = lambda index, method, *params: answers[method]
            peer = wire.WirePeer(net, 0, time.monotonic() + 60, budget=wire.WireBudget())
            with patch.object(wire.socket, "socket") as create:
                with self.subTest(fault=fault), self.assertRaises(wire.ProbeError):
                    peer.__enter__()
                create.assert_not_called()

    def test_complete_handshake_v1_marker_and_context_cleanup(self):
        for relay in (True, False):
            net = private_controller()
            incoming = wire.frame(b"version", struct.pack("<i", 70016) + bytes(76)) + wire.frame(b"verack")
            sock = MemorySocket(incoming, chunk=3)
            peer = wire.WirePeer(net, 0, time.monotonic() + 60, budget=wire.WireBudget(), wtxid_relay=relay)
            def rpc(index, method, *params):
                if method == "getblockchaininfo": return {"chain": "qludev"}
                if method == "getblockhash": return wire.GENESIS
                if method == "getrpcinfo": return {"logpath": str(net.node(0) / "qludev/debug.log")}
                if method == "getpeerinfo":
                    return [] if sock.closed else [{"addr": peer.endpoint, "subver": peer.subversion,
                                                    "id": 31, "inbound": True, "transport_protocol_type": "v1"}]
                raise AssertionError(method)
            net.rpc.side_effect = rpc
            with patch.object(wire.socket, "socket", return_value=sock) as create:
                with peer as entered:
                    self.assertIs(entered, peer)
                    self.assertEqual(peer.peer_id, 31)
                    self.assertEqual(peer.endpoint, "127.0.0.1:42001")
                    self.assertEqual(sock.connected, ("127.0.0.1", 28440))
                create.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            self.assertTrue(sock.closed)
            self.assertIsNone(peer.socket)
            self.assertEqual(wire.frame(b"wtxidrelay") in sock.written, relay)
            self.assertTrue(sock.written.endswith(wire.frame(b"verack")))

    def test_peer_marker_transport_and_endpoint_must_all_match(self):
        for change in ({"subver": "/foreign/"}, {"transport_protocol_type": "v2"},
                       {"inbound": False}, {"id": True}):
            peer = peer_with_socket(MemorySocket())
            peer.endpoint = "127.0.0.1:42001"
            row = {"addr": peer.endpoint, "subver": peer.subversion, "transport_protocol_type": "v1", "inbound": True, "id": 7}
            peer.net.rpc.return_value = [{**row, **change}]
            with self.subTest(change=change), self.assertRaises(wire.ProbeError):
                peer._verify_peer()

    def test_handshake_ordering_and_protocol_fail_closed(self):
        for raw in (wire.frame(b"verack"), wire.frame(b"version", b"short"),
                    wire.frame(b"version", struct.pack("<i", 70015) + bytes(76))):
            with self.assertRaises(wire.ProbeError):
                peer_with_socket(MemorySocket(raw))._handshake()

    def test_context_failure_still_closes_socket_and_checks_peer_removal(self):
        sock = MemorySocket()
        peer = peer_with_socket(sock)
        peer.endpoint = "127.0.0.1:42001"
        peer._check_ownership = Mock()
        peer.net.rpc.return_value = []
        peer.__exit__(RuntimeError, RuntimeError("test failure"), None)
        self.assertTrue(sock.closed)
        peer.net.rpc.assert_called_once_with(0, "getpeerinfo")

    def test_cleanup_never_accepts_replaced_owned_process(self):
        peer = peer_with_socket(MemorySocket())
        peer._check_ownership()
        peer.endpoint = "127.0.0.1:42001"
        peer.close()
        peer.net.read_state.return_value["0"]["token"] = "b" * 32
        with self.assertRaisesRegex(wire.ProbeError, "ownership changed"):
            peer.wait_peer_removed()
        peer.net.rpc.assert_not_called()

    def test_rpc_work_deadline_checked_before_and_after_existing_controller_call(self):
        clock = [100.0]
        with patch.object(wire.time, "monotonic", side_effect=lambda: clock[0]):
            peer = peer_with_socket(MemorySocket())
            peer.global_deadline = 101
            def finish_late(*args): clock[0] = 102; return []
            peer.net.rpc.side_effect = finish_late
            with self.assertRaisesRegex(wire.ProbeError, "work deadline"):
                peer._rpc("getpeerinfo")
            with self.assertRaises(wire.ProbeError):
                peer._rpc("getpeerinfo")
            self.assertEqual(peer.net.rpc.call_count, 1)


if __name__ == "__main__":
    unittest.main()
