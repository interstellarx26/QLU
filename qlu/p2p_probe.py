"""Bounded V1 wire probes for an already owned localhost QLU laboratory.

Socket operations share a ten-second handshake/case deadline. Controller RPCs
retain Devnet's existing bounded subprocess timeout; the overall work deadline
is checked before and after each RPC (one call may finish after that deadline).
This module cannot select a hostname, public network, or arbitrary TCP port.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import socket
import struct
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from private_net import QLUPrivateNet
from protocol import GENESIS, NETWORK, ROOT

MAGIC = bytes.fromhex("f1dcd324")
MAX_PAYLOAD = 8192
MAX_RECEIVE_FRAME = 65536
MAX_MESSAGES = 256
MAX_SENT_PER_NODE = 1024 * 1024
MAX_RECEIVED_PER_NODE = 2 * 1024 * 1024
SOCKET_SECONDS = 10
MAX_WORK_SECONDS = 600
MALFORMED_NONCE = 0x514C550000000001


class ProbeError(RuntimeError):
    """Fixed diagnostic labels only; never include peer-provided bytes."""


class PeerClosed(ProbeError):
    """The still-open client observed EOF or a connection reset."""


def require(condition, message):
    if not condition:
        raise ProbeError(message)


def checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def command_valid(command):
    return (type(command) is bytes and 0 < len(command) <= 12
            and all(32 <= byte <= 126 for byte in command))


def frame(command, payload=b""):
    require(command_valid(command), "Invalid outgoing wire command")
    require(type(payload) is bytes and len(payload) <= MAX_PAYLOAD, "Outgoing wire payload limit")
    return MAGIC + command.ljust(12, b"\0") + struct.pack("<I", len(payload)) + checksum(payload) + payload


@dataclass(frozen=True)
class WireCase:
    name: str
    raw: bytes
    expected: str
    log_token: str
    forbidden_pongs: tuple[int, ...] = ()


def wire_cases():
    """Fixed, small malformed frames; oversize cases contain only a header."""
    ping = frame(b"ping", struct.pack("<Q", MALFORMED_NONCE))
    header = frame(b"ping")
    cases = [WireCase("wrong-magic", b"\xfa" + ping[1:], "disconnect", "Wrong MessageStart"),
             WireCase("length-4000001", header[:16] + struct.pack("<I", 4000001) + header[20:], "disconnect", "Size too large"),
             WireCase("length-ffffffff", header[:16] + b"\xff" * 4 + header[20:], "disconnect", "Size too large"),
             WireCase("wrong-checksum-ping", ping[:20] + bytes([ping[20] ^ 1]) + ping[21:], "ignore", "Wrong checksum", (MALFORMED_NONCE,)),
             WireCase("command-nonprintable", ping[:4] + b"pi\x01g" + ping[8:], "ignore", "Invalid message type", (MALFORMED_NONCE,)),
             WireCase("command-nul-trailing", ping[:4] + b"ping\0x" + bytes(6) + ping[16:], "ignore", "Invalid message type", (MALFORMED_NONCE,))]
    for size in (0, 7):
        cases.append(WireCase(f"short-ping-{size}", frame(b"ping", struct.pack("<Q", MALFORMED_NONCE)[:size]),
                              "ignore", f"ProcessMessages(ping, {size} bytes): Exception", (MALFORMED_NONCE, 0)))
    for name, payload in (("empty", b""), ("truncated-version", b"\x02\0\0"),
                          ("noncanonical-compactsize", b"\x02\0\0\0\xfd\x01\0"),
                          ("oversized-compactsize", b"\x02\0\0\0\xfe\xff\xff\xff\xff")):
        cases.append(WireCase("tx-" + name, frame(b"tx", payload), "ignore",
                              f"ProcessMessages(tx, {len(payload)} bytes): Exception"))
    return tuple(cases)


@dataclass
class WireBudget:
    sent: list[int] = field(default_factory=lambda: [0] * 4)
    received: list[int] = field(default_factory=lambda: [0] * 4)

    def remaining(self, index, direction):
        require(type(index) is int and 0 <= index < 4, "Invalid wire budget node")
        require(direction in ("sent", "received"), "Invalid wire budget direction")
        limit = MAX_SENT_PER_NODE if direction == "sent" else MAX_RECEIVED_PER_NODE
        return limit - getattr(self, direction)[index]

    def charge(self, index, direction, amount):
        require(type(amount) is int and 0 <= amount <= self.remaining(index, direction), "Per-node wire byte budget exceeded")
        getattr(self, direction)[index] += amount

    def stats(self):
        return [{"node": index, "sent_bytes": self.sent[index], "received_bytes": self.received[index]}
                for index in range(4)]


class WirePeer:
    def __init__(self, net, index, global_deadline, *, budget, wtxid_relay=True):
        require(isinstance(net, QLUPrivateNet), "Wire probes require a QLU private controller")
        require(type(index) is int and 0 <= index < 4, "Invalid wire target node")
        require(net.chain == NETWORK == "qludev" and net.p2p_base == 28440 and net.rpc_base == 28540,
                "Wire controller network or ports differ")
        require(net.root == ROOT.resolve() and net.local == net.root / ".local"
                and re.fullmatch(r"p2p-resilience-[0-9a-f]{32}", net.data_name) is not None
                and net.data == net.local / net.data_name
                and net.data.resolve().parent == net.local.resolve(),
                "Wire controller data escapes the private project")
        now = time.monotonic()
        require(type(global_deadline) in (int, float) and now < global_deadline <= now + MAX_WORK_SECONDS,
                "Invalid wire work deadline")
        require(isinstance(budget, WireBudget) and type(wtxid_relay) is bool, "Invalid wire probe options")
        self.net, self.index, self.global_deadline, self.budget = net, index, global_deadline, budget
        self.wtxid_relay = wtxid_relay
        self.socket = None
        self.case_deadline = min(global_deadline, now + SOCKET_SECONDS)
        self.peer_id = None
        self.endpoint = None
        self.subversion = "/QLUWireProbe:" + uuid.uuid4().hex + "/"
        self.message_count = 0
        self.sent_bytes = 0
        self.used_nonces = set()
        self.ownership = None

    def _global_remaining(self):
        remaining = self.global_deadline - time.monotonic()
        require(remaining > 0, "Wire work deadline exceeded")
        return remaining

    def _remaining(self):
        self._global_remaining()
        remaining = self.case_deadline - time.monotonic()
        require(remaining > 0, "Wire socket deadline exceeded")
        return remaining

    def _rpc(self, method, *params):
        self._global_remaining()
        result = self.net.rpc(self.index, method, *params)
        self._global_remaining()
        return result

    def _check_ownership(self):
        self._global_remaining()
        state = self.net.read_state()
        entry = state.get(str(self.index))
        require(isinstance(entry, dict) and self.net.owned(self.index, entry), "Wire target process is not owned")
        if self.ownership is not None:
            require(entry == self.ownership, "Wire target ownership changed")
        self.ownership = dict(entry)
        self._global_remaining()

    def _verify_controller(self):
        self._check_ownership()
        require(self._rpc("getblockchaininfo").get("chain") == "qludev", "Wire target has wrong chain")
        expected = self.net.node(self.index) / "qludev" / "debug.log"
        require(Path(self._rpc("getrpcinfo").get("logpath", "")).resolve() == expected.resolve(),
                "Wire target has wrong data directory")
        require(self._rpc("getblockhash", 0) == GENESIS, "Wire target has wrong genesis")

    def __enter__(self):
        try:
            self._verify_controller()
            self.case_deadline = min(self.global_deadline, time.monotonic() + SOCKET_SECONDS)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self._remaining())
            self.socket.connect(("127.0.0.1", 28440 + self.index))
            require(self.socket.getpeername() == ("127.0.0.1", 28440 + self.index), "Unexpected wire socket target")
            local = self.socket.getsockname()
            require(local[0] == "127.0.0.1" and type(local[1]) is int and 0 < local[1] <= 65535,
                    "Unexpected wire socket origin")
            self.endpoint = f"127.0.0.1:{local[1]}"
            self._handshake()
            self._verify_peer()
            self.case_deadline = min(self.global_deadline, time.monotonic() + SOCKET_SECONDS)
            return self
        except BaseException:
            self.close()
            if self.endpoint is not None:
                self.wait_peer_removed()
            raise

    def __exit__(self, *_):
        self.close()
        self.wait_peer_removed()

    def close(self):
        if self.socket is not None:
            owned, self.socket = self.socket, None
            owned.close()

    def begin_case(self):
        """Start one explicit new test case; never called by read/write loops."""
        require(self.socket is not None and self.peer_id is not None, "New wire case needs an identified open peer")
        self._global_remaining()
        self.case_deadline = min(self.global_deadline, time.monotonic() + SOCKET_SECONDS)

    def send_raw(self, raw):
        require(self.socket is not None, "Wire peer is closed")
        require(type(raw) is bytes and len(raw) <= MAX_PAYLOAD + 24, "Raw wire input limit")
        require(len(raw) <= self.budget.remaining(self.index, "sent"), "Per-node wire byte budget exceeded")
        offset = 0
        while offset < len(raw):
            self.socket.settimeout(self._remaining())
            try:
                written = self.socket.send(raw[offset:])
            except (BrokenPipeError, ConnectionResetError) as error:
                raise PeerClosed("Wire peer closed while writing") from error
            except socket.timeout as error:
                raise ProbeError("Wire socket deadline exceeded") from error
            require(written > 0, "Wire socket made no write progress")
            self.budget.charge(self.index, "sent", written)
            self.sent_bytes += written
            offset += written

    def send_message(self, command, payload=b""):
        self.send_raw(frame(command, payload))

    def _read_exact(self, length):
        require(self.socket is not None, "Wire peer is closed")
        require(type(length) is int and 0 <= length <= MAX_RECEIVE_FRAME, "Wire read size limit")
        require(length <= self.budget.remaining(self.index, "received"), "Per-node wire byte budget exceeded")
        result = bytearray()
        while len(result) < length:
            self.socket.settimeout(self._remaining())
            try:
                chunk = self.socket.recv(min(length - len(result), 4096))
            except ConnectionResetError as error:
                raise PeerClosed("Wire peer reset the connection") from error
            except socket.timeout as error:
                raise ProbeError("Wire socket deadline exceeded") from error
            if not chunk:
                raise PeerClosed("Wire peer sent EOF")
            self.budget.charge(self.index, "received", len(chunk))
            result.extend(chunk)
        return bytes(result)

    def receive_message(self):
        require(self.message_count < MAX_MESSAGES, "Wire message count limit")
        header = self._read_exact(24)
        require(header[:4] == MAGIC, "Unexpected received wire magic")
        padded = header[4:16]
        command = padded.split(b"\0", 1)[0]
        require(command_valid(command) and padded == command.ljust(12, b"\0"), "Invalid received wire command")
        length = struct.unpack("<I", header[16:20])[0]
        require(length <= MAX_RECEIVE_FRAME, "Received wire frame exceeds limit")
        payload = self._read_exact(length)
        require(checksum(payload) == header[20:24], "Invalid received wire checksum")
        self.message_count += 1
        if command == b"ping":
            require(len(payload) == 8, "Invalid received ping length")
            self.send_message(b"pong", payload)
        return command, payload

    def _handshake(self):
        address = struct.pack("<Q", 0) + bytes(10) + b"\xff\xff\x7f\0\0\x01" + struct.pack(">H", 28440 + self.index)
        subversion = self.subversion.encode("ascii")
        nonce = int.from_bytes(uuid.uuid4().bytes[:8], "little") or 1
        version = (struct.pack("<iQq", 70016, 0, int(time.time())) + address + address
                   + struct.pack("<Q", nonce) + bytes([len(subversion)]) + subversion + struct.pack("<i?", 0, True))
        self.send_message(b"version", version)
        version_seen = False
        while True:
            command, payload = self.receive_message()
            if command == b"version":
                require(not version_seen and len(payload) >= 80 and struct.unpack("<i", payload[:4])[0] >= 70016,
                        "Invalid peer protocol version")
                version_seen = True
                if self.wtxid_relay:
                    self.send_message(b"wtxidrelay")
                self.send_message(b"verack")
            elif command == b"verack":
                require(version_seen and payload == b"", "Invalid peer handshake ordering")
                return

    def _verify_peer(self):
        while True:
            self._remaining()
            matches = [row for row in self._rpc("getpeerinfo") if row.get("addr") == self.endpoint]
            require(len(matches) <= 1, "Ambiguous wire peer endpoint")
            if matches:
                peer = matches[0]
                require(peer.get("subver") == self.subversion and peer.get("transport_protocol_type") == "v1"
                        and peer.get("inbound") is True and type(peer.get("id")) is int and peer["id"] >= 0,
                        "Wire RPC peer identity or transport mismatch")
                self.peer_id = peer["id"]
                return
            time.sleep(min(.02, self._remaining()))

    def wait_peer_removed(self):
        if self.endpoint is None:
            return
        deadline = min(self.global_deadline, time.monotonic() + SOCKET_SECONDS)
        self._check_ownership()
        while True:
            require(time.monotonic() < deadline, "Wire peer cleanup deadline exceeded")
            peers = self._rpc("getpeerinfo")
            matches = [row for row in peers if row.get("addr") == self.endpoint
                       or (self.peer_id is not None and row.get("id") == self.peer_id)
                       or row.get("subver") == self.subversion]
            if not matches:
                return
            time.sleep(min(.02, max(0, deadline - time.monotonic())))

    def wait_received(self):
        """Prove this exact peer received all bytes written so far, even a prefix.

        Per-peer raw bytesrecv advances at socket reception, independently of
        message completion. Waiting before the next write prevents TCP from
        coalescing a deliberately incomplete prefix with its later remainder.
        """
        require(self.socket is not None and self.peer_id is not None, "Receive progress needs an identified open peer")
        while True:
            self._remaining()
            matches = [row for row in self._rpc("getpeerinfo") if row.get("id") == self.peer_id]
            require(len(matches) == 1, "Wire peer missing during receive progress check")
            peer = matches[0]
            require(peer.get("addr") == self.endpoint and peer.get("subver") == self.subversion
                    and peer.get("transport_protocol_type") == "v1" and peer.get("inbound") is True,
                    "Wire peer changed during receive progress check")
            received = peer.get("bytesrecv")
            require(type(received) is int and 0 <= received <= self.sent_bytes, "Unexpected wire peer receive counter")
            if received == self.sent_bytes:
                return received
            time.sleep(min(.02, self._remaining()))

    @staticmethod
    def _nonce(nonce):
        require(type(nonce) is int and 0 < nonce < 2 ** 64, "Invalid probe ping nonce")

    def _await_pongs(self, nonces, forbidden_pongs):
        remaining = set(nonces)
        forbidden = set(forbidden_pongs)
        require(not remaining & forbidden, "Expected ping is also forbidden")
        while remaining:
            command, payload = self.receive_message()
            if command != b"pong":
                continue
            require(len(payload) == 8, "Invalid received pong length")
            nonce = struct.unpack("<Q", payload)[0]
            require(nonce not in forbidden, "Malformed ping was incorrectly answered")
            require(nonce in remaining, "Unexpected or repeated pong nonce")
            remaining.remove(nonce)

    def ping(self, nonce, *, forbidden_pongs=(), fragmented=False):
        self._nonce(nonce)
        require(type(fragmented) is bool, "Invalid fragmentation option")
        require(nonce not in self.used_nonces, "Probe ping nonce was reused")
        self.used_nonces.add(nonce)
        raw = frame(b"ping", struct.pack("<Q", nonce))
        receipts = []
        if fragmented:
            self.send_raw(raw[:7])
            received = self.wait_received()  # Only a partial message header.
            receipts.append({"peer_id": self.peer_id, "sent_bytes": self.sent_bytes, "peer_bytes_received": received})
            self.send_raw(raw[7:27])
            received = self.wait_received()  # Header, only three payload bytes.
            receipts.append({"peer_id": self.peer_id, "sent_bytes": self.sent_bytes, "peer_bytes_received": received})
            self.send_raw(raw[27:])
        else:
            self.send_raw(raw)
        self._await_pongs((nonce,), forbidden_pongs)
        return receipts

    def ping_pair(self, first, second):
        self._nonce(first); self._nonce(second)
        require(first != second and not self.used_nonces & {first, second}, "Probe ping nonce was reused")
        self.used_nonces.update((first, second))
        self.send_raw(frame(b"ping", struct.pack("<Q", first)) + frame(b"ping", struct.pack("<Q", second)))
        self._await_pongs((first, second), ())

    def wait_disconnect(self):
        require(self.socket is not None, "Cannot attribute a client-closed connection to server rejection")
        while True:
            try:
                self.receive_message()
            except PeerClosed:
                return
