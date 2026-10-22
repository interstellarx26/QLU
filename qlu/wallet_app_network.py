"""Local QLU wallet-app network adapter; valueless private laboratory coins only.

The fixed 0.001 QLU fee and automatic block generation are test conveniences,
not public fee estimation or mining policy. This adapter never changes consensus,
imports keys into a node, or connects to public peers. Faucet keys exist only in
this process and are discarded on stop; the chain itself is never reset.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path
import re
import json
import threading
import time
from typing import Callable

from devnet import NODE_COUNT, RpcError
from lab import private_port_lock
from private_net import QLUPrivateNet
import protocol
import recovery
from payment_conflicts import validate_transaction, validate_conflict, outpoints
from payment_resume import validate_resume_record, locally_resumable
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, from_hex
from test_framework.segwit_addr import decode_segwit_address, encode_segwit_address

COIN = 100_000_000
FEE = 100_000
MAX_MONEY = 21_000_000 * COIN
COINBASE_MATURITY = 100
PAYMENT_SCAN_LIMIT = 10_000
RECEIVED_LOOKUP_SECONDS = 25
HEX256 = re.compile(r"[0-9a-f]{64}\Z")


class NetworkError(RuntimeError):
    """Safe, fixed user-facing messages; never include RPC or signing details."""
    def __init__(self, message: str, code: str = "network_error"):
        super().__init__(message)
        self.message = message
        self.code = code


class PaymentPending(NetworkError):
    """Broadcast may have happened. A caller must not suggest a new payment."""
    def __init__(self, txid: str):
        super().__init__("Payment may have been broadcast, but four-node confirmation is not verified. "
                         "Keep its transaction ID, check its status, and do not create a replacement payment.",
                         "payment_pending")
        self.txid = txid
        self.receipt = {"txid": txid, "status": "pending", "message": self.message}


def format_amount(satoshis: int) -> str:
    return f"{satoshis // COIN}.{satoshis % COIN:08d}"


def parse_amount(value: str) -> int:
    """No floats, signs, exponent notation, whitespace, or silent rounding."""
    if type(value) is not str or len(value) > 17 or re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,8})?", value) is None:
        raise NetworkError("Enter a positive QLU amount with at most eight decimal places.", "invalid_amount")
    whole, _, fraction = value.partition(".")
    amount = int(whole) * COIN + int(fraction.ljust(8, "0") or "0")
    if not 0 < amount <= MAX_MONEY - FEE:
        raise NetworkError("The payment amount is outside this private network's supported range.", "invalid_amount")
    return amount


def address_script(address: str) -> bytes:
    if type(address) is not str or not 8 <= len(address) <= 90:
        raise NetworkError("Enter a valid QLU private-network receiving address.", "invalid_address")
    try:
        version, program = decode_segwit_address("qlud", address)
        if version != 2 or program is None or len(program) != 32:
            raise ValueError
        return b"\x52\x20" + bytes(program)
    except Exception:
        raise NetworkError("Enter a valid QLU private-network receiving address.", "invalid_address") from None


def _script(script: bytes) -> bytes:
    if type(script) is not bytes or len(script) != 34 or script[:2] != b"\x52\x20":
        raise NetworkError("The wallet's private-network identity is invalid.", "invalid_wallet")
    return script


def _rpc_amount(value) -> int:
    try:
        if type(value) not in (str, int, float, Decimal):
            raise ValueError
        amount = Decimal(str(value)) * COIN
        if not amount.is_finite() or amount != amount.to_integral_value() or not 0 <= amount <= MAX_MONEY:
            raise ValueError
        return int(amount)
    except (ValueError, InvalidOperation, OverflowError):
        raise NetworkError("A private node returned an invalid amount.") from None


def _null(value) -> bool:
    return value is None or (type(value) is str and value == "")


@dataclass(frozen=True, repr=False)
class PreparedPayment:
    tx: CTransaction
    spent: tuple[CTxOut, ...]
    own_script: bytes
    recipient: str
    amount: str
    fee: str
    total: str
    _owner: object = field(repr=False)
    _unsigned: bytes = field(repr=False)
    _previous: tuple[bytes, ...] = field(repr=False)

    def public(self) -> dict:
        same_wallet = address_script(self.recipient) == self.own_script
        return {**{name: getattr(self, name) for name in ("recipient", "amount", "fee", "total")},
                "is_self_transfer": same_wallet,
                "wallet_debit": self.fee if same_wallet else self.total}

    def __repr__(self):
        return f"<PreparedPayment amount={self.amount} fee={self.fee}>"


@dataclass(frozen=True, repr=False)
class PreparedResume:
    _payload: str = field(repr=False)
    _own_script: bytes = field(repr=False)
    _snapshot: tuple[int, str] = field(repr=False)
    _owner: object = field(repr=False)

    def public(self) -> dict:
        record = json.loads(self._payload)
        same_wallet = record["kind"] != "funding" and address_script(record["recipient"]) == self._own_script
        total = format_amount(parse_amount(record["amount"]) + FEE)
        return {**{key: record[key] for key in ("operation_id", "kind", "txid", "recipient", "amount", "fee")},
                "total": total, "is_self_transfer": same_wallet,
                "wallet_debit": "0.00000000" if record["kind"] == "funding" else record["fee"] if same_wallet else total,
                "wallet_credit": record["amount"] if record["kind"] == "funding" else "0.00000000"}

    def __repr__(self):
        return "<PreparedResume original authorized payment>"


class _AppNet(QLUPrivateNet):
    def __init__(self, root, data_name, process_label):
        self.data_name = data_name
        self.process_label = process_label
        super().__init__(root)

    @contextmanager
    def rpc_budget(self, deadline):
        previous = getattr(self, "_rpc_deadline", None)
        self._rpc_deadline = deadline if previous is None else min(previous, deadline)
        try:
            yield
        finally:
            self._rpc_deadline = previous

    def rpc(self, index, method, *args, **kwargs):
        # Applies to calls inside inherited identity/synchronization helpers as
        # well as block lookup. One in-flight call retains its 15-second limit.
        deadline = getattr(self, "_rpc_deadline", None)
        if deadline is not None and time.monotonic() >= deadline:
            raise NetworkError("The private lookup exceeded its time budget.", "incoming_unavailable")
        result = super().rpc(index, method, *args, **kwargs)
        if deadline is not None and time.monotonic() >= deadline:
            raise NetworkError("The private lookup exceeded its time budget.", "incoming_unavailable")
        return result


class WalletAppNetwork:
    def __init__(self, root=protocol.ROOT, data_name="wallet-app-net", process_label="QLUWalletApp"):
        if (type(data_name) is not str or re.fullmatch(r"wallet-app-[a-zA-Z0-9_-]{1,80}", data_name) is None
                or type(process_label) is not str or re.fullmatch(r"QLUWalletApp[a-zA-Z0-9_-]{0,80}", process_label) is None):
            raise NetworkError("Invalid private wallet-network location.")
        self.controller = _AppNet(Path(root), data_name, process_label)
        self._lock_context = None
        self._owns_lifecycle = False
        self._running = False
        self._mutex = threading.RLock()
        self._owner = object()
        self._faucet_wallet = None
        self._faucet_keys = None

    @property
    def running(self) -> bool:
        return self._running

    @contextmanager
    def reconciliation_budget(self, deadline):
        """Share one RPC deadline across multiple public history lookups."""
        with self._mutex, self.controller.rpc_budget(deadline):
            yield

    def _release(self):
        lock, self._lock_context = self._lock_context, None
        if lock is not None:
            lock.__exit__(None, None, None)

    def start(self):
        with self._mutex:
            if self._lock_context is not None or self._owns_lifecycle:
                raise NetworkError("This wallet network is already started or still needs cleanup.", "already_running")
            lock = private_port_lock(self.controller.root)
            try:
                lock.__enter__()
                self._lock_context = lock
                self.controller.setup()
                self.controller.require_binaries()
                # Never adopt a previous launch, even with a valid ownership file.
                self.controller.require_stopped()
                self._owns_lifecycle = True
                self.controller.start()
                self._running = True
                self._validate()
            except BaseException as error:
                if self._owns_lifecycle:
                    try:
                        self.stop()
                    except Exception:
                        raise NetworkError("Wallet network startup failed and cleanup is incomplete. "
                                           "Close the app only after stopping its private nodes.", "cleanup_failed") from None
                else:
                    self._release()
                if not isinstance(error, Exception):
                    raise
                raise NetworkError("The private network could not start. Another test may be running, "
                                   "or the local build, disk space, or configuration needs attention.", "start_failed") from None

    def stop(self):
        with self._mutex:
            self._faucet_wallet = None
            self._faucet_keys = None
            if not self._owns_lifecycle:
                self._running = False
                self._release()
                return
            try:
                self.controller.stop()
                if any(row.get("status") != "stopped" for row in self.controller.status()):
                    raise ValueError
            except Exception:
                # Retain the laboratory lock and ownership state for a retry.
                # An incomplete cleanup is never reported as a stopped network.
                raise NetworkError("Some private wallet nodes could not be stopped. Retry stopping the network; "
                                   "unrelated processes were left untouched.", "cleanup_failed") from None
            self._running = False
            self._owns_lifecycle = False
            self._owner = object()  # Prepared payments cannot survive a network restart.
            self._release()

    def _validate(self) -> str:
        if not self._running:
            raise NetworkError("Start the private test network first.", "network_stopped")
        try:
            deadline = time.monotonic() + 2
            while True:
                self.controller.setup()  # Refuses altered config, symlinks, and settings overrides.
                state = self.controller.read_state()
                if set(state) != {str(i) for i in range(NODE_COUNT)}:
                    raise ValueError
                markers = {index: f"{self.controller.process_label}-{state[str(index)]['token']}"
                           for index in range(NODE_COUNT)}
                incomplete = False
                for index in range(NODE_COUNT):
                    if not self.controller.owned(index, state[str(index)]):
                        raise ValueError
                    self.controller.verify_node(index)  # Exact qludev genesis and owned data directory.
                    info = self.controller.rpc(index, "getnetworkinfo")
                    if type(info) is not dict or info.get("networkactive") is not True:
                        raise ValueError
                    peers = self.controller.rpc(index, "getpeerinfo")
                    if type(peers) is not list:
                        raise ValueError
                    found = set()
                    for peer in peers:
                        if type(peer) is not dict:
                            raise ValueError
                        if not peer.get("addr", "").startswith("127.0.0.1:"):
                            raise ValueError
                        identity = peer.get("subver")
                        if identity == "":
                            # Extra inbound loopback connections can still be
                            # handshaking after the required mesh is ready. Wait
                            # briefly, never accept an unidentified peer.
                            incomplete = True
                        else:
                            matches = {other for other, marker in markers.items()
                                       if type(identity) is str and marker in identity}
                            if len(matches) != 1 or index in matches:
                                raise ValueError
                            # As at startup, a completed pong establishes that
                            # this distinct owned peer finished its handshake.
                            received = peer.get("bytesrecv_per_msg", {})
                            pong = received.get("pong", 0) if type(received) is dict else None
                            if type(pong) is not int or pong < 29:
                                incomplete = True
                            else:
                                found.update(matches)
                    if found != set(range(NODE_COUNT)) - {index}:
                        incomplete = True
                if not incomplete:
                    return self.controller.wait_synced()
                if time.monotonic() >= deadline:
                    raise ValueError
                time.sleep(0.05)
                # Each retry rechecks configuration, process ownership, genesis,
                # data paths and every peer. A changed identity fails closed.
        except Exception:
            raise NetworkError("The four private nodes failed their identity, ownership, or localhost checks. "
                               "No payment was authorized by this check.", "network_identity") from None

    def _scan(self, script: bytes) -> dict:
        script = _script(script)
        try:
            snapshot_height, tip = self._chain_snapshot()
            result = self.controller.rpc(0, "scantxoutset", "start", [f"raw({script.hex()})"])
            if (type(result) is not dict or result.get("success") is not True or result.get("bestblock") != tip
                    or type(result.get("height")) is not int or result["height"] != snapshot_height
                    or type(result.get("unspents")) is not list):
                raise ValueError
            available = immature = 0
            coins = []
            seen = set()
            for row in result["unspents"]:
                txid, vout, height = row["txid"], row["vout"], row["height"]
                amount = _rpc_amount(row["amount"])
                if (type(txid) is not str or HEX256.fullmatch(txid) is None
                        or type(vout) is not int or not 0 <= vout <= 0xffffffff
                        or type(height) is not int or not 0 <= height <= result["height"]
                        or row["scriptPubKey"] != script.hex() or type(row["coinbase"]) is not bool
                        or (txid, vout) in seen or amount <= 0):
                    raise ValueError
                seen.add((txid, vout))
                confirmations = result["height"] - height + 1
                # scantxoutset sees chain state only. Exclude inputs already spent
                # in the mempool before presenting them as available.
                spent_in_pool = False
                for index in range(NODE_COUNT):
                    current = self.controller.rpc(index, "gettxout", txid, vout, True)
                    if _null(current):
                        spent_in_pool = True
                        continue
                    self._check_coin(current, amount, script, require_mature=False)
                    if (current.get("bestblock") != tip or current["confirmations"] != confirmations
                            or row["coinbase"] != current["coinbase"]):
                        raise ValueError
                # A competing or not-yet-propagated mempool spend on any node
                # makes this outpoint unavailable to a new wallet payment.
                if spent_in_pool:
                    continue
                if row["coinbase"] and confirmations < COINBASE_MATURITY:
                    immature += amount
                else:
                    available += amount
                    coins.append({"txid": txid, "vout": vout, "height": height,
                                  "value": amount, "script": script})
            if available + immature > MAX_MONEY or self._chain_snapshot() != (result["height"], tip):
                raise ValueError
            coins.sort(key=lambda row: (row["height"], row["txid"], row["vout"]))
            return {"balance": format_amount(available), "immature_balance": format_amount(immature), "utxos": coins}
        except NetworkError:
            raise
        except Exception:
            raise NetworkError("Wallet balance could not be verified. Refresh after the private nodes agree.", "balance_failed") from None

    def balance(self, script: bytes) -> dict:
        with self._mutex:
            return self._scan(script)

    @staticmethod
    def _check_coin(coin, amount: int, script: bytes, *, require_mature=True):
        if (type(coin) is not dict or _rpc_amount(coin.get("value")) != amount
                or coin.get("scriptPubKey", {}).get("hex") != script.hex()
                or type(coin.get("confirmations")) is not int or coin["confirmations"] < 1
                or type(coin.get("coinbase")) is not bool
                or (require_mature and coin["coinbase"] and coin["confirmations"] < COINBASE_MATURITY)):
            raise NetworkError("A payment input changed or is not yet spendable. Review a fresh payment.", "stale_payment")

    def prepare(self, keys: dict, recipient: str, amount: str) -> PreparedPayment:
        try:
            own_script = protocol.script_for(keys)
        except Exception:
            raise NetworkError("The wallet's private-network identity is invalid.", "invalid_wallet") from None
        return self.prepare_send(own_script, recipient, amount)

    def prepare_send(self, script: bytes, recipient: str, amount: str) -> PreparedPayment:
        with self._mutex:
            script = _script(script)
            target = address_script(recipient)
            value = parse_amount(amount)
            recipient = encode_segwit_address("qlud", 2, target[2:])
            result = self._scan(script)
            selected, total = [], 0
            for coin in result["utxos"][:16]:
                selected.append(coin)
                total += coin["value"]
                if total >= value + FEE:
                    break
            if total < value + FEE:
                raise NetworkError("Insufficient spendable test QLU for the amount and fee within the 16-input limit.", "insufficient_funds")
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(row["txid"], 16), row["vout"]), nSequence=0xffffffff) for row in selected]
            tx.vout = [CTxOut(value, target)]
            if total > value + FEE:
                tx.vout.append(CTxOut(total - value - FEE, script))
            spent = tuple(CTxOut(row["value"], script) for row in selected)
            return PreparedPayment(tx, spent, script, recipient, format_amount(value), format_amount(FEE),
                                   format_amount(value + FEE), self._owner, tx.serialize_without_witness(),
                                   tuple(out.serialize() for out in spent))

    def _validate_prepared(self, prepared: PreparedPayment):
        try:
            if (not isinstance(prepared, PreparedPayment) or prepared._owner is not self._owner
                    or prepared.tx.serialize_without_witness() != prepared._unsigned
                    or tuple(out.serialize() for out in prepared.spent) != prepared._previous
                    or any(out.scriptPubKey != prepared.own_script for out in prepared.spent)
                    or prepared.tx.vout[0].scriptPubKey != address_script(prepared.recipient)
                    or prepared.tx.vout[0].nValue != parse_amount(prepared.amount)
                    or sum(out.nValue for out in prepared.spent) - sum(out.nValue for out in prepared.tx.vout) != FEE
                    or prepared.fee != format_amount(FEE)
                    or prepared.total != format_amount(parse_amount(prepared.amount) + FEE)):
                raise ValueError
        except Exception:
            raise NetworkError("This payment preview is no longer valid. Review a new payment.", "stale_payment") from None

    def _ensure_faucet(self):
        if self._faucet_wallet is None:
            try:
                wallet = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
                keys = protocol.keytool(wallet)
                _script(protocol.script_for(keys))
                self._faucet_wallet, self._faucet_keys = wallet, keys
            except Exception:
                raise NetworkError("The disposable test-fund key could not be prepared.", "faucet_failed") from None
        return protocol.address_for(self._faucet_keys)

    def _validate_conflict_guards(self, records, tip):
        """A saved resolution cannot authorize spending on a different chain."""
        if not records:
            return
        deadline = time.monotonic() + RECEIVED_LOOKUP_SECONDS
        try:
            if type(records) not in (list, tuple) or len(records) > 10_000:
                raise ValueError
            with self.controller.rpc_budget(deadline):
                for record in records:
                    if type(record) is not dict or record.get("status") != "conflicted":
                        raise ValueError
                    result = self.payment_status(record)
                    if result.get("status") != "conflicted":
                        raise ValueError
                if time.monotonic() >= deadline or self._chain_snapshot()[1] != tip:
                    raise ValueError
        except Exception:
            raise NetworkError("A previous payment conflict changed. Check payment status and review again.",
                               "stale_payment") from None

    def _submit(self, prepared: PreparedPayment, signer: Callable, *, before_broadcast=None,
                conflict_records=()) -> dict:
        self._validate_prepared(prepared)
        tip = self._validate()
        try:
            for txin, previous in zip(prepared.tx.vin, prepared.spent, strict=True):
                txid = f"{txin.prevout.hash:064x}"
                for index in range(NODE_COUNT):
                    current = self.controller.rpc(index, "gettxout", txid, txin.prevout.n, True)
                    self._check_coin(current, previous.nValue, previous.scriptPubKey)
                    if current.get("bestblock") != tip:
                        raise NetworkError("The chain changed after review. Review a fresh payment.", "stale_payment")
        except NetworkError:
            raise
        except Exception:
            raise NetworkError("Payment inputs could not be checked. No payment was signed.", "stale_payment") from None
        mining_address = self._ensure_faucet()
        self._validate_conflict_guards(conflict_records, tip)
        try:
            signed = signer(CTransaction(prepared.tx), [CTxOut(out.nValue, out.scriptPubKey) for out in prepared.spent])
            if signed.serialize_without_witness() != prepared._unsigned:
                raise ValueError
            raw = signed.serialize_with_witness().hex()
            txid = signed.txid_hex
        except Exception:
            raise NetworkError("The wallet could not sign this payment. Unlock it and review again.", "signing_failed") from None
        try:
            for index in range(NODE_COUNT):
                accepted = self.controller.rpc(index, "testmempoolaccept", [raw])
                if type(accepted) is not list or len(accepted) != 1 or accepted[0].get("allowed") is not True:
                    raise ValueError
        except Exception:
            raise NetworkError("The payment was rejected before broadcast. Review its available funds and fee.", "payment_rejected") from None
        try:
            start_height, current_tip = self._chain_snapshot()
            if current_tip != tip:
                raise ValueError
        except Exception:
            raise NetworkError("The private chain changed before broadcast. Review a fresh payment.", "stale_payment") from None
        # A durable record must exist before the first RPC that might submit the
        # signed transaction. A failed write is NOT an uncertain broadcast.
        self._validate_conflict_guards(conflict_records, tip)
        if before_broadcast is not None:
            try:
                before_broadcast({"txid": txid, "recipient": prepared.recipient,
                                  "amount": prepared.amount, "fee": prepared.fee,
                                  "start_height": start_height,
                                  "transaction": signed.serialize_without_witness().hex(),
                                  "signed_transaction": raw,
                                  "spent_outputs": [{"value": out.nValue, "script": out.scriptPubKey.hex()}
                                                    for out in prepared.spent]})
            except Exception:
                raise NetworkError("Payment history could not be saved. No payment was broadcast.",
                                   "history_failed") from None
        # From this point even a timed-out RPC might have submitted the payment.
        # Always preserve the locally computed txid and prohibit blind retry.
        try:
            if self.controller.rpc(0, "sendrawtransaction", raw) != txid:
                raise ValueError
            result = self.controller.rpc(0, "generateblock", mining_address, [raw])
            block = result["hash"]
            if type(block) is not str or HEX256.fullmatch(block) is None:
                raise ValueError
            self.controller.wait_synced(block)
            if self._validate() != block:
                raise ValueError
            for index in range(NODE_COUNT):
                for vout, output in enumerate(signed.vout):
                    current = self.controller.rpc(index, "gettxout", txid, vout, True)
                    self._check_coin(current, output.nValue, output.scriptPubKey)
                    if current.get("bestblock") != block or current.get("coinbase") is not False:
                        raise ValueError
                for txin in signed.vin:
                    if not _null(self.controller.rpc(index, "gettxout", f"{txin.prevout.hash:064x}", txin.prevout.n, True)):
                        raise ValueError
            # A previously checked node can reorganize while the later nodes
            # are being inspected. Never publish that stale confirmation.
            if self._chain_snapshot() != (start_height + 1, block):
                raise ValueError
            return {"txid": txid, "block": block, "amount": prepared.amount, "fee": prepared.fee,
                    "recipient": prepared.recipient, "confirmed_nodes": NODE_COUNT,
                    "start_height": start_height}
        except Exception:
            raise PaymentPending(txid) from None

    def send(self, session, prepared: PreparedPayment, *, before_broadcast=None, conflict_records=()) -> dict:
        """The wallet app supplies its durable callback; omission is for lab harnesses."""
        with self._mutex:
            if session.locked:
                raise NetworkError("Unlock your wallet before sending.", "wallet_locked")
            return self._submit(prepared, session.sign, before_broadcast=before_broadcast,
                                conflict_records=conflict_records)

    def _check_resume(self, record, own_script):
        """Fresh chain/input/mempool proof; no signing, mining or submission."""
        if not locally_resumable(record):
            raise NetworkError("This payment cannot be resumed from its saved record. Check payment status.",
                               "resume_unavailable")
        try:
            signed = validate_resume_record(record, _script(own_script))
            snapshot = self._chain_snapshot()
            if (type(record.get("start_height")) is not int
                    or not 0 <= record["start_height"] <= snapshot[0]):
                raise ValueError
            pooled = []
            for index in range(NODE_COUNT):
                pool = self.controller.rpc(index, "getrawmempool")
                if (type(pool) is not list or len(set(pool)) != len(pool)
                        or any(type(item) is not str or HEX256.fullmatch(item) is None for item in pool)):
                    raise ValueError
                present = record["txid"] in pool
                pooled.append(present)
                if present and self.controller.rpc(index, "getrawtransaction", record["txid"], False) != record["signed_transaction"]:
                    raise ValueError
                for txin, previous in zip(signed.vin, record["spent_outputs"], strict=True):
                    # Chain-only availability remains checkable when the exact
                    # original already occupies some peers' mempools. An absent
                    # peer must also have no competing unconfirmed input spend.
                    for include_mempool in ([False] if present else [False, True]):
                        coin = self.controller.rpc(index, "gettxout", f"{txin.prevout.hash:064x}",
                                                   txin.prevout.n, include_mempool)
                        self._check_coin(coin, previous["value"], bytes.fromhex(previous["script"]))
                        if coin.get("bestblock") != snapshot[1]:
                            raise ValueError
                if not present:
                    accepted = self.controller.rpc(index, "testmempoolaccept", [record["signed_transaction"]])
                    if type(accepted) is not list or len(accepted) != 1 or accepted[0].get("allowed") is not True:
                        raise ValueError
            if self._chain_snapshot() != snapshot:
                raise ValueError
            return snapshot, pooled
        except Exception:
            raise NetworkError("The original payment could not be safely checked on all four private nodes. "
                               "Check payment status and review again.", "stale_payment") from None

    def prepare_resume(self, record: dict, own_script: bytes) -> PreparedResume:
        """Review only the original immutable signed payment; no new payment."""
        with self._mutex, self.controller.rpc_budget(time.monotonic() + RECEIVED_LOOKUP_SECONDS):
            snapshot, _ = self._check_resume(record, own_script)
            return PreparedResume(json.dumps(record, sort_keys=True, separators=(",", ":")),
                                  own_script, snapshot, self._owner)

    def resume(self, prepared: PreparedResume, *, before_broadcast, conflict_records=()) -> dict:
        """Rebroadcast exact durable bytes, then verify the same payment on four nodes.

        There is deliberately no signer or wallet session parameter. A fresh
        one-use review and a durable-journal guard are supplied by the bridge.
        """
        with self._mutex, self.controller.rpc_budget(time.monotonic() + RECEIVED_LOOKUP_SECONDS):
            if (not isinstance(prepared, PreparedResume) or prepared._owner is not self._owner
                    or not callable(before_broadcast)):
                raise NetworkError("Review the original payment again before resuming.", "resume_invalid")
            record = json.loads(prepared._payload)
            snapshot, pooled = self._check_resume(record, prepared._own_script)
            if snapshot != prepared._snapshot:
                raise NetworkError("The private chain changed. Review the original payment again.", "stale_payment")
            # Creating a disposable mining destination does not re-sign the
            # original spend and never changes its fee or transaction ID.
            mining_address = self._ensure_faucet()
            self._validate_conflict_guards(conflict_records, snapshot[1])
            if self._chain_snapshot() != snapshot:
                raise NetworkError("The private chain changed. Review the original payment again.", "stale_payment")
            try:
                before_broadcast()
            except Exception:
                raise NetworkError("The saved payment history changed. No payment was resumed.", "history_failed") from None
            try:
                for index, present in enumerate(pooled):
                    if not present:
                        try:
                            if self.controller.rpc(index, "sendrawtransaction", record["signed_transaction"]) != record["txid"]:
                                raise ValueError
                        except Exception:
                            # Propagation can win the race between peers. Only
                            # the exact same bytes in that peer's pool count.
                            if self.controller.rpc(index, "getrawtransaction", record["txid"], False) != record["signed_transaction"]:
                                raise
                for index in range(NODE_COUNT):
                    if self.controller.rpc(index, "getrawtransaction", record["txid"], False) != record["signed_transaction"]:
                        raise ValueError
                if self._chain_snapshot() != snapshot:
                    raise ValueError
                before_broadcast()
                result = self.controller.rpc(0, "generateblock", mining_address, [record["txid"]])
                block = result["hash"]
                if type(block) is not str or HEX256.fullmatch(block) is None:
                    raise ValueError
                self.controller.wait_synced(block)
                receipt = self.payment_status({**record, "block": block}, finish=False)
                if receipt.get("status") != "confirmed" or receipt.get("confirmed_nodes") != NODE_COUNT:
                    raise ValueError
                return receipt
            except Exception:
                raise PaymentPending(record["txid"]) from None

    def faucet(self, recipient: str, *, before_broadcast=None, conflict_records=()) -> dict:
        """Fund a private wallet through the same durable boundary as normal sends."""
        with self._mutex:
            address_script(recipient)
            self._validate()
            address = self._ensure_faucet()
            result = self._scan(protocol.script_for(self._faucet_keys))
            if sum(row["value"] for row in result["utxos"][:16]) < COIN + FEE:
                try:
                    blocks = self.controller.rpc(0, "generatetoaddress", 101, address)
                    if type(blocks) is not list or len(blocks) != 101:
                        raise ValueError
                    self.controller.wait_synced(blocks[-1])
                except Exception:
                    raise NetworkError("The private test-fund mining step failed. The existing chain was preserved.", "faucet_failed") from None
            try:
                prepared = self.prepare(self._faucet_keys, recipient, "1.00000000")
            except NetworkError as error:
                if error.code == "insufficient_funds":
                    raise NetworkError("This persistent laboratory's mining rewards cannot fund another 1 QLU payment "
                                       "within the input limit. The chain was not reset.", "faucet_exhausted") from None
                raise
            return self._submit(prepared, lambda tx, spent: protocol.sign_transaction(self._faucet_wallet, tx, spent),
                                before_broadcast=before_broadcast, conflict_records=conflict_records)

    def _chain_snapshot(self) -> tuple[int, str]:
        """A strict active-chain height shared by all owned, identity-checked nodes."""
        tip = self._validate()
        if type(tip) is not str or HEX256.fullmatch(tip) is None:
            raise ValueError
        heights = []
        for index in range(NODE_COUNT):
            height = self.controller.rpc(index, "getblockcount")
            if (type(height) is not int or not 0 <= height <= 0x7fffffff
                    or self.controller.rpc(index, "getbestblockhash") != tip):
                raise ValueError
            heights.append(height)
        if len(set(heights)) != 1:
            raise ValueError
        return heights[0], tip

    def _active_payment_block(self, txid: str, height: int) -> str | None:
        """Confirm membership in an active block, even when all outputs are spent."""
        hashes, membership = [], []
        for index in range(NODE_COUNT):
            block_hash = self.controller.rpc(index, "getblockhash", height)
            if type(block_hash) is not str or HEX256.fullmatch(block_hash) is None:
                raise ValueError
            block = self.controller.rpc(index, "getblock", block_hash, 1)
            if (type(block) is not dict or block.get("hash") != block_hash
                    or type(block.get("height")) is not int or block["height"] != height
                    or type(block.get("confirmations")) is not int or block["confirmations"] < 1
                    or type(block.get("tx")) is not list
                    or not block["tx"]
                    or any(type(value) is not str or HEX256.fullmatch(value) is None for value in block["tx"])
                    or len(set(block["tx"])) != len(block["tx"])):
                raise ValueError
            hashes.append(block_hash)
            membership.append(txid in block["tx"])
        if len(set(hashes)) != 1 or len(set(membership)) != 1:
            raise ValueError
        return hashes[0] if membership[0] else None

    def verify_received_payment(self, txid: str, own_script: bytes, *, block_hint=None) -> dict:
        """Read-only proof from four owned nodes' active block and undo data.

        A bounded backward search finds the candidate without a transaction
        index. A saved block is an untrusted height hint only. All four nodes
        must agree on canonical transaction bytes and validated undo prevouts;
        this is not an independent Merkle proof. Any own input means self/change
        or mixed ownership, conservatively refused as a new incoming payment.
        """
        if (type(txid) is not str or HEX256.fullmatch(txid) is None
                or (block_hint is not None and (type(block_hint) is not str or HEX256.fullmatch(block_hint) is None))):
            raise NetworkError("Enter a complete transaction ID with 64 lowercase hexadecimal characters.", "invalid_transaction")
        own_script = _script(own_script)
        deadline = time.monotonic() + RECEIVED_LOOKUP_SECONDS

        def unavailable():
            return NetworkError("This incoming payment could not be verified on all four private nodes. Try checking again.",
                                "incoming_unavailable")

        def rpc(index, method, *args):
            # The node RPC already has a finite transport timeout. Checking the
            # shared deadline between calls bounds the whole historical search.
            if time.monotonic() >= deadline:
                raise unavailable()
            value = self.controller.rpc(index, method, *args)
            if time.monotonic() >= deadline:
                raise unavailable()
            return value

        def block_transactions(block, block_hash, block_height, *, verbose):
            if (type(block) is not dict or block.get("hash") != block_hash
                    or type(block.get("height")) is not int or block["height"] != block_height
                    or type(block.get("confirmations")) is not int or block["confirmations"] < 1
                    or type(block.get("tx")) is not list or not 1 <= len(block["tx"]) <= 100_000):
                raise ValueError
            ids = [row.get("txid") if type(row) is dict else None for row in block["tx"]] if verbose else block["tx"]
            if any(type(value) is not str or HEX256.fullmatch(value) is None for value in ids) or len(set(ids)) != len(ids):
                raise ValueError
            return ids

        with self._mutex, self.controller.rpc_budget(deadline):
            try:
                height, tip = self._chain_snapshot()
                if time.monotonic() >= deadline:
                    raise unavailable()
                candidate = None
                visited = set()
                heights = []
                if block_hint is not None:
                    hint = rpc(0, "getblockheader", block_hint, True)
                    if (type(hint) is not dict or hint.get("hash") != block_hint
                            or type(hint.get("height")) is not int or hint["height"] < 0):
                        raise ValueError
                    if hint["height"] <= height:
                        heights.append(hint["height"])
                heights.extend(range(height, max(-1, height - PAYMENT_SCAN_LIMIT), -1))
                for block_height in heights:
                    if block_height in visited:
                        continue
                    visited.add(block_height)
                    block_hash = rpc(0, "getblockhash", block_height)
                    if type(block_hash) is not str or HEX256.fullmatch(block_hash) is None:
                        raise ValueError
                    block = rpc(0, "getblock", block_hash, 1)
                    if txid in block_transactions(block, block_hash, block_height, verbose=False):
                        candidate = (block_height, block_hash)
                        break
                if candidate is None:
                    if height + 1 > PAYMENT_SCAN_LIMIT:
                        raise unavailable()
                    if self._chain_snapshot() != (height, tip):
                        raise ValueError
                    raise NetworkError("That transaction is not confirmed on this private network yet.", "incoming_not_found")
                block_height, block_hash = candidate
                fingerprints = []
                amount = None
                for index in range(NODE_COUNT):
                    if rpc(index, "getblockhash", block_height) != block_hash:
                        raise ValueError
                    block = rpc(index, "getblock", block_hash, 3)
                    ids = block_transactions(block, block_hash, block_height, verbose=True)
                    if txid not in ids:
                        raise ValueError
                    row = block["tx"][ids.index(txid)]
                    raw = row.get("hex")
                    if (type(raw) is not str or not 2 <= len(raw) <= 8_000_000 or len(raw) % 2
                            or re.fullmatch(r"[0-9a-f]+", raw) is None):
                        raise ValueError
                    transaction = from_hex(CTransaction(), raw)
                    if transaction.serialize_with_witness().hex() != raw or transaction.txid_hex != txid:
                        raise ValueError
                    if (not 1 <= len(transaction.vin) <= 16 or not 1 <= len(transaction.vout) <= 32
                            or type(row.get("vin")) is not list or len(row["vin"]) != len(transaction.vin)):
                        raise ValueError
                    if any(value.prevout.hash == 0 and value.prevout.n == 0xffffffff for value in transaction.vin):
                        raise NetworkError("Mining rewards and self-transfers are not new incoming payments.", "incoming_not_received")
                    received = sum(output.nValue for output in transaction.vout if output.scriptPubKey == own_script)
                    if (any(output.nValue < 0 or output.nValue > MAX_MONEY for output in transaction.vout)
                            or sum(output.nValue for output in transaction.vout) > MAX_MONEY):
                        raise ValueError
                    if not 0 < received <= MAX_MONEY:
                        raise NetworkError("That transaction does not contain a new payment to this wallet.", "incoming_not_received")
                    previous = []
                    for txin, public_input in zip(transaction.vin, row["vin"], strict=True):
                        if (type(public_input) is not dict or public_input.get("txid") != f"{txin.prevout.hash:064x}"
                                or type(public_input.get("vout")) is not int or public_input["vout"] != txin.prevout.n
                                or type(public_input.get("prevout")) is not dict):
                            raise ValueError
                        undo = public_input["prevout"]
                        script = _script(bytes.fromhex(undo["scriptPubKey"]["hex"]))
                        value = _rpc_amount(undo["value"])
                        if value <= 0:
                            raise ValueError
                        if script == own_script:
                            raise NetworkError("That transaction spends from this wallet, so its outputs are not new incoming payments.",
                                               "incoming_not_received")
                        previous.append((f"{txin.prevout.hash:064x}", txin.prevout.n, value, script))
                    fingerprints.append((raw, tuple(previous)))
                    amount = received
                if len(set(fingerprints)) != 1 or self._chain_snapshot() != (height, tip):
                    raise ValueError
                if time.monotonic() >= deadline:
                    raise unavailable()
                return {"txid": txid, "block": block_hash, "start_height": block_height,
                        "recipient": encode_segwit_address("qlud", 2, own_script[2:]),
                        "amount": format_amount(amount), "confirmed_nodes": NODE_COUNT}
            except NetworkError as error:
                if error.code in {"incoming_not_found", "incoming_not_received", "incoming_unavailable"}:
                    raise
                raise unavailable() from None
            except Exception:
                raise unavailable() from None

    def _received_payment_status(self, record: dict) -> dict:
        try:
            script = address_script(record.get("recipient"))
            amount = _rpc_amount(record.get("amount"))
            if amount <= 0 or record.get("amount") != format_amount(amount) or "fee" in record:
                raise ValueError
        except Exception:
            raise NetworkError("The saved incoming payment record is invalid.", "invalid_payment_record") from None
        public = {key: record[key] for key in ("txid", "recipient", "amount", "start_height")}
        try:
            verified = self.verify_received_payment(record["txid"], script, block_hint=record.get("block"))
            if verified["amount"] != record["amount"] or verified["recipient"] != record["recipient"]:
                raise ValueError
            return {**verified, "start_height": record["start_height"], "status": "confirmed"}
        except Exception:
            # Incoming history is observational. A reorg/missing undo never
            # authorizes mining, signing, or a replacement transaction here.
            return {**public, "status": "pending", "status_reason": "network_unavailable"}

    def _find_conflict(self, record, original, snapshot):
        """Prove an active competing spend; stored proof fields are hints only.

        Node zero supplies candidates. Every accepted candidate is then decoded
        and checked against the active block and exact raw bytes on all four
        owned nodes. A bounded search never equates absence with rejection.
        """
        height, tip = snapshot
        original_inputs = outpoints(original)
        deadline = time.monotonic() + RECEIVED_LOOKUP_SECONDS

        def block_rows(block, block_hash, block_height):
            if (type(block) is not dict or block.get("hash") != block_hash
                    or type(block.get("height")) is not int or block["height"] != block_height
                    or type(block.get("confirmations")) is not int
                    or block["confirmations"] != height - block_height + 1
                    or type(block.get("tx")) is not list or not 1 <= len(block["tx"]) <= 100_000):
                raise ValueError
            ids = [row.get("txid") if type(row) is dict else None for row in block["tx"]]
            if any(type(item) is not str or HEX256.fullmatch(item) is None for item in ids) or len(set(ids)) != len(ids):
                raise ValueError
            return block["tx"]

        def decode(row):
            raw = row.get("hex")
            if (type(raw) is not str or not 2 <= len(raw) <= 8_000_000 or len(raw) % 2
                    or re.fullmatch(r"[0-9a-f]+", raw) is None):
                raise ValueError
            tx = from_hex(CTransaction(), raw)
            if (tx.serialize_with_witness().hex() != raw or tx.txid_hex != row["txid"]
                    or tx.version != 2 or not 1 <= len(tx.vin) <= 16 or not 1 <= len(tx.vout) <= 32
                    or len(outpoints(tx)) != len(tx.vin)):
                raise ValueError
            return tx, raw

        with self.controller.rpc_budget(deadline):
            heights = []
            hint = record.get("conflict")
            if hint is not None:
                validate_conflict(hint, record["transaction"], record["txid"])
                if hint["height"] <= height:
                    heights.append(hint["height"])
            heights.extend(range(height, max(-1, height - PAYMENT_SCAN_LIMIT), -1))
            visited = set()
            for block_height in heights:
                if time.monotonic() >= deadline:
                    raise ValueError
                if block_height in visited:
                    continue
                visited.add(block_height)
                block_hash = self.controller.rpc(0, "getblockhash", block_height)
                if type(block_hash) is not str or HEX256.fullmatch(block_hash) is None:
                    raise ValueError
                rows = block_rows(self.controller.rpc(0, "getblock", block_hash, 2), block_hash, block_height)
                for row in rows:
                    # Public vin only filters candidates. It is never the proof.
                    if type(row.get("vin")) is not list:
                        raise ValueError
                    if not any(type(item) is dict and type(item.get("vout")) is int
                               and type(item.get("txid")) is str
                               and (item["txid"], item["vout"]) in original_inputs for item in row["vin"]):
                        continue
                    candidate, raw = decode(row)
                    shared = original_inputs & outpoints(candidate)
                    if not shared:
                        raise ValueError
                    fingerprints = []
                    for index in range(NODE_COUNT):
                        if self.controller.rpc(index, "getblockhash", block_height) != block_hash:
                            raise ValueError
                        peer_rows = block_rows(self.controller.rpc(index, "getblock", block_hash, 2), block_hash, block_height)
                        matches = [item for item in peer_rows if item["txid"] == candidate.txid_hex]
                        if len(matches) != 1:
                            raise ValueError
                        peer_tx, peer_raw = decode(matches[0])
                        if peer_raw != raw or original_inputs & outpoints(peer_tx) != shared:
                            raise ValueError
                        fingerprints.append(peer_raw)
                        for txid, vout in shared:
                            if not _null(self.controller.rpc(index, "gettxout", txid, vout, False)):
                                raise ValueError
                    if len(set(fingerprints)) != 1 or self._chain_snapshot() != snapshot or time.monotonic() >= deadline:
                        raise ValueError
                    if candidate.txid_hex == record["txid"]:
                        return {"status": "confirmed", "block": block_hash, "confirmed_nodes": NODE_COUNT}
                    txid, vout = sorted(shared)[0]
                    conflict = {"txid": candidate.txid_hex, "block": block_hash, "height": block_height,
                                "input": {"txid": txid, "vout": vout}}
                    validate_conflict(conflict, record["transaction"], record["txid"])
                    return {"status": "conflicted", "conflict": conflict, "confirmed_nodes": NODE_COUNT}
            if self._chain_snapshot() != snapshot or time.monotonic() >= deadline:
                raise ValueError
            return None

    def payment_status(self, record: dict, *, finish=False) -> dict:
        """Reconcile a public journal record without signing or broadcasting again.

        Absence and uncertainty never establish rejection. A confirmed receipt is
        rechecked against active-chain block membership on all four private nodes.
        Optional finishing mines only an existing, unanimously pooled txid.
        """
        if (type(record) is not dict or type(finish) is not bool
                or type(record.get("txid")) is not str or HEX256.fullmatch(record["txid"]) is None
                or type(record.get("start_height")) is not int
                or not 0 <= record["start_height"] <= 0x7fffffff
                or ("block" in record and (type(record["block"]) is not str or HEX256.fullmatch(record["block"]) is None))):
            raise NetworkError("The saved payment record is invalid.", "invalid_payment_record")
        if record.get("kind") == "receive":
            return self._received_payment_status(record)
        try:
            original = None
            if "transaction" in record:
                original = validate_transaction(record["transaction"], record["txid"])
            if "conflict" in record:
                validate_conflict(record["conflict"], record.get("transaction"), record["txid"])
            address_script(record.get("recipient"))
            amount = parse_amount(record.get("amount"))
            if record.get("amount") != format_amount(amount) or record.get("fee") != format_amount(FEE):
                raise ValueError
        except Exception:
            raise NetworkError("The saved payment record is invalid.", "invalid_payment_record") from None
        public = {key: record[key] for key in ("txid", "recipient", "amount", "fee", "start_height")}

        def pending(reason):
            return {**public, "status": "pending", "status_reason": reason}

        with self._mutex:
            try:
                height, tip = self._chain_snapshot()
                found = None
                scan_limited = height - record["start_height"] + 1 > PAYMENT_SCAN_LIMIT
                # A saved block is a lookup hint only. The active height mapping
                # and transaction membership must still agree on every node.
                if "block" in record:
                    try:
                        hint = self.controller.rpc(0, "getblockheader", record["block"], True)
                    except RpcError as error:
                        # An orphan header may be absent after rebuilding node
                        # data. Ignore only explicit block-not-found, never a
                        # transport failure or a malformed successful response.
                        if error.code != -5:
                            raise
                    else:
                        if (type(hint) is not dict or hint.get("hash") != record["block"]
                                or type(hint.get("height")) is not int or hint["height"] < 0):
                            raise ValueError
                        if hint["height"] <= height:
                            found = self._active_payment_block(record["txid"], hint["height"])
                if found is None and not scan_limited:
                    for block_height in range(record["start_height"], height + 1):
                        found = self._active_payment_block(record["txid"], block_height)
                        if found is not None:
                            break
                if self._chain_snapshot() != (height, tip):
                    raise ValueError
                if found is not None:
                    return {**public, "status": "confirmed", "block": found,
                            "confirmed_nodes": NODE_COUNT}
                pooled = []
                for index in range(NODE_COUNT):
                    pool = self.controller.rpc(index, "getrawmempool")
                    if (type(pool) is not list
                            or any(type(value) is not str or HEX256.fullmatch(value) is None for value in pool)
                            or len(set(pool)) != len(pool)):
                        raise ValueError
                    pooled.append(record["txid"] in pool)
                if self._chain_snapshot() != (height, tip) or len(set(pooled)) != 1:
                    raise ValueError
                if not pooled[0]:
                    if original is not None:
                        resolution = self._find_conflict(record, original, (height, tip))
                        if resolution is not None:
                            return {**public, **resolution}
                    return pending("scan_limit" if scan_limited else "not_found")
                if not finish or "conflict" in record:
                    return pending("mempool")
                # generateblock accepts the existing transaction's id from the
                # mempool. Never reconstruct, resign, or sendrawtransaction here.
                result = self.controller.rpc(0, "generateblock", self._ensure_faucet(), [record["txid"]])
                block = result["hash"]
                if type(block) is not str or HEX256.fullmatch(block) is None:
                    raise ValueError
                self.controller.wait_synced(block)
                return self.payment_status({**record, **public, "block": block}, finish=False)
            except Exception:
                return pending("network_unavailable")
