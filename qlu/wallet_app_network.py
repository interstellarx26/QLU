"""Local QLU wallet-app network adapter; valueless private laboratory coins only.

The fixed 0.001 QLU fee and automatic block generation are test conveniences,
not public fee estimation or mining policy. This adapter never changes consensus,
imports keys into a node, or connects to public peers. Faucet keys exist only in
this process and are discarded on stop; the chain itself is never reset.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
import re
import threading
from typing import Callable

from devnet import NODE_COUNT
from lab import private_port_lock
from private_net import QLUPrivateNet
import protocol
import recovery
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.segwit_addr import decode_segwit_address, encode_segwit_address

COIN = 100_000_000
FEE = 100_000
MAX_MONEY = 21_000_000 * COIN
COINBASE_MATURITY = 100
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
                         "Do not send it again; keep this transaction ID for verification.",
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
        return {name: getattr(self, name) for name in ("recipient", "amount", "fee", "total")}

    def __repr__(self):
        return f"<PreparedPayment amount={self.amount} fee={self.fee}>"


class _AppNet(QLUPrivateNet):
    def __init__(self, root, data_name, process_label):
        self.data_name = data_name
        self.process_label = process_label
        super().__init__(root)


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
            self.controller.setup()  # Refuses altered config, symlinks, and settings overrides.
            state = self.controller.read_state()
            if set(state) != {str(i) for i in range(NODE_COUNT)}:
                raise ValueError
            markers = {f"{self.controller.process_label}-{entry['token']}" for entry in state.values()}
            for index in range(NODE_COUNT):
                if not self.controller.owned(index, state[str(index)]):
                    raise ValueError
                self.controller.verify_node(index)  # Exact qludev genesis and owned data directory.
                for peer in self.controller.rpc(index, "getpeerinfo"):
                    if (not peer.get("addr", "").startswith("127.0.0.1:")
                            or not any(marker in peer.get("subver", "") for marker in markers)):
                        raise ValueError
            return self.controller.wait_synced()
        except Exception:
            raise NetworkError("The four private nodes failed their identity, ownership, or localhost checks. "
                               "No payment was authorized by this check.", "network_identity") from None

    def _scan(self, script: bytes) -> dict:
        script = _script(script)
        tip = self._validate()
        try:
            result = self.controller.rpc(0, "scantxoutset", "start", [f"raw({script.hex()})"])
            if (type(result) is not dict or result.get("success") is not True or result.get("bestblock") != tip
                    or type(result.get("height")) is not int or result["height"] < 0
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
                current = self.controller.rpc(0, "gettxout", txid, vout, True)
                if _null(current):
                    continue
                self._check_coin(current, amount, script, require_mature=False)
                if current.get("bestblock") != tip or current["confirmations"] != confirmations:
                    raise ValueError
                if row["coinbase"] != current["coinbase"]:
                    raise ValueError
                if row["coinbase"] and confirmations < COINBASE_MATURITY:
                    immature += amount
                else:
                    available += amount
                    coins.append({"txid": txid, "vout": vout, "height": height,
                                  "value": amount, "script": script})
            if available + immature > MAX_MONEY or self.controller.rpc(0, "getbestblockhash") != tip:
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

    def _submit(self, prepared: PreparedPayment, signer: Callable) -> dict:
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
            return {"txid": txid, "block": block, "amount": prepared.amount, "fee": prepared.fee,
                    "recipient": prepared.recipient, "confirmed_nodes": NODE_COUNT}
        except Exception:
            raise PaymentPending(txid) from None

    def send(self, session, prepared: PreparedPayment) -> dict:
        with self._mutex:
            if session.locked:
                raise NetworkError("Unlock your wallet before sending.", "wallet_locked")
            return self._submit(prepared, session.sign)

    def faucet(self, recipient: str) -> dict:
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
            return self._submit(prepared, lambda tx, spent: protocol.sign_transaction(self._faucet_wallet, tx, spent))
