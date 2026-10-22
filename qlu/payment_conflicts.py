"""Bounded public metadata for chain-proven outgoing payment conflicts.

This validates local evidence shapes and the original transaction's txid, not
chain membership. The network adapter must prove the competing spend afresh.
No signature, private key or broadcasting capability is stored here.
"""
import re

try:
    from . import protocol  # Establish the pinned test-framework import path.
except ImportError:
    import protocol
from test_framework.messages import CTransaction, from_hex

HEX256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_TRANSACTION_HEX = 16_384


def _require(condition):
    if not condition:
        raise ValueError("Invalid public payment conflict metadata")


def outpoints(transaction):
    return {(f"{item.prevout.hash:064x}", item.prevout.n) for item in transaction.vin}


def validate_transaction(transaction, txid):
    _require(type(txid) is str and HEX256.fullmatch(txid) is not None)
    _require(type(transaction) is str and 2 <= len(transaction) <= MAX_TRANSACTION_HEX
             and len(transaction) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", transaction) is not None)
    try:
        parsed = from_hex(CTransaction(), transaction)
        _require(parsed.serialize_without_witness().hex() == transaction and parsed.txid_hex == txid)
        _require(parsed.version == 2 and 1 <= len(parsed.vin) <= 16 and 1 <= len(parsed.vout) <= 32)
        _require(len(outpoints(parsed)) == len(parsed.vin))
        _require(all(not (item.prevout.hash == 0 and item.prevout.n == 0xffffffff) for item in parsed.vin))
        _require(all(0 <= item.nValue <= 21_000_000 * 100_000_000 for item in parsed.vout))
        _require(sum(item.nValue for item in parsed.vout) <= 21_000_000 * 100_000_000)
        return parsed
    except Exception:
        raise ValueError("Invalid public payment transaction") from None


def validate_conflict(conflict, transaction, txid):
    original = validate_transaction(transaction, txid)
    _require(type(conflict) is dict and set(conflict) == {"txid", "block", "height", "input"})
    for name in ("txid", "block"):
        _require(type(conflict[name]) is str and HEX256.fullmatch(conflict[name]) is not None)
    _require(conflict["txid"] != txid)
    _require(type(conflict["height"]) is int and 0 <= conflict["height"] <= 0x7fffffff)
    item = conflict["input"]
    _require(type(item) is dict and set(item) == {"txid", "vout"})
    _require(type(item["txid"]) is str and HEX256.fullmatch(item["txid"]) is not None)
    _require(type(item["vout"]) is int and 0 <= item["vout"] <= 0xffffffff)
    _require((item["txid"], item["vout"]) in outpoints(original))
    return conflict
