"""Bounded validation for a private wallet's already-authorized payment outbox.

This checks encoding, identity and intent, not cryptographic validity. Every
resume also requires fresh input and mempool validation by all four owned nodes.
Signed bytes are broadcastable: keep them in the private journal, never the UI.
"""
from __future__ import annotations

import hashlib
import re

try:
    from . import protocol
    from .payment_conflicts import validate_transaction
except ImportError:
    import protocol
    from payment_conflicts import validate_transaction
from test_framework.messages import CTransaction, from_hex
from test_framework.segwit_addr import decode_segwit_address, encode_segwit_address

MAX_SIGNED_HEX = 262144
MAX_MONEY = 21_000_000 * 100_000_000
FEE = 100_000


def _amount(value):
    if type(value) is not str or re.fullmatch(r"(?:0|[1-9][0-9]{0,7})\.[0-9]{8}", value) is None:
        raise ValueError("Invalid saved payment amount")
    whole, fraction = value.split(".")
    result = int(whole) * 100_000_000 + int(fraction)
    if not 0 < result <= MAX_MONEY:
        raise ValueError("Invalid saved payment amount")
    return result


def _script(value):
    if type(value) is not str or re.fullmatch(r"5220[0-9a-f]{64}", value) is None:
        raise ValueError("Invalid saved input script")
    return bytes.fromhex(value)


def validate_resume_record(record: dict, own_script: bytes | None = None) -> CTransaction:
    """Validate immutable outbox fields; status eligibility is a separate check."""
    try:
        if type(record) is not dict or record.get("kind") not in {"send", "funding"}:
            raise ValueError
        raw = record.get("signed_transaction")
        if (type(raw) is not str or not 2 <= len(raw) <= MAX_SIGNED_HEX or len(raw) % 2
                or re.fullmatch(r"[0-9a-f]+", raw) is None):
            raise ValueError
        unsigned = validate_transaction(record.get("transaction"), record.get("txid"))
        signed = from_hex(CTransaction(), raw)
        if (signed.serialize_with_witness().hex() != raw
                or signed.serialize_without_witness() != unsigned.serialize_without_witness()
                or signed.txid_hex != record["txid"] or len(signed.wit.vtxinwit) != len(signed.vin)
                or any(txin.scriptSig for txin in signed.vin)
                or not 1 <= len(signed.vout) <= 2):
            raise ValueError
        previous = record.get("spent_outputs")
        if type(previous) is not list or len(previous) != len(signed.vin):
            raise ValueError
        scripts, values = [], []
        tag = hashlib.sha256(b"QLU/key-commitment/v1").digest()
        for output, witness in zip(previous, signed.wit.vtxinwit, strict=True):
            if (type(output) is not dict or set(output) != {"value", "script"}
                    or type(output["value"]) is not int or not 0 < output["value"] <= MAX_MONEY):
                raise ValueError
            script = _script(output["script"])
            stack = witness.scriptWitness.stack
            if len(stack) != 4 or tuple(map(len, stack)) != (1952, 32, 3309, 64):
                raise ValueError
            if hashlib.sha256(tag + tag + b"\x01" + stack[0] + stack[1]).digest() != script[2:]:
                raise ValueError
            scripts.append(script)
            values.append(output["value"])
        if len(set(scripts)) != 1 or sum(values) > MAX_MONEY:
            raise ValueError
        recipient = record.get("recipient")
        if type(recipient) is not str or not 8 <= len(recipient) <= 90:
            raise ValueError
        version, program = decode_segwit_address("qlud", recipient)
        if (version != 2 or program is None or len(program) != 32
                or encode_segwit_address("qlud", 2, program) != recipient):
            raise ValueError
        target = b"\x52\x20" + bytes(program)
        if (signed.vout[0].scriptPubKey != target or signed.vout[0].nValue != _amount(record.get("amount"))
                or _amount(record.get("fee")) != FEE
                or sum(values) - sum(out.nValue for out in signed.vout) != FEE
                or (len(signed.vout) == 2 and (signed.vout[1].scriptPubKey != scripts[0]
                                              or signed.vout[1].nValue <= 0))):
            raise ValueError
        if own_script is not None:
            if type(own_script) is not bytes or _script(own_script.hex()) != own_script:
                raise ValueError
            if (record["kind"] == "send" and scripts[0] != own_script
                    or record["kind"] == "funding" and target != own_script):
                raise ValueError
        return signed
    except Exception:
        raise ValueError("Invalid saved payment outbox") from None


def locally_resumable(record: dict) -> bool:
    """Local eligibility only; never authorizes a broadcast without live checks."""
    if (type(record) is not dict or record.get("status") != "pending"
            or "block" in record or "conflict" in record):
        return False
    try:
        validate_resume_record(record)
        return True
    except ValueError:
        return False
