"""QLU private-prototype transaction tooling, not a consumer wallet.

Uses the pinned upstream Python test serializer; all authorization is checked again
by nodes. Secrets reach the native key tool only over stdin, never RPC or argv.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/functional"))
from test_framework.messages import CTransaction, CTxInWitness, CTxOut, ser_compact_size
from test_framework.segwit_addr import encode_segwit_address

GENESIS = "6267316c0eead38376d28b505d23c779e9f053e6fde5369572f855bfe9d684e5"
NETWORK = "qludev"


def keytool(wallet: dict, digest: bytes | None = None) -> dict:
    from recovery import validate_wallet
    wallet = validate_wallet(wallet)
    if wallet.get("network_id") != NETWORK or wallet.get("genesis_hash") != GENESIS:
        raise ValueError("Wallet belongs to another network")
    request = {"action": "public" if digest is None else "sign", "seed": wallet["master_seed"]}
    if digest is not None:
        request["digest"] = digest.hex()
    result = subprocess.run([str(ROOT / "build/qlu-foundation/bin/qlu-keytool")],
                            input=json.dumps(request), capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError("QLU key operation failed")
    return json.loads(result.stdout)


def script_for(keys: dict) -> bytes:
    commitment = bytes.fromhex(keys["key_commitment"])
    if len(commitment) != 32:
        raise ValueError("Invalid key commitment")
    return b"\x52\x20" + commitment


def address_for(keys: dict) -> str:
    return encode_segwit_address("qlud", 2, bytes.fromhex(keys["key_commitment"]))


def authorization_digest(tx: CTransaction, spent: list[CTxOut], index: int,
                         genesis: str = GENESIS) -> bytes:
    if len(spent) != len(tx.vin) or not 0 <= index < len(tx.vin):
        raise ValueError("Authorization input mismatch")
    tag = hashlib.sha256(b"QLU/tx-auth/v1").digest()
    message = (bytes.fromhex(genesis)[::-1] + (1).to_bytes(4, "little") + index.to_bytes(4, "little")
               + tx.serialize_without_witness() + ser_compact_size(len(spent))
               + b"".join(out.serialize() for out in spent))
    return hashlib.sha256(tag + tag + message).digest()


def sign_transaction(wallet: dict, tx: CTransaction, spent: list[CTxOut], *,
                     digest_genesis: str = GENESIS) -> CTransaction:
    """Sign known own inputs; digest_genesis override exists only for replay-rejection experiments."""
    keys = keytool(wallet)
    own_script = script_for(keys)
    if len(spent) != len(tx.vin) or any(out.scriptPubKey != own_script for out in spent):
        raise ValueError("Every input must belong to this prototype wallet")
    if tx.version != 2 or not 1 <= len(tx.vin) <= 16 or not 1 <= len(tx.vout) <= 32:
        raise ValueError("Unsupported transaction shape")
    if any(out.nValue < 0 for out in spent + tx.vout) or sum(out.nValue for out in tx.vout) > sum(out.nValue for out in spent):
        raise ValueError("Invalid transaction amounts")
    result = CTransaction(tx)
    result.wit.vtxinwit = []
    for index in range(len(tx.vin)):
        signed = keytool(wallet, authorization_digest(tx, spent, index, digest_genesis))
        witness = CTxInWitness()
        witness.scriptWitness.stack = [bytes.fromhex(signed[name]) for name in
                                      ("mldsa_public", "schnorr_public", "mldsa_signature", "schnorr_signature")]
        result.wit.vtxinwit.append(witness)
    return result
