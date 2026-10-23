#!/usr/bin/env python3
"""Deliberately regenerate PUBLIC SYNTHETIC payment vectors with valueless keys.

Never pass actual wallet seeds or files here. The seed is fixed public text below.
Native randomized signatures change on regeneration; reference signatures do not.
Inspect and review fixture changes before accepting them as new expected values.
"""
from __future__ import annotations

import argparse
import hashlib
import json

import conformance_smoke as smoke
from conformance_smoke import protocol, recovery, reference
from test_framework.messages import CTransaction, CTxOut, from_hex


PUBLIC_SEED_LABEL = b"QLU PUBLIC SYNTHETIC conformance fixture v1 - NEVER USE FOR FUNDS"


def generate():
    seed = hashlib.sha256(PUBLIC_SEED_LABEL).digest()
    wallet = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
    wallet["master_seed"] = seed.hex()
    keys = smoke.compare_keys(wallet)
    script = reference.script_for(keys)
    unsigned = reference.unsigned_transaction(
        [("0123456789abcdef" * 4, 3, 0xfffffffe), ("fedcba9876543210" * 4, 7, 0xfffffffd)],
        [(299900000, script), (0, b"\x6a\x04QLU1")], locktime=42)
    tx = from_hex(CTransaction(), unsigned.hex())
    spent = [CTxOut(100000000, script), CTxOut(200000000, script)]
    native_signed = protocol.sign_transaction(wallet, tx, spent)
    reference_signed = smoke.independent_sign(wallet, tx, spent)
    digests = smoke.verify_independently(native_signed, spent, keys)
    smoke.verify_independently(reference_signed, spent, keys)
    return {"format": "qlu-public-synthetic-conformance-v1", "public_synthetic": True,
            "warning": "PUBLIC SYNTHETIC KEY. Never send funds to this address or use this seed for a wallet.",
            "seed_derivation": "SHA256 of the ASCII public_seed_label; no random/private wallet material",
            "public_seed_label": PUBLIC_SEED_LABEL.decode("ascii"), "public_synthetic_master_seed": seed.hex(),
            "network": protocol.NETWORK, "genesis": protocol.GENESIS,
            "keys": {name: keys[name] for name in smoke.KEY_FIELDS},
            "address": reference.address_for(keys), "script": script.hex(), "transaction": unsigned.hex(),
            "spent": [{"sats": output.nValue, "script": output.scriptPubKey.hex()} for output in spent],
            "digests": [digest.hex() for digest in digests],
            "native_signed_transaction": native_signed.serialize_with_witness().hex(),
            "reference_signed_transaction": reference_signed.serialize_with_witness().hex(),
            "native_signing": "OpenSSL ML-DSA-65 randomized; libsecp256k1 BIP340 fresh auxiliary randomness",
            "reference_signing": "dilithium-py 1.5.1 deterministic ML-DSA-65; BIP340 Python reference, zero auxiliary randomness",
            "regeneration": "qlu/generate_conformance_vectors.py --write-public-synthetic-vectors"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-public-synthetic-vectors", action="store_true", required=True)
    parser.parse_args()
    document = generate()
    # This file deliberately contains public seed material, not a secret or wallet.
    smoke.VECTORS.write_text(json.dumps(document, indent=2) + "\n")
    smoke.check_public_vectors(native=True)
    print("Regenerated and cross-checked PUBLIC SYNTHETIC conformance vectors.")
