"""Independent, TEST-ONLY interpretation of docs/QLU_PRIVATE_V1.md.

Never use this module with actual wallet seeds. The pure Python implementations
are not constant time and deterministic signing here exists for public, disposable
test vectors only. No production protocol helper, serializer, signer, OpenSSL
ML-DSA implementation, libsecp256k1, or node RPC is imported by this module.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
from importlib.metadata import version
import json
from pathlib import Path
import struct

import dilithium_py
from dilithium_py.ml_dsa import ML_DSA_65, ml_dsa as ml_dsa_module
from dilithium_py.polynomials import polynomials as polynomial_module
from dilithium_py.shake import shake_wrapper
from conformance_vendor import bip340_reference as bip340

if version("dilithium-py") != "1.5.1":
    raise RuntimeError("Install the exact hashed conformance-requirements.txt dependency")


def _check_backend() -> None:
    # Upstream can optionally select xoflib. This experiment only supports the
    # pinned wrapper using stdlib hashlib SHAKE; it is not an independent hash
    # primitive implementation, although its ML-DSA arithmetic is independent.
    if (ml_dsa_module.shake256 is not shake_wrapper.shake256
            or polynomial_module.shake128 is not shake_wrapper.shake128
            or polynomial_module.shake256 is not shake_wrapper.shake256):
        raise RuntimeError("Unexpected independent reference SHAKE backend")


_check_backend()

GENESIS = "6267316c0eead38376d28b505d23c779e9f053e6fde5369572f855bfe9d684e5"
CONTEXT = b"QLU/hybrid/v1"
MAX_MONEY = 21_000_000 * 100_000_000  # Inherited lab validity bound, not adopted tokenomics.
MAX_UNSIGNED_BYTES = 4096


def _bytes(value: bytes, length: int | None = None) -> bytes:
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        raise ValueError("Invalid byte field")
    return value


def _integer(value: int, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Invalid integer field")
    return value


def _hex(value: str, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != 2 * length:
        raise ValueError("Invalid hex field")
    result = bytes.fromhex(value)
    return _bytes(result, length)


def tagged_hash(tag: bytes, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(_bytes(tag)).digest()
    return hashlib.sha256(tag_hash + tag_hash + _bytes(message)).digest()


def compact_size(value: int) -> bytes:
    value = _integer(value, 0xffffffffffffffff)
    if value < 253:
        return bytes([value])
    if value <= 0xffff:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


class _Reader:
    def __init__(self, data: bytes):
        self.data = _bytes(data)
        self.offset = 0

    def read(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise ValueError("Truncated transaction")
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def integer(self, length: int, *, signed: bool = False) -> int:
        return int.from_bytes(self.read(length), "little", signed=signed)

    def size(self, maximum: int) -> int:
        marker = self.integer(1)
        if marker < 253:
            value = marker
        else:
            length = {253: 2, 254: 4, 255: 8}[marker]
            value = self.integer(length)
            if value < {253: 253, 254: 0x10000, 255: 0x100000000}[marker]:
                raise ValueError("Noncanonical CompactSize")
        if value > maximum:
            raise ValueError("Oversized transaction field")
        return value


def _output(value: int, script: bytes, *, spent: bool = False) -> bytes:
    _integer(value, MAX_MONEY)
    _bytes(script)
    hybrid = len(script) == 34 and script[:2] == b"\x52\x20"
    metadata = not spent and value == 0 and 1 <= len(script) <= 83 and script[0] == 0x6a
    if not hybrid and not metadata:
        raise ValueError("Unsupported QLU output")
    return struct.pack("<q", value) + compact_size(len(script)) + script


def unsigned_transaction(inputs: list[tuple[str, int, int]],
                         outputs: list[tuple[int, bytes]], version: int = 2,
                         locktime: int = 0) -> bytes:
    """Encode a bounded non-coinbase QLU v1 transaction without witness.

    Inputs are (display-order txid, output index, sequence); outputs are
    (integer amount, script bytes). Deliberately rejects unsupported forms.
    """
    if type(version) is not int or version != 2 or not 1 <= len(inputs) <= 16 or not 1 <= len(outputs) <= 32:
        raise ValueError("Unsupported QLU transaction shape")
    result = struct.pack("<i", version) + compact_size(len(inputs))
    seen = set()
    for txid, index, sequence in inputs:
        outpoint = _hex(txid, 32)[::-1] + struct.pack("<I", _integer(index, 0xffffffff))
        if outpoint in seen or outpoint == bytes(32) + b"\xff" * 4:
            raise ValueError("Repeated or null outpoint")
        seen.add(outpoint)
        result += outpoint + b"\x00" + struct.pack("<I", _integer(sequence, 0xffffffff))
    result += compact_size(len(outputs))
    total = 0
    for amount, script in outputs:
        result += _output(amount, script)
        total += amount
        _integer(total, MAX_MONEY)
    return result + struct.pack("<I", _integer(locktime, 0xffffffff))


def parse_transaction(unsigned: bytes) -> dict:
    """Strict canonical parser, independent of Bitcoin's Python test framework."""
    if len(_bytes(unsigned)) > MAX_UNSIGNED_BYTES:
        raise ValueError("Oversized unsigned transaction")
    reader = _Reader(unsigned)
    version_number = reader.integer(4, signed=True)
    inputs = []
    for _ in range(reader.size(16)):
        txid = reader.read(32)[::-1].hex()
        index = reader.integer(4)
        if reader.size(0) != 0:
            raise ValueError("Nonempty scriptSig")
        inputs.append((txid, index, reader.integer(4)))
    outputs = []
    for _ in range(reader.size(32)):
        amount = reader.integer(8, signed=True)
        script = reader.read(reader.size(83))
        outputs.append((amount, script))
    locktime = reader.integer(4)
    if reader.offset != len(unsigned):
        raise ValueError("Trailing transaction data")
    if unsigned_transaction(inputs, outputs, version_number, locktime) != unsigned:
        raise ValueError("Noncanonical transaction")
    return {"version": version_number, "inputs": inputs, "outputs": outputs, "locktime": locktime}


def authorization_digest(unsigned: bytes, spent: list[tuple[int, bytes]], index: int,
                         genesis: str = GENESIS) -> bytes:
    tx = parse_transaction(unsigned)
    if len(spent) != len(tx["inputs"]):
        raise ValueError("Authorization input mismatch")
    _integer(index, len(spent) - 1)
    encoded_spent = b"".join(_output(value, script, spent=True) for value, script in spent)
    total = sum(value for value, _ in spent)
    _integer(total, MAX_MONEY)
    if sum(value for value, _ in tx["outputs"]) > total:
        raise ValueError("Outputs exceed spent inputs")
    message = (_hex(genesis, 32)[::-1] + struct.pack("<II", 1, index) + unsigned
               + compact_size(len(spent)) + encoded_spent)
    return tagged_hash(b"QLU/tx-auth/v1", message)


def _private_keys(seed: bytes) -> tuple[bytes, bytes, bytes]:
    _bytes(seed, 32)
    ml_seed = hmac.digest(seed, b"QLU/ML-DSA-65/seed/v1", "sha256")
    public, private = ML_DSA_65.key_derive(ml_seed)
    for counter in range(0x100000000):
        schnorr = hmac.digest(seed, b"QLU/BIP340/secret/v1" + struct.pack(">I", counter), "sha256")
        if 1 <= int.from_bytes(schnorr, "big") < bip340.n:
            return public, private, schnorr
    raise ValueError("Schnorr derivation exhausted")


def _public_keys(ml_public: bytes, schnorr_secret: bytes) -> dict:
    schnorr_public = bip340.pubkey_gen(schnorr_secret)
    commitment = tagged_hash(b"QLU/key-commitment/v1", b"\x01" + ml_public + schnorr_public)
    return {"mldsa_public": ml_public.hex(), "schnorr_public": schnorr_public.hex(),
            "key_commitment": commitment.hex()}


def derive_keys(seed: bytes) -> dict:
    public, _, schnorr = _private_keys(seed)
    return _public_keys(public, schnorr)


def script_for(keys: dict) -> bytes:
    return b"\x52\x20" + _hex(keys["key_commitment"], 32)


def address_for(keys: dict) -> str:
    """Bech32m, independently implemented from BIP350, fixed qlud witness v2."""
    program = _hex(keys["key_commitment"], 32)
    words = [2]
    accumulator = bits = 0
    for byte in program:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((accumulator >> bits) & 31)
    if bits:
        words.append((accumulator << (5 - bits)) & 31)
    hrp = "qlud"
    values = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp] + words
    checksum = 1
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    for value in values + [0] * 6:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                checksum ^= generator
    checksum ^= 0x2bc830a3
    words += [(checksum >> (5 * (5 - i))) & 31 for i in range(6)]
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join(alphabet[word] for word in words)


def sign(seed: bytes, digest: bytes, context: bytes = CONTEXT) -> dict:
    """Deterministic signatures for public vectors or disposable valueless tests.

    Never use real wallet keys: this reference is not constant time.
    """
    _bytes(digest, 32)
    if len(_bytes(context)) > 255:
        raise ValueError("Invalid ML-DSA context")
    public, private, schnorr = _private_keys(seed)
    result = _public_keys(public, schnorr)
    result["mldsa_signature"] = ML_DSA_65.sign(private, digest, ctx=context, deterministic=True).hex()
    result["schnorr_signature"] = bip340.schnorr_sign(digest, schnorr, bytes(32)).hex()
    return result


def verify(keys: dict, digest: bytes, mldsa_signature: bytes, schnorr_signature: bytes,
           context: bytes = CONTEXT) -> bool:
    try:
        _bytes(digest, 32)
        _bytes(mldsa_signature, 3309)
        _bytes(schnorr_signature, 64)
        if len(_bytes(context)) > 255:
            return False
        public = _hex(keys["mldsa_public"], 1952)
        schnorr = _hex(keys["schnorr_public"], 32)
        commitment = tagged_hash(b"QLU/key-commitment/v1", b"\x01" + public + schnorr)
        if not hmac.compare_digest(commitment, _hex(keys["key_commitment"], 32)):
            return False
        return bool(ML_DSA_65.verify(public, digest, mldsa_signature, ctx=context)
                    and bip340.schnorr_verify(digest, schnorr, schnorr_signature))
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def encode_witness(unsigned: bytes, witnesses: list[list[bytes]]) -> bytes:
    """Attach exactly four fixed-sized hybrid items to each validated input."""
    tx = parse_transaction(unsigned)
    if len(witnesses) != len(tx["inputs"]):
        raise ValueError("Witness count mismatch")
    encoded = b""
    for stack in witnesses:
        if len(stack) != 4:
            raise ValueError("Witness item count mismatch")
        encoded += b"\x04"
        for item, length in zip(stack, (1952, 32, 3309, 64), strict=True):
            encoded += compact_size(length) + _bytes(item, length)
    return unsigned[:4] + b"\x00\x01" + unsigned[4:-4] + encoded + unsigned[-4:]


def self_test() -> dict:
    """Fail closed on altered dependencies or external known-answer mismatches.

    The standalone node drill calls this before starting any private nodes. Hashes
    describe the pinned wheel and vendored source; they are not an audit or a claim
    that a compromised interpreter can attest to its own integrity.
    """
    vendor = Path(__file__).resolve().parent / "conformance_vendor"
    provenance = json.loads((vendor / "provenance.json").read_text())
    _check_backend()

    def require(condition: bool) -> None:
        if not condition:
            raise RuntimeError("Independent reference integrity or known-answer check failed")

    expected_vendor = {"bip340_reference.py", "bip340_test_vectors.csv", "bip340.LICENSE",
                       "dilithium_py.LICENSE", "nist.LICENSE", "nist_mldsa65_subset.json"}
    require(set(provenance["vendored_sha256"]) == expected_vendor)
    for filename, expected in provenance["vendored_sha256"].items():
        require(hashlib.sha256((vendor / filename).read_bytes()).hexdigest() == expected)
    require(not bip340.DEBUG)
    package = Path(dilithium_py.__file__).resolve().parent
    installed_hashes = {"dilithium_py/" + file.relative_to(package).as_posix():
                        hashlib.sha256(file.read_bytes()).hexdigest() for file in package.rglob("*.py")}
    require(installed_hashes == provenance["dilithium_py"]["package_python_sha256"])
    require(version("dilithium-py") == provenance["dilithium_py"]["release"] == "1.5.1")

    with (vendor / "bip340_test_vectors.csv").open(newline="") as stream:
        vectors = list(csv.DictReader(stream))
    require([int(row["index"]) for row in vectors] == list(range(19)))
    for row in vectors:
        public, message, signature = (bytes.fromhex(row[key]) for key in ("public key", "message", "signature"))
        require(bip340.schnorr_verify(message, public, signature) == (row["verification result"] == "TRUE"))
        if row["secret key"]:
            secret, auxiliary = bytes.fromhex(row["secret key"]), bytes.fromhex(row["aux_rand"])
            require(bip340.pubkey_gen(secret) == public)
            require(bip340.schnorr_sign(message, secret, auxiliary) == signature)

    nist = json.loads((vendor / "nist_mldsa65_subset.json").read_text())
    require([row["tcId"] for row in nist["keygen"]] == [26])
    require([row["tcId"] for row in nist["siggen"]] == [31])
    require([row["tcId"] for row in nist["sigver"]] == [31, 32, 33])
    for row in nist["keygen"]:
        public, _ = ML_DSA_65.key_derive(bytes.fromhex(row["seed"]))
        require(public == bytes.fromhex(row["pk"]))
    for row in nist["siggen"]:
        require((row["parameterSet"], row["signatureInterface"], row["preHash"], row["deterministic"])
                == ("ML-DSA-65", "external", "pure", True))
        private, message, context = (bytes.fromhex(row[key]) for key in ("sk", "message", "context"))
        require(ML_DSA_65.sign(private, message, ctx=context, deterministic=True) == bytes.fromhex(row["signature"]))
    for row in nist["sigver"]:
        require((row["parameterSet"], row["signatureInterface"], row["preHash"]) == ("ML-DSA-65", "external", "pure"))
        public, message, signature, context = (bytes.fromhex(row[key]) for key in ("pk", "message", "signature", "context"))
        require(ML_DSA_65.verify(public, message, signature, ctx=context) == row["testPassed"])
    return {"bip340_vectors": len(vectors), "nist_mldsa65_keygen_vectors": len(nist["keygen"]),
            "nist_mldsa65_sign_vectors": len(nist["siggen"]), "nist_mldsa65_verify_vectors": len(nist["sigver"]),
            "mldsa_implementation": "dilithium-py", "mldsa_version": version("dilithium-py"),
            "shake_backend": "dilithium_py.shake.shake_wrapper using stdlib hashlib",
            "vendored_sha256": provenance["vendored_sha256"], "installed_python_sha256": installed_hashes}
