#!/usr/bin/env python3
"""Independent, test-only hybrid payment conformance on disposable localhost nodes.

The reference has separate serialization, ML-DSA and Schnorr implementations.
The node controller, lifecycle and Bitcoin test block builder are shared tooling;
they are not themselves an independent full-node implementation.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devnet import DevnetError, RpcError, secure_directory, write_private
from lab import private_port_lock
from private_net import QLUPrivateNet
from payment_workload import fixture_size, failure_summary, wait_mempools, sats
import conformance_reference as reference
import protocol
import recovery
from test_framework.messages import CBlock, COutPoint, CTransaction, CTxIn, CTxOut, from_hex
from test_framework.blocktools import add_witness_commitment

MAX_WORK_SECONDS = 600
KEY_FIELDS = ("mldsa_public", "schnorr_public", "key_commitment")
WITNESS_FIELDS = ("mldsa_public", "schnorr_public", "mldsa_signature", "schnorr_signature")
VECTORS = Path(__file__).with_name("conformance_vectors.json")
SOURCES = ("conformance_smoke.py", "conformance_reference.py", "conformance_vectors.json",
           "conformance-requirements.txt", "protocol.py", "recovery.py", "private_net.py",
           "devnet.py", "lab.py", "payment_workload.py")
VENDOR_FILES = ("bip340_reference.py", "bip340_test_vectors.csv", "bip340.LICENSE",
                "dilithium_py.LICENSE", "nist_mldsa65_subset.json", "nist.LICENSE", "provenance.json")


def require(condition, message):
    if not condition:
        raise DevnetError(message)


def fingerprints():
    paths = [Path("qlu") / name for name in SOURCES]
    paths += [Path("qlu/conformance_vendor") / name for name in VENDOR_FILES]
    paths += [Path("test/functional/test_framework/messages.py"), Path("test/functional/test_framework/blocktools.py"),
              Path("test/functional/test_framework/segwit_addr.py")]
    return {"sources": {str(path): hashlib.sha256((protocol.ROOT / path).read_bytes()).hexdigest() for path in paths},
            "installed_dilithium_py": dependency_fingerprints(),
            "binaries": {name: hashlib.sha256((protocol.ROOT / "build/qlu-foundation/bin" / name).read_bytes()).hexdigest()
                         for name in ("bitcoind", "bitcoin-cli", "qlu-keytool")}}


def dependency_fingerprints():
    """Record the installed implementation bytes, in addition to the pinned wheel/version."""
    distribution = importlib.metadata.distribution("dilithium-py")
    require(distribution.version == "1.5.1", "Unexpected conformance dependency version")
    files = [path for path in (distribution.files or ())
             if str(path).startswith("dilithium_py/") and str(path).endswith(".py")]
    require(0 < len(files) <= 64, "Missing or oversized conformance dependency inventory")
    result = {}
    for path in files:
        require(".." not in Path(path).parts, "Invalid conformance dependency path")
        location = distribution.locate_file(path)
        require(location.stat().st_size <= 1048576, "Oversized conformance dependency file")
        result[str(path)] = hashlib.sha256(location.read_bytes()).hexdigest()
    return result


class ConformanceNet(QLUPrivateNet):
    process_label = "QLUConformance"

    def __init__(self, root, identifier):
        require(type(identifier) is str and re.fullmatch(r"[0-9a-f]{32}", identifier) is not None,
                "Invalid conformance identifier")
        self.data_name = "conformance-" + identifier
        super().__init__(root)
        require(not self.data.exists() and not self.data.is_symlink(), "Conformance requires a fresh directory")
        self.work_deadline = None

    def check_deadline(self):
        require(self.work_deadline is None or time.monotonic() < self.work_deadline, "Conformance time budget exceeded")

    def rpc(self, index, method, *params, **kwargs):
        self.check_deadline()
        result = super().rpc(index, method, *params, **kwargs)
        self.check_deadline()
        return result


def independent_unsigned(tx):
    """Re-encode structured fields without the production/test transaction serializer."""
    inputs = [(f"{item.prevout.hash:064x}", item.prevout.n, item.nSequence) for item in tx.vin]
    outputs = [(item.nValue, bytes(item.scriptPubKey)) for item in tx.vout]
    result = reference.unsigned_transaction(inputs, outputs, version=tx.version, locktime=tx.nLockTime)
    require(result == tx.serialize_without_witness(), "Independent transaction encoding disagrees")
    return result


def independent_digests(tx, spent, genesis=protocol.GENESIS):
    unsigned = independent_unsigned(tx)
    previous = [(item.nValue, bytes(item.scriptPubKey)) for item in spent]
    result = [reference.authorization_digest(unsigned, previous, index, genesis) for index in range(len(tx.vin))]
    require(result == [protocol.authorization_digest(tx, spent, index, genesis) for index in range(len(tx.vin))],
            "Independent authorization encoding disagrees")
    return result


def compare_keys(wallet):
    keys = reference.derive_keys(bytes.fromhex(wallet["master_seed"]))
    native = protocol.keytool(wallet)
    require({key: keys[key] for key in KEY_FIELDS} == {key: native[key] for key in KEY_FIELDS},
            "Independent key derivation disagrees")
    require(reference.address_for(keys) == protocol.address_for(native), "Independent address encoding disagrees")
    return keys


def independent_sign(wallet, tx, spent, *, genesis=protocol.GENESIS, context=b"QLU/hybrid/v1", indices=None):
    digests = independent_digests(tx, spent, genesis)
    seed = bytes.fromhex(wallet["master_seed"])
    if indices is None:
        indices = range(len(tx.vin))
    require(len(indices) == len(tx.vin), "Independent signer input mismatch")
    witnesses = []
    for index in indices:
        signed = reference.sign(seed, digests[index], context)
        witnesses.append([bytes.fromhex(signed[name]) for name in WITNESS_FIELDS])
    raw = reference.encode_witness(independent_unsigned(tx), witnesses)
    result = from_hex(CTransaction(), raw.hex())
    require(result.serialize_with_witness() == raw, "Independent witness encoding disagrees")
    return result


def verify_independently(tx, spent, keys):
    digests = independent_digests(tx, spent)
    require(len(tx.wit.vtxinwit) == len(tx.vin), "Missing authorization")
    for index, witness in enumerate(tx.wit.vtxinwit):
        stack = witness.scriptWitness.stack
        require(len(stack) == 4 and stack[:2] == [bytes.fromhex(keys[name]) for name in KEY_FIELDS[:2]],
                "Unexpected signer keys")
        require(reference.verify(keys, digests[index], stack[2], stack[3], b"QLU/hybrid/v1"),
                "Independent signature verification failed")
    return digests


def reject_everywhere(net, tx, reason, candidate):
    """Require the intended rejection independently at admission and direct-block checks."""
    raw = tx.serialize_with_witness().hex()
    tips = [net.rpc(index, "getbestblockhash") for index in range(4)]
    mempools = [net.rpc(index, "getrawmempool") for index in range(4)]
    admission, blocks = [], []
    for index in range(4):
        result = net.rpc(index, "testmempoolaccept", [raw])
        require(len(result) == 1 and result[0].get("allowed") is False
                and result[0].get("reject-reason") == reason, "Unexpected conformance admission result")
        try:
            net.rpc(index, "sendrawtransaction", raw)
        except RpcError as error:
            require(error.code == -26 and reason in str(error), "Unexpected conformance broadcast result")
        else:
            raise DevnetError("Invalid conformance payment was broadcast")
        admission.append({"node": index, "reason": reason})
    block = from_hex(CBlock(), candidate)
    require(len(block.vtx) == 2, "Unexpected conformance block template")
    block.vtx[1] = CTransaction(tx)
    add_witness_commitment(block)
    block.hashMerkleRoot = block.calc_merkle_root()
    for index in range(4):
        # Distinct headers avoid a rejection propagated by peers hiding validation.
        block.nNonce += 1
        block.solve()
        result = net.rpc(index, "submitblock", block.serialize().hex())
        require(result == reason, "Unexpected conformance block rejection")
        blocks.append({"node": index, "reason": result, "block": block.hash_hex})
    require([net.rpc(index, "getbestblockhash") for index in range(4)] == tips,
            "Rejected conformance payment changed a tip")
    require([net.rpc(index, "getrawmempool") for index in range(4)] == mempools,
            "Rejected conformance payment changed a mempool")
    return {"txid": tx.txid_hex, "wtxid": tx.wtxid_hex, "admission": admission, "blocks": blocks}


def negative_cases(wallet, tx, spent, recipient_keys):
    """Each signature mutation preserves the underlying transaction identifier."""
    cases = []
    def add(name, changed, reason="qlu-hybrid-signature"):
        cases.append((name, changed, reason))
    changed = CTransaction(tx); changed.vout[0].nValue -= 1
    add("changed-output-amount", changed)
    changed = CTransaction(tx); changed.vout[0].scriptPubKey = spent[0].scriptPubKey
    add("changed-recipient", changed)
    for position, name in ((2, "mldsa"), (3, "schnorr")):
        changed = CTransaction(tx)
        sig = bytearray(changed.wit.vtxinwit[1].scriptWitness.stack[position]); sig[0] ^= 1
        changed.wit.vtxinwit[1].scriptWitness.stack[position] = bytes(sig)
        add("corrupt-" + name, changed)
        changed = CTransaction(tx); del changed.wit.vtxinwit[1].scriptWitness.stack[position]
        add("missing-" + name, changed, "qlu-witness-shape")
    for position, name in ((0, "mldsa"), (1, "schnorr")):
        changed = CTransaction(tx)
        changed.wit.vtxinwit[1].scriptWitness.stack[position] = bytes.fromhex(recipient_keys[KEY_FIELDS[position]])
        add("wrong-" + name + "-key", changed, "qlu-key-commitment")
    for index in range(len(spent)):
        changed_spent = [CTxOut(item.nValue, item.scriptPubKey) for item in spent]
        changed_spent[index].nValue += 1
        add(f"wrong-spent-amount-{index}", independent_sign(wallet, tx, changed_spent))
    changed_spent = [CTxOut(item.nValue, item.scriptPubKey) for item in spent]
    changed_spent[1].scriptPubKey = protocol.script_for(recipient_keys)
    add("wrong-spent-script", independent_sign(wallet, tx, changed_spent))
    add("wrong-network", independent_sign(wallet, tx, spent, genesis="00" * 32))
    add("wrong-mldsa-context", independent_sign(wallet, tx, spent, context=b"QLU/other/v1"))
    add("wrong-input-index", independent_sign(wallet, tx, spent, indices=list(reversed(range(len(spent))))))
    return cases


def confirm(net, signed, address):
    raw = signed.serialize_with_witness().hex()
    for index in range(4):
        result = net.rpc(index, "testmempoolaccept", [raw])
        require(len(result) == 1 and result[0].get("allowed") is True, "Valid independent payment was rejected")
    require(net.rpc(0, "sendrawtransaction", raw) == signed.txid_hex, "Conformance broadcast identifier changed")
    wait_mempools(net, {signed.txid_hex})
    blockhash = net.rpc(0, "generatetoaddress", 1, address)[0]
    net.wait_synced(blockhash)
    original = None
    for index in range(4):
        raw_block = net.rpc(index, "getblock", blockhash, 0)
        block = from_hex(CBlock(), raw_block)
        require(len(block.vtx) == 2 and block.vtx[1].serialize_with_witness().hex() == raw,
                "Confirmed independent transaction bytes changed")
        require(original is None or original == raw_block, "Conformance nodes stored different blocks")
        original = raw_block
        out = net.rpc(index, "gettxout", signed.txid_hex, 0)
        require(out is not None and out["confirmations"] == 1 and sats(out["value"]) == signed.vout[0].nValue
                and out["scriptPubKey"]["hex"] == signed.vout[0].scriptPubKey.hex(), "Conformance output mismatch")
        require(net.rpc(index, "getrawmempool") == [], "Conformance payment remained pending")
    return {"txid": signed.txid_hex, "wtxid": signed.wtxid_hex, "block": blockhash,
            "nodes": 4, "inputs": len(signed.vin), "serialized_bytes": len(bytes.fromhex(raw))}


def check_public_vectors(*, native=False):
    """Explicit PUBLIC SYNTHETIC seed material, never funded outside disposable tests."""
    document = json.loads(VECTORS.read_text())
    require(document["format"] == "qlu-public-synthetic-conformance-v1" and document["public_synthetic"] is True,
            "Unknown conformance vector format")
    require(document["genesis"] == protocol.GENESIS and document["network"] == protocol.NETWORK,
            "Conformance vectors have a different identity")
    seed = bytes.fromhex(document["public_synthetic_master_seed"])
    keys = reference.derive_keys(seed)
    require({name: keys[name] for name in KEY_FIELDS} == document["keys"], "Frozen independent keys changed")
    require(reference.address_for(keys) == document["address"] == protocol.address_for(keys), "Frozen address changed")
    require(protocol.script_for(keys).hex() == document["script"], "Frozen key commitment changed")
    if native:
        wallet = recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS)
        wallet["master_seed"] = seed.hex()
        native_keys = protocol.keytool(wallet)
        require({name: native_keys[name] for name in KEY_FIELDS} == document["keys"], "Native vector keys changed")
    tx = from_hex(CTransaction(), document["transaction"])
    spent = [CTxOut(row["sats"], bytes.fromhex(row["script"])) for row in document["spent"]]
    digests = independent_digests(tx, spent)
    require([digest.hex() for digest in digests] == document["digests"], "Frozen authorization digest changed")
    require(len(digests) == 2 and digests[0] != digests[1], "Vectors must exercise two distinct input indices")
    for signer in ("native", "reference"):
        signed = from_hex(CTransaction(), document[signer + "_signed_transaction"])
        require(signed.serialize_without_witness() == tx.serialize_without_witness(), "Frozen transaction was substituted")
        verify_independently(signed, spent, keys)
    return {"inputs": 2, "signers": ["native-openssl-libsecp256k1", "reference-dilithium-py-python-bip340"],
            "vectors_sha256": hashlib.sha256(VECTORS.read_bytes()).hexdigest(), "native_keys_checked": native}


def run():
    identifier = uuid.uuid4().hex
    net = ConformanceNet(protocol.ROOT, identifier)
    report = {"format": "qlu-independent-conformance-v1", "attempt": identifier, "passed": False, "phase": "setup",
              "network": protocol.NETWORK, "genesis": protocol.GENESIS, "checks": {}, "negative_cases": [], "payments": [],
              "started_at": datetime.now(timezone.utc).isoformat(), "cleanup": "not-started",
              "reference_dependency": {"dilithium-py": importlib.metadata.version("dilithium-py")},
              "host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
              "scope": "Independent test-only key/signature and transaction encoding checks, using shared lifecycle/block-construction tooling. Four same-host localhost nodes are not independent operators, an audited hybrid construction, or a production readiness claim.",
              "plan": {"funding_blocks": 102, "work_limit_seconds": MAX_WORK_SECONDS, "disk_sample_limit_bytes": 104857600}}
    evidence = protocol.ROOT / ".local/evidence"
    started, failure = False, None
    with private_port_lock(protocol.ROOT):
        secure_directory(evidence)
        def save():
            contents = json.dumps(report, indent=2) + "\n"
            write_private(evidence / f"conformance-{identifier}.json", contents)
            write_private(evidence / "conformance-latest.json", contents)
        try:
            net.setup(); net.require_binaries(); net.require_stopped()
            report["fingerprints_start"] = fingerprints()
            report["head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=protocol.ROOT, text=True, timeout=10).strip()
            net.work_deadline = time.monotonic() + MAX_WORK_SECONDS
            report["phase"] = "official-primitive-self-test"
            report["reference_self_test"] = reference.self_test()
            report["checks"]["official_primitive_vectors_and_vendor_provenance"] = True
            report["phase"] = "public-vectors"
            report["public_vectors"] = check_public_vectors(native=True)
            report["checks"]["frozen_public_vectors_both_signers_both_input_indices"] = True
            save()
            wallets = [recovery.generate_wallet(protocol.NETWORK, protocol.GENESIS) for _ in range(2)]
            keys = [compare_keys(wallet) for wallet in wallets]
            report["checks"]["fresh_key_derivation_commitment_and_address_agreement"] = True
            report["phase"] = "funding"
            started = True
            net.start()
            mining_address = reference.address_for(keys[0])
            hashes = net.rpc(0, "generatetoaddress", 102, mining_address)
            require(len(hashes) == 102 and len(set(hashes)) == 102, "Unexpected conformance funding blocks")
            net.wait_synced(hashes[-1]); fixture_size(net.data)
            tx, spent = CTransaction(), []
            for blockhash in hashes[:2]:
                coinbase = net.rpc(0, "getblock", blockhash, 2)["tx"][0]
                output = coinbase["vout"][0]
                script, amount = bytes.fromhex(output["scriptPubKey"]["hex"]), sats(output["value"])
                require(script == protocol.script_for(keys[0]), "Conformance input policy mismatch")
                tx.vin.append(CTxIn(COutPoint(int(coinbase["txid"], 16), 0), nSequence=0xffffffff))
                spent.append(CTxOut(amount, script))
            tx.vout = [CTxOut(sum(item.nValue for item in spent) - 100000, protocol.script_for(keys[1]))]
            report["phase"] = "native-signature-verification"
            native = protocol.sign_transaction(wallets[0], tx, spent)
            verify_independently(native, spent, keys[0])
            report["checks"]["native_openssl_and_libsecp_signatures_verified_independently"] = True
            signed = independent_sign(wallets[0], tx, spent)
            verify_independently(signed, spent, keys[0])
            candidate = net.rpc(0, "generateblock", mining_address, [signed.serialize_with_witness().hex()], False)["hex"]
            report["phase"] = "tampered-payment-rejections"
            for name, altered, reason in negative_cases(wallets[0], signed, spent, keys[1]):
                net.check_deadline(); fixture_size(net.data)
                observation = reject_everywhere(net, altered, reason, candidate)
                observation.update(name=name, expected_reason=reason, same_txid=altered.txid_hex == signed.txid_hex)
                report["negative_cases"].append(observation)
                save()
            report["checks"]["tampered_payments_rejected_by_all_four_admission_and_block_validators"] = True
            report["phase"] = "independent-payment-confirmation"
            report["payments"].append(confirm(net, signed, mining_address))
            report["checks"]["independent_two_input_payment_confirmed_after_invalid_same_txid_witnesses"] = True
            returned = CTransaction()
            returned.vin = [CTxIn(COutPoint(int(signed.txid_hex, 16), 0), nSequence=0xffffffff)]
            returned.vout = [CTxOut(signed.vout[0].nValue - 100000, protocol.script_for(keys[0]))]
            returned_spent = [CTxOut(signed.vout[0].nValue, signed.vout[0].scriptPubKey)]
            native_return = protocol.sign_transaction(wallets[1], returned, returned_spent)
            verify_independently(native_return, returned_spent, keys[1])
            report["phase"] = "native-return-payment"
            report["payments"].append(confirm(net, native_return, mining_address))
            report["checks"]["independently_verified_native_return_payment_confirmed"] = True
            report["fixture_bytes"] = fixture_size(net.data)
            report["passed"], report["phase"] = True, "complete"
        except BaseException as error:
            failure = error
            report["error_type"] = type(error).__name__
            report["error_location"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                        for frame in traceback.extract_tb(error.__traceback__)]
        finally:
            net.work_deadline = None
            try:
                if started:
                    net.stop()
                require(all(row["status"] == "stopped" for row in net.status()), "Conformance nodes remain active")
                report["cleanup"] = "owned-nodes-stopped"
                report["ports_free"] = {str(port): net.port_free(port) for port in (*range(28440, 28444), *range(28540, 28544))}
                require(all(report["ports_free"].values()), "Conformance ports remain occupied")
            except BaseException as error:
                failure = failure or error
                report["cleanup"], report["cleanup_error_type"] = "needs-attention", type(error).__name__
            try:
                report["fingerprints_end"] = fingerprints()
                require(report.get("fingerprints_start") == report["fingerprints_end"], "Conformance source or binaries changed")
            except BaseException as error:
                failure = failure or error
                report["integrity_error_type"] = type(error).__name__
            report["passed"] = report["passed"] and failure is None
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            try:
                save()
            except BaseException as error:
                failure = failure or error
                report["passed"], report["evidence_error_type"] = False, type(error).__name__
            if not report["passed"]:
                print(json.dumps(failure_summary(report), indent=2), flush=True)
    if failure is not None:
        raise DevnetError("Independent conformance failed; retained evidence records its phase") from None
    print(json.dumps({"passed": report["passed"], "phase": report["phase"], "attempt": identifier,
                      "checks": report["checks"], "negative_cases": len(report["negative_cases"]),
                      "nodes_per_admission_and_block_rejection": 4, "confirmed_payments": len(report["payments"]),
                      "reference_dependency": report["reference_dependency"], "public_vectors": report["public_vectors"],
                      "reference_self_test": report["reference_self_test"],
                      "fingerprints": report["fingerprints_end"], "cleanup": report["cleanup"],
                      "ports_free": report["ports_free"]}, indent=2))
    return report


if __name__ == "__main__":
    try:
        run()
    except Exception:
        print("Independent conformance failed; inspect its retained evidence.", file=sys.stderr)
        raise SystemExit(1)
