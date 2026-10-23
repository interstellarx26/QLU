# Independent private-payment conformance checks

This milestone checks the existing QLU private hybrid v1 rules against separate
implementations. It does not change consensus, wallet custody, mining, issuance
or public-network access. The reference code is test tooling only and must never
be used to hold or sign real-value funds.

## Independence boundary

The node and native key helper use OpenSSL ML-DSA-65 and libsecp256k1 BIP340.
The new test reference uses `dilithium-py` for ML-DSA and the BIP340 project's
Python reference for Schnorr. The former is educational, not constant-time or
production custody software. Both are pinned with provenance and file hashes.
The reference does not import QLU's transaction digest, key derivation or the
upstream Python transaction/address serializers. It independently implements
the documented byte encodings, HMAC labels, commitment and Bech32m address.
SHA-256/HMAC/SHAKE remain standard-library primitives; this is not independent
hardware, an independent protocol specification or an independent security audit.

QLU uses **pure ML-DSA-65** on the 32-byte QLU authorization digest, with context
`QLU/hybrid/v1`. This is not HashML-DSA. Both ML-DSA and BIP340 are required.
Deterministic reference signing is permitted only for public synthetic test
vectors and disposable private-network fixtures. The application's randomized
signing path stays unchanged.

## Acceptance contract

1. Check pinned primitive reference cases and vendor integrity before trusting
   cross-implementation results. A missing or changed test dependency must fail,
   not silently skip this milestone.
2. Retain portable, explicitly public synthetic cases with expected derived
   public keys, commitment, address, canonical unsigned bytes, input-specific
   authorization digests and signed witness bytes. Compare fixed expected bytes
   with both reference calculations and existing QLU tooling. Include multiple
   inputs so every spent output and each signing input index are checked.
3. Verify newly generated QLU signatures with the separate reference. Verify
   independently generated signatures through actual QLU node consensus using
   disposable mature outputs. Both directions must pass; a reference self-test
   alone cannot satisfy this requirement.
4. Require rejection of altered recipients, values, spent-value fee information,
   wrong genesis or signature context, and missing or corrupt signature
   components. Demonstrate that rejecting a bad witness does not prevent the
   valid transaction with the same transaction ID from confirming.
5. Run the fixed corpus and focused negative tests in the existing Mac and Linux
   automated jobs. Run the live experiment with four owned localhost `qludev`
   nodes, verify the accepted payment on every node and retain exact-revision
   results. A Linux CI pass is not a physical-device recovery acceptance test.

## Laboratory safety and evidence

Only fresh disposable data directories under ignored `.local/` are used. The
shared private-port lock, exact localhost settings, genesis checks and owned
process controls remain in force. Existing wallets, backups and node data are
not used by the drill or modified. Separate preservation checks compare file
hashes without opening a wallet or using its keys. Public corpus seeds are
conspicuously marked as test-only;
live synthetic seeds stay in memory or bounded helper stdin. No RPC receives
private seeds. Failure reports must not echo secret inputs or backend diagnostics.

The run retains source, binary, dependency and corpus fingerprints, pass/failure
phase and cleanup status. Execution and RPC waits are bounded. Only fixture-owned
processes are stopped, including after failure; success requires cleanup and
unchanged fingerprints. Failures are preserved and investigated, not omitted.

## Running the checks

Build the existing QLU binaries with `qlu/build.py` as described in
[the foundation guide](FOUNDATION.md). In the isolated test environment, install
both hash-pinned requirement files; the reference package is not a dependency
of the wallet app or its recovery export packages:

```sh
.local/recovery-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r qlu/recovery-requirements.txt
.local/recovery-venv/bin/python -m pip install --require-hashes --only-binary=:all: --no-deps -r qlu/conformance-requirements.txt
.local/recovery-venv/bin/python -m unittest discover -s qlu/tests -v
.local/recovery-venv/bin/python qlu/conformance_smoke.py
```

The live check needs the laboratory ports free. It uses fresh wallets and a fresh
four-node directory, then stops its owned nodes. Reports stay in ignored
`.local/evidence/conformance-<attempt>.json`; a public summary in the test log
contains results and fingerprints, without wallet seeds or RPC credentials.

`qlu/conformance_vectors.json` contains deliberately **public synthetic** seed
material and signatures. Normal tests only read it. The separate
`qlu/generate_conformance_vectors.py --write-public-synthetic-vectors` command
deliberately replaces it and requires review: regeneration is not a way to
repair a failing expected value. Native signatures use randomness, so regenerating
the corpus changes those bytes. Exact external revisions, original source hashes,
extraction details and licenses are in `qlu/conformance_vendor/provenance.json`
and its adjacent files.

## Limits

This is bounded interoperability and regression evidence. Two implementations
can share a specification mistake, and reference implementations can have bugs.
These checks do not prove absence of side channels, safe custody on compromised
devices, hostile-network endurance, Windows/phone support, production economics
or production readiness. Specialist cryptography review and the remaining
[release gates](RECOVERY_RELEASE_GATE.md) still apply.

Sources: [QLU's accepted private rules](QLU_PRIVATE_V1.md),
[NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
[dilithium-py](https://github.com/GiacomoPope/dilithium-py),
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
Exact vendored revision and release information accompany the test sources.

The pinned primitive corpus contains all 19 BIP340 reference vectors and five
extracted NIST ACVP ML-DSA-65 cases: one key-generation case, one deterministic
external pure/context signature-generation case and three verification cases
(two reject, one accept). The reference checks all 20 installed package Python
files against the pinned wheel's source hashes and requires its documented
standard-library SHAKE backend. Optional accelerated backends are outside this
experiment. These integrity and primitive checks run before the live drill,
as well as in the unit suite.
