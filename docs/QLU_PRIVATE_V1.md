# QLU private v1 rules

Status: accepted direction implemented as an experimental private-network protocol. This is
not an audited protocol, public testnet, or live currency. Coins have no value. Freeze no
mainnet parameters from this experiment without benchmarks and independent security review.

## Decisions

- QLU is a separate chain and native coin. Its development, future public test, and future
  live networks must have different genesis blocks, wire identifiers, address prefixes,
  ports, and data directories. Only the development network exists here.
- Every spendable output requires **ML-DSA-65 AND BIP340 Schnorr**. Both signatures cover the
  same network-bound authorization. This is a QLU construction, not a NIST-certified hybrid.
- No legacy, Taproot key-path, unknown-version, or recovery bypass is permitted. Change and
  mining rewards obey exactly the same rules. Zero-valued provably unspendable metadata is allowed.
- Recovery recreates the same required keys from an encrypted portable backup and separate
  random offline code. VibexHQ has no master key, password reset, or on-chain override.
- A contact-based user interface is a later wallet layer. Contacts never replace key authorization.
- RandomX, production difficulty/rewards/supply, public testnet, and mainnet remain separate work.
  Bitcoin regtest's SHA-256 proof of work, 100-block coinbase maturity, and 150-block subsidy
  halving interval are deliberately temporary laboratory behavior. They are not QLU tokenomics.

## Development identity

| Field | Value |
| --- | --- |
| Selectors / reported chain | `-qludev`, `-chain=qludev` / `qludev` |
| Genesis hash (display order) | `6267316c0eead38376d28b505d23c779e9f053e6fde5369572f855bfe9d684e5` |
| Genesis Merkle root | `01b208e9ebe024eb7d5c37b7afaf455a8cd10343d609e6a382a36733fc7570bb` |
| Header time / nonce / bits / version | `1792368000` / `0` / `0x207fffff` / `1` |
| Genesis transaction | Version 2, one zero-value `OP_RETURN` output; no spendable allocation |
| Wire magic | `f1 dc d3 24` (first four SHA-256 bytes of ASCII `QLU private devnet v1 network magic`) |
| Address HRP | `qlud`, Bech32m, witness version 2, 32-byte program |
| Default P2P / RPC ports | `28440` / `28540` |
| Four-node controller ports | P2P `28440–28443`; RPC `28540–28543`, all loopback |
| Controller data | `.local/qlu-private-v1/nodeN/qludev/` |

Genesis text is `QLU private development network 2026-10-19; no monetary value`.
QLU has no DNS/fixed seeds or assumeutxo snapshots. Its default invocation binds loopback
and disables discovery and automatic peers. Explicit operator networking overrides exist;
the supported controller requires exact local configurations, disables settings overrides,
checks genesis/data/process ownership, and refuses conflicting ports. The earlier
`.local/devnet/` Bitcoin regtest remains separate and reusable.

## Keys, output policy, and authorization

All integer transaction values use existing integer accounting (eight decimal places).
The current prototype uses a single uniformly random 32-byte master seed per wallet, one
key pair, and derivation version 1. It is not yet an HD wallet with fresh receiving keys.

1. Derive the ML-DSA seed as `HMAC-SHA256(master, ASCII("QLU/ML-DSA-65/seed/v1"))`.
2. Derive a Schnorr secret candidate as `HMAC-SHA256(master,
   ASCII("QLU/BIP340/secret/v1") || uint32BE(counter))`, starting at counter zero and
   rejecting scalars outside the valid secp256k1 range; never reduce modulo the order.
3. Generate ML-DSA-65 keys through OpenSSL's default provider and BIP340 keys through the
   pinned upstream libsecp256k1. The ML-DSA public key is 1,952 bytes; the x-only Schnorr key is 32.
4. The key commitment is `taggedSHA256("QLU/key-commitment/v1",
   0x01 || ml_public || schnorr_public)`. Tagged SHA-256 is
   `SHA256(SHA256(tag) || SHA256(tag) || message)` with the tag's ASCII bytes.
5. The only spendable script is exactly `OP_2 PUSH32 commitment` (34 bytes).
   It is interpreted by QLU consensus, never by Bitcoin's permissive unknown-witness rule.
   Other scripts fail, except zero-value scripts beginning with `OP_RETURN`, at most 83 bytes.
6. Non-coinbase inputs have an empty scriptSig and exactly four witness items in this order:
   ML-DSA public key (1,952), Schnorr public key (32), ML-DSA signature (3,309), Schnorr
   signature (64). No annex, sighash selector, additional item, or alternate encoding is supported.
7. The authorization digest is `taggedSHA256("QLU/tx-auth/v1", genesis32_wire ||
   uint32LE(1) || uint32LE(input_index) || TX_NO_WITNESS(transaction) ||
   CompactSize(number_of_inputs) || serialize(spent_output_0) || ... )`.
   Genesis uses Bitcoin's 32-byte internal/wire order, the reverse of displayed hex.
   Each spent output uses normal `CTxOut` encoding: int64LE value and CompactSize-prefixed script.
   This binds every input/outpoint/sequence, every output/amount/script, version, locktime,
   fee through all spent values, signing input index, protocol version, network, and key policy.
8. Both algorithms sign the identical 32-byte digest. ML-DSA uses **pure ML-DSA** on that
   digest as its message, context ASCII `QLU/hybrid/v1`, with provider randomized signing;
   this is not HashML-DSA. BIP340 uses fresh auxiliary randomness. Both must verify.

Transactions must be version 2, have 1–16 inputs and 1–32 outputs. Blocks allow at most
256 non-coinbase input authorizations, in addition to inherited block-weight limits.
Exact witness lengths bound verification work. The miner charges 312 conventional sigop-cost
units per hybrid input, conservatively fitting under the inherited 80,000 budget; reserved
coinbase capacity can make assembled blocks stricter than the consensus 256-input ceiling.
These are development limits, not throughput promises. QLU-specific structural policy replaces
the three incompatible Bitcoin standard-script/witness gates; fee, conflict, maturity,
locktime, input existence, amount and block checks still run.

Mempool and direct-block validation independently enforce hybrid authorization. QLU does not
reuse Bitcoin script-success caches or skip signatures under assumevalid. Invalid witnesses
are distinguished from invalid non-witness transactions so a bad witness does not poison a
valid transaction sharing its txid. Upstream block witness commitments are verified before
QLU input checks. Only `qlu_devnet` parameters enable these rules; Bitcoin baseline networks
retain their consensus behavior.

## Recovery format and authority

The complete wallet JSON includes `format=qlu-wallet`, `version=1`,
`policy=mldsa65-and-bip340-v1`, `derivation_version=1`, `network_id`, `genesis_hash`,
`master_seed`, and `discovery={scheme:single-key-v1,key_index:0,scan_from_height:0}`.
The scan height may be a nonnegative signed-32-bit integer. Unknown fields, versions,
policies, algorithms, duplicate keys, and oversized payloads are rejected, not guessed or migrated.

- Generate an **independent random 32-byte recovery code**. Append the first eight bytes of
  `SHA256("QLU recovery code v1\0" || code)`, encode uppercase RFC4648 Base32 without padding,
  group into eight groups of eight characters, and prefix `QLU1-`. The checksum detects typos.
- Encrypt canonical wallet JSON with AES-256-GCM (128-bit authentication tag), fresh 12-byte
  nonce, and fresh 32-byte salt. Canonical JSON has sorted keys, no whitespace, ASCII escaping.
- Derive the encryption key using HKDF-SHA256 with the random code as input key material,
  the salt above, length 32, info `QLU wallet backup v1 / AES-256-GCM key\0`.
- The authenticated header contains format/version/cipher/KDF/salt/nonce/network/genesis.
  Associated data is `QLU wallet backup v1 / authenticated header\0` plus canonical header JSON.
  Salt, nonce, and ciphertext use standard Base64. Ciphertext includes its GCM tag.
- Restore requires the expected network and genesis, authenticates before returning keys,
  validates inner metadata, and reconstructs exactly the same signing authority.
  Maximum wallet JSON is 4,096 bytes; backup envelope 8,192; recovery-code input 128.
- CLI files are exclusive-create mode `0600`, with unsafe paths, symlinks, and hard-linked
  reads rejected. Secrets are not command arguments, node RPC parameters, or console output.
  The signing helper accepts bounded JSON on stdin and emits only public keys/signatures.

The older protocol fixtures contain disposable plaintext wallet files with restrictive
permissions. The new [encrypted wallet foundation](SECURE_WALLET.md) encrypts the working
wallet with a separate passphrase and provides lock/unlock and guided backup/recovery;
the portable backup format above is unchanged. Python cannot guarantee secret-memory
erasure. There is no hardware-backed key store, production account-discovery UI, or
guardian recovery yet. Store
backup copies safely and the recovery code on separate offline storage. Different folders on
one computer are not offline separation. The automated drill colocates disposable test
materials for reproducibility and must not be presented as production custody guidance.

Restoration does not revoke a thief's copy, cancel payments, or reverse theft. Suspected
compromise requires moving funds to newly generated keys. Losing all usable access and
recovery materials can permanently lose funds.

## Verification and release boundary

Required tests: official ML-DSA key-generation known answer; signature corruption/missing
component rejection; commitment mismatch; full-transaction and all-input binding; wrong-network
authorization; legacy/unknown-output rejection including coinbase; 256/257 authorization
boundary; invalid directly submitted blocks with valid commitments/PoW; valid same-txid after
invalid witnesses; four-node propagation/confirmation; authentic restore after removing the
original wallet; rediscovery of unspent outputs from restored keys; a restored-key payment; wrong-code/tampered-backup rejection; restart/cleanup.

See [current evidence](STATUS.md) for what has actually passed. A fresh-process restoration
on one Mac is not a second-device test. Hosted CI, sanitizers, fuzzing, hostile-network testing,
cross-implementation vectors, mobile measurements, independent specialist cryptography review,
and full-node operational review remain release gates. No runtime or security guarantees
for real-value funds are established by this milestone.

Recovery interoperability is a mandatory release gate across supported Mac, native
Windows, Linux, iPhone, and Android devices. Minimum supported OS versions and
platform implementations must be explicitly selected and tested before support is
claimed. See the [physical-device acceptance matrix](RECOVERY_RELEASE_GATE.md).
The [performance baseline](PERFORMANCE.md) and [MacBook drill](MACBOOK_RECOVERY.md)
track the first follow-on measurements without changing these protocol rules.

This construction uses 256-bit commitments and authorization hashes; it does not claim
ML-DSA-65's security category for every layer. Schnorr is not a second quantum-resistant
signature. Hybrid signing does not protect compromised devices, stolen backups/codes, scams,
or weak mining economics. Say **quantum-resistant spending prototype**, never quantum-proof.

Implementation references: [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final),
[OpenSSL ML-DSA keys](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-DSA/),
[OpenSSL ML-DSA signatures](https://docs.openssl.org/3.6/man7/EVP_SIGNATURE-ML-DSA/),
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki),
[Bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
OpenSSL must be at least 3.5; the locally tested implementation is 3.6.4. QLU runs a
cryptographic self-test before starting its chain/network; an unavailable or misconfigured
provider prevents startup rather than silently rejecting valid blocks. Recovery dependencies
are pinned with official PyPI wheel hashes in `qlu/recovery-requirements.txt`.
