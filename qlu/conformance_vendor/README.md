# Test-only cryptographic references

These files are conformance evidence and independent test implementations. They
must never be imported by the wallet, signing helper, or consensus code. Python
reference signing is not constant time. Every seed or secret key in these vectors
is published disposable test material, never a real wallet or custody credential.
Git preserves the exact vendored bytes. The BIP340 CSV retains its upstream CRLF
line endings and the NIST license retains its original trailing space; ordinary
whitespace cleanup would change the pinned source hashes.

## BIP340

`bip340_reference.py`, `bip340_test_vectors.csv`, and `bip340.LICENSE` are unmodified
copies from the official [Bitcoin BIPs repository](https://github.com/bitcoin/bips/tree/f98774a68c23269d9bfa78c8d9c4671ebf4ceb69/bip-0340),
commit `f98774a68c23269d9bfa78c8d9c4671ebf4ceb69`. The complete CSV has 19 cases,
indices 0–18, including variable-length messages. All verification expectations
and every signing case with an available secret key are checked. Upstream code
and vectors offer BSD-2-Clause, MIT, or CC0-1.0; the unchanged license notice is
retained. The BIP authors are Pieter Wuille, Jonas Nick, and Tim Ruffing.

## ML-DSA-65 reference

[dilithium-py 1.5.1](https://pypi.org/project/dilithium-py/1.5.1/) is installed only
through `qlu/conformance-requirements.txt`, using the official universal-wheel
SHA-256 hash. Its [release source](https://github.com/GiacomoPope/dilithium-py/tree/23cb5ee9dd7fa15d9e3c17527e7964c58f3cc549)
is pinned to commit `23cb5ee9dd7fa15d9e3c17527e7964c58f3cc549`. The full upstream
license is retained in `dilithium_py.LICENSE`. No optional extras or unpinned
transitive dependencies are installed. `provenance.json` records hashes of all
20 Python source files inside the pinned wheel; the standalone self-test compares
them with the actually installed package, rejecting missing, changed, or extra
Python files. A compromised interpreter can evade these checks; this is
reproducibility evidence, not hostile-host attestation.

The reference requires upstream's bundled `shake_wrapper` backend and rejects
the optional `xoflib` backend. It uses standard-library `hashlib` for SHAKE and
SHA-256, which may itself use OpenSSL. The ML-DSA algorithm and polynomial
arithmetic are independent Python code; no OpenSSL ML-DSA signing or verification
operation is called. The BIP340 reference uses Python integer arithmetic rather
than libsecp256k1. These are two independent signature paths, not independent
implementations of every hash primitive or of the entire node.

## NIST ACVP known answers

`nist_mldsa65_subset.json` is a small extraction from the National Institute of
Standards and Technology's official [ACVP-Server repository](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files),
commit `975de31eb83d87039ec88934fdc47d8c312b892d`. Source files are the `prompt.json`
and `expectedResults.json` pairs in:

- `ML-DSA-keyGen-FIPS204`: group 2, case 26, full public-key known answer.
- `ML-DSA-sigGen-FIPS204`: group 3, case 31, external pure deterministic signature
  with a nonempty context; exact signature bytes are checked.
- `ML-DSA-sigVer-FIPS204`: group 3, cases 31, 32, 33, external pure verification
  with contexts, expected false, false, true.

Each extracted case merges group metadata (excluding its `tests` array), the
prompt's case, and the expected-result case. Only the unused key-generation
private key was omitted. Fields and byte strings are otherwise unchanged; the
subset was reformatted as JSON on 2026-10-23. The published signature-generation
private key remains so exact deterministic signing can be tested. Full source
file hashes, exact paths, extraction recipe, and subset hashes appear in
`provenance.json`. `nist.LICENSE` preserves the entire NIST notice from that
revision's README License section. NIST is the source of these known answers;
their use does not certify, approve, or audit QLU.

The current pinned ACVP key-generation case 26 differs from the older sample
published in OpenSSL's 3.6.4 test file and used by QLU's existing C++ test. Case IDs
alone do not identify immutable vectors; compare the pinned sources and complete
bytes. The independent test compares all 1,952 expected public-key bytes.

`conformance_reference.self_test()` validates package/vendor integrity and these
known answers before the standalone live private-network drill starts any nodes.
Unit tests additionally exercise malformed encodings, all-input authorization
binding, missing/corrupt signatures, wrong context, and integrity failures.
