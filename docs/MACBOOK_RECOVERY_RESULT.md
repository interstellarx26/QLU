# First physical MacBook recovery result

**Passed on 2026-10-19 at 9:29 p.m. America/Chicago.** The returned MacBook
response matched the supplied file fingerprint, satisfied the prepared challenge,
and produced a payment confirmed on all four QLU private nodes. All four test
nodes stopped after verification. This is an experimental recovery/spending
result with valueless coins, not a public-release or custody certification.

## Verified on the original Mac

- The returned file SHA-256 exactly matched the fingerprint the user obtained
  in the MacBook Terminal:
  `1de7bc97e4dddbded4f5b2b65a23c37ab6d00cf926320fba35ff9b0dd79ebcf0`.
- Session `ed5cb43b67794073a0a5aaa9bf051f76`, network, genesis, key commitment,
  complete transaction, recipient and fee matched the frozen challenge.
- All three recovery/signing Python files matched the prepared source versions;
  the original node and key-tool binary fingerprints were unchanged.
- Every node accepted the restored wallet's mandatory ML-DSA-65 **and** BIP340
  signatures. The prepared input was spent, and the exact destination output
  was confirmed on every node: **0.99900000 test QLU**, with a **0.00100000 test QLU** fee.
- Transaction: `e96fbc7fdc2f1233bcaf839b19865c8a59d642b5593e1b001bfe93729467bf0c`.
- Block: `1cb384f59d196dee94b0569bd93407dfb2f1c61c58a1b1072c355cdb148579e8`.

## Target and evidence limits

The user identified the separate target as a MacBook Air 15-inch M4 (2025),
16 GB, macOS Tahoe 26.4, and supplied its setup and Terminal results. The user
reported a local arm64 build with the macOS 26.4 SDK and OpenSSL 3.5.9, a passing
native self-test, and 46 passing recovery tests without skips. The target setup
report itself has not been retrieved independently.

The returned response records Darwin 25.4.0, arm64 and Python 3.13.16. Its target
native helper SHA-256 is
`5330ae0732fceed0afcfdf8a73315a9f4491742c177045a1aad9a8d8381e5c8e`.
The response reports 2.68 ms for backup decryption and 164.13 ms for key derivation
and signing. These are one target-reported sample, not an independently measured
performance distribution. Hardware identity and separate-device execution rely
on the user's attestation; no remote hardware attestation was performed.

The disposable recovery code was disclosed in this conversation at the user's
request. This does not invalidate the signature/interoperability check, but the
trial does **not** demonstrate secret custody or the release gate's offline-code
handling requirement. Retire this test wallet and its code; never use these keys
for real value. Its prepared challenge is already spent and must not be reused.

Only this Mac-to-Mac recovery/spending trial passed. Full platform acceptance,
reverse-direction backup creation, complete output discovery on the target,
secret handling, peak memory, and independent security review remain outstanding.
Intel Mac, native Windows, Linux, iPhone and Android trials remain unverified.
The [cross-platform release gate](RECOVERY_RELEASE_GATE.md) remains open.

## Retained local evidence

Evidence is ignored under `.local/device-tests/ed5cb43b67794073a0a5aaa9bf051f76/`:

- `receipt.json`: confirmed-payment result and matching public provenance.
- `results/macbook-response.json`: byte-preserved returned response.
- `results/macbook-transfer.json`: expected file fingerprint, user-reported setup,
  physical-device attestation source and custody qualification.

The receipt's `response_sha256` hashes canonical JSON **without** a trailing
newline. The transferred file fingerprint above hashes the actual file including
its newline; these are intentionally different digests.

Verification ran the existing coordinator at checkpoint
`b8cd63d54f10d4717c725fdd46c602529055f91d`. No consensus, signing or recovery code
was changed for this verification. The old q-chain folders remain untouched.
