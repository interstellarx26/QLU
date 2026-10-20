# MacBook encrypted-wallet recovery result

**Functional trial passed on 2026-10-19 at 11:05 p.m. America/Chicago**
(2026-10-20 04:05:09 UTC). The returned MacBook response matched the supplied
file fingerprint, and its exact payment confirmed on all four QLU private
nodes. All four nodes stopped afterward. The target reported all ten wallet
checks passing, supported by the user's Terminal transcript.

This is an experimental wallet/recovery result with valueless coins. Secret
custody acceptance and the wider platform release gate remain incomplete.

## Independently verified on the original Mac

- Returned file SHA-256:
  `5057169496d9f49db8ddc8234a1850481794381f51a64b279efa7dbebc1e8e7b`.
  It matches the fingerprint the user obtained on the MacBook.
- Session `fa1557813a004859b69112783b3777ba`, network, genesis, key commitment,
  full transaction, recipient and fee match the frozen challenge. Wallet and
  recovery source fingerprints match the prepared versions; the origin node
  and key-tool binaries are unchanged.
- Every private node accepted the mandatory ML-DSA-65 **and** BIP340 signatures.
  The prepared input was spent and the exact recipient output confirmed on
  every node: **0.99900000 test QLU**, with a **0.00100000 test QLU** fee.
- Transaction:
  `7c98aafd6c06c559414588a228cf33fc0d080df394e713f9a5b6e26512536e9f`.
- Block:
  `143a8db64f47ebd52e3cff11253d1d169baec8e72e2e0bc6e8e36484094849d0`.

## Target reports and limits

The user identified a separate MacBook Air 15-inch M4 (2025), 16 GB, running
macOS Tahoe 26.4. Its response records Darwin 25.4.0, arm64 and Python 3.14.3.
Separate physical hardware is user-attested, not remotely attested.

The response reports encrypted restoration, matching identity, explicit lock
blocking signing, wrong-passphrase rejection, a fresh session starting locked,
saved backup verification, the full idle interval, idle lock blocking signing,
hybrid payment signing and a locked session on exit. It records **300.005
seconds** for the required 300-second idle interval. The user's Terminal
transcript corroborates this flow.

These target checks and timing are self-reported. The origin verifies the
signed payment, but cannot independently observe the target's stored vault,
timer callback, secret memory or physical hardware. The new kit's separate
setup/test report was not supplied; earlier setup results and local kit tests
must not be presented as this MacBook's new setup-suite results.

The recovery code and the test passphrase supplied for this trial were
disclosed in chat at the user's request. The actual hidden passphrase entry
was not inspected. The disclosure does not invalidate the functional payment
check, but this run does **not** pass secret-custody or offline-code handling
acceptance. Retire these disposable keys and supplied secrets; do not reuse
them. The prepared challenge is spent.

Full target output discovery, complete storage/negative-case acceptance, peak
memory, reverse-direction backup creation, Intel Mac, native Windows, Linux,
iPhone and Android trials remain outstanding. The
[cross-platform release gate](RECOVERY_RELEASE_GATE.md) remains open.

## Retained evidence

Ignored `.local/device-tests/fa1557813a004859b69112783b3777ba/` contains:

- `wallet-receipt.json` and `receipt.json`: wallet wrapper and confirmed-payment
  results, including source fingerprints and target reports.
- `results/macbook-wallet-response.json`: byte-preserved transferred file.
- `results/wallet-response.json` and `results/wallet-payment-response.json`:
  validated outer report and nested signed-payment response.
- `results/macbook-wallet-transfer.json`: file fingerprint, operator evidence,
  scope, credential disclosure and retirement record.

Receipt digests hash canonical JSON without a trailing newline; the transfer
fingerprint hashes the actual received file. They are different by design.
Verification used checkpoint `eaf50c7`. No consensus, signing, recovery or
wallet implementation was changed for this verification. Existing source-kit
and automated-suite results remain historical; they were not rerun for this
documentation update. A separate agent reviewed the verification path and
receipts without finding a blocker to this limited result; this was not a
specialist security audit.
