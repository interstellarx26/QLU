# QLU private v1 status

Date: 2026-10-19 (America/Chicago; verification timestamps continue into 2026-10-20 UTC).

**Implemented and locally verified:** separate QLU development identity, mandatory ML-DSA-65
AND Schnorr spending, encrypted working-wallet storage and recovery, and restored-key
spending on four loopback nodes.
Test coins have no value. Both laboratory networks are stopped after tests.

The first [native Mac wallet app](WALLET_APP.md) is now built locally. It adds
create/open/recover screens, backup verification, QR receiving, balance discovery,
explicit payment review, lock controls and private-node startup/shutdown. It uses
the existing encrypted wallet through private process pipes; no consensus or
recovery-format changes were made.

**256 Python tests passed** (196 existing plus 32 bridge and 28 network tests).
A fresh app-bridge drill passed ten checks, including exact payments on four
nodes, restoration to a fresh encrypted vault after moving the original out of
its working location, rediscovery, restored spending, restart and cleanup.
The native UI also opened a disposable encrypted fixture, verified its backup
through the file picker, displayed the address/QR, received 1 test QLU and
reviewed/confirmed a 0.1 QLU self-payment with a 0.001 QLU fee. Quitting stopped
all four nodes.

Review corrected shutdown acknowledgment before cleanup, unclear pending-payment
presentation, and a focus-loss race during first creation/restoration. A hide
check did not reliably show a locked window, so explicit hide/minimize handlers
were added. The final build relocked an unlock request received while the app
was inactive. Full human foreground hide/minimize, new-wallet backup-code and
restoration flows remain acceptance work; automated UI fixtures do not establish
secret custody. This app is tied to the local checkout and dependencies, not a
portable or notarized release. Source review and local tests are not an audit.

The [encrypted wallet foundation](SECURE_WALLET.md) now passes locally: separate
daily passphrase and offline recovery code, encrypted vault creation/restoration,
explicit and idle locking, and guided backup verification. **162 Python tests
passed** (106 earlier tests plus 26 vault, 25 interface, and 5 worker-boundary
tests). A fresh four-node drill passed all eight checks: a funded encrypted
wallet rejected locked signing, its original vault was removed, a new process
restored directly to an encrypted vault, and the recovered keys rediscovered
their output and sent 0.999 test QLU with both signatures. That payment survived
all four nodes restarting, and all nodes stopped afterward.

That automated drill is on one physical Mac. It does not complete cross-platform
wallet acceptance. The guided interface is a
terminal tool; there is no consumer app or hardware-backed key store yet.
Three issues caught during implementation were corrected and regression-tested:
publication inode checking, command-line error redaction, and nonseekable terminal
stream handling. Separate agent review found no remaining blocker for this
private milestone; that is not a specialist security audit.

An updated [MacBook encrypted-wallet test kit](MACBOOK_WALLET_TEST.md) now adds
the guided target trial, frozen wallet-source provenance, and a separate origin
coordinator while preserving the earlier challenge and spending formats. The
expanded suite passes **196 tests**. A disposable same-host rehearsal passed all
ten wallet checks and confirmed its returned payment on four nodes; its shortened
idle wait is explicitly a rehearsal. All nodes stopped afterward. The separate
[MacBook encrypted-wallet trial has now passed its functional checks](MACBOOK_WALLET_RESULT.md):
the returned file matched its fingerprint, reported all ten wallet checks and
300.005 seconds of idle time, and produced the exact hybrid-signed payment
confirmed on all four nodes. All nodes stopped afterward. Target wallet checks
are self-reported and supported by the user's Terminal transcript; separate
hardware is user-attested. The code and supplied test passphrase were disclosed
in chat, so custody/offline-code acceptance remains unmet and these test keys
are retired. The new kit's MacBook setup-suite report was not supplied.

Follow-on milestone: [performance baseline](PERFORMANCE.md) now passes locally,
including an actually connected 256-authorization block and a fresh-process
offline-response recovery rehearsal. The separate MacBook recovery/spending trial
has now [passed](MACBOOK_RECOVERY_RESULT.md): the transferred response matched its
fingerprint, both signatures were accepted and its payment confirmed on four nodes.
Physical-device identity is user-attested; the disclosed disposable code makes
this an interoperability result, not proof of secret custody.
Recovery across Mac, native Windows, Linux, iPhone, and Android is now a mandatory
[release gate](RECOVERY_RELEASE_GATE.md), not an existing support claim.
At that earlier milestone the Python suite passed 106 tests, covering prior behavior plus the
offline challenge, coordinator, shared port lock and source-kit integrity. The
extracted MacBook source kit also builds locally and passes its native self-test
and 46 packaged recovery tests. The user also reports a passing native build/self-test
and 46 passing tests on the macOS 26.4 MacBook; its returned payment is independently
verified here. Historical counts below
describe the preceding protocol milestone; C++ consensus code was not changed
for this follow-on work.

## Project and scope

- Active project: `$HOME/Developer/QLU`, branch `qlu/main`; the original chat
  workspace links here. The old q-chain project folders remain untouched.
- Upstream ancestry: Bitcoin Core v31.1, `9be056a8a72b624dae9623b2f7bded92c2a21c91`.
  Unlike stage 0, this milestone deliberately modifies consensus for `qludev` only.
- Accepted rules and byte formats: [QLU private v1](QLU_PRIVATE_V1.md).
- Private QLU data `.local/qlu-private-v1/`; preserved Bitcoin baseline `.local/devnet/`.
- OpenSSL 3.6.4 provides ML-DSA; pinned upstream libsecp256k1 provides Schnorr. Recovery
  dependencies: cryptography 50.0.2, cffi 2.1.1, pycparser 3.11, with PyPI wheel hashes.
- Network identity, parameter parsing, cryptography integration, validation, recovery,
  transaction serialization and CI changes received separate agent reviews. This is not
  an independent specialist audit.

## Verified behavior

| Check | Result |
| --- | --- |
| Native release build | Passed on this Mac |
| Registered C++ CTest entries | 154 passed, 0 failed, 1 skipped (155 total) |
| Controller, recovery and protocol Python tests | 54 passed |
| QLU identity | Four nodes agree on QLU genesis; separate ports, data and addresses; local peer mesh |
| Hybrid spending | Both signatures mandatory; genuine ML-DSA implementation and external key-generation known answer tested |
| Invalid payments | Altered amounts, corrupted/missing signatures, wrong-network authorization, legacy and unknown outputs rejected |
| Directly submitted invalid blocks | Bad signature, classical mining reward, unknown output and excessive authorization count rejected on every node after recomputing witness commitments and proof of work |
| Authorization resource boundary | 256 accepted structurally; 257 rejected; 16-input/32-output transaction limits tested |
| Valid payment after invalid witness variants | Same-txid valid transaction propagates to all four mempools and confirms |
| Recovery | Original test wallet removed; new process restores a new file; same keys rediscover an unspent output and send a confirmed payment |
| Restart | Recovered payment survives all four nodes restarting |
| Runtime cryptography failure | Misconfigured provider prevents node startup with a clear error, before chain files/RPC cookies are created |
| Preserved upstream baseline | Four-node Bitcoin regtest smoke still passes with the modified binary |
| Cleanup | Both controllers stop all their owned nodes |

One optional CTest group, `script_assets_tests`, is skipped because the external
`DIR_UNIT_TEST_DATA` corpus is not configured. Counts are groups, not individual assertions.
The measured one-input/one-output hybrid transaction was **5,462 serialized bytes**. This is
an observation from the smoke test, not a throughput, fee or mobile-performance claim.

That earlier recovery drill proves a fresh process and file on the same Mac.
The later [MacBook trial](MACBOOK_RECOVERY_RESULT.md) records the separate-device result.
Disposable backup/code files are colocated under ignored `.local/recovery-drills/`
for automation; real offline separation is still required for users.

## Evidence

Ignored `.local/evidence/` retains timestamped build/CTest logs and pass/failure attempts.
`verification-summary-private.json` identifies the final implementation revision, source tree,
node/keytool hashes and current reports. Main reports are `qlu-private-latest.json`,
`devnet-smoke.json`, `provider-startup-negative.json`, and `python-tests-private.log`.
CTest XML is `build/qlu-foundation/qlu-ctest.xml`. No private wallet/code/cookie files are committed.

Encrypted-wallet evidence: `.local/evidence/python-tests-encrypted-wallet.log`,
`wallet-latest.json`, and `verification-summary-wallet.json`. The confirmed
payment is `b41cdda993ee5c06f2d4273b4ff00abb6c0d856033b6543320bed508e8c0ed3c`,
in block `6e19151a90b6bbba1c01dadf7541a2bf705f2aabe878a766258ea717480639f9`.
The private run `339af969141e46b683bc0b39f50914ae` completed at
2026-10-20 02:56:07 UTC (October 19 in Chicago). Its report records source and
binary fingerprints. Retained wallet and backup files from this drill are
encrypted; passphrases and recovery codes were not saved.

Wallet-app evidence: `.local/evidence/verification-summary-wallet-app.json`,
`python-tests-wallet-app.log`, `wallet-app-latest.json`,
`wallet-app-native-build.log`, `wallet-app-build.json` and
`wallet-app-native-ui.json`. The final bridge drill is
`9af6bce00e444f959d0ff2ba237ba9f2`; its recovered payment is
`2cd212e4ba7a416a8b528dfa4bf06ae86d50a382f4aed7b26547b249e67bf1fd`.
The native UI self-payment is
`7b60db5c91e9ab4dd8d17ef5b6620870c4b44a30b67f8698e8a493d3f79fe036`.
UI fixtures were disposable, their credentials known to automation, and the
temporary wallet-picker copy was archived outside the normal app wallet list.
The app's most recent payment and uncertainty notice are session-only; persistent
history and automatic reconciliation of unknown outcomes remain future work.

Development failures were retained and corrected: missing OpenSSL test include propagation
and CMake target scope, a narrowed integer in a test fixture, and a block-rejection test that
encountered already-processed peer headers. Each node now receives a distinct solved invalid
header so the test checks independent rejection. The startup negative test initially treated
creation of empty data directories as chain startup; inspection confirmed only empty directories
existed, and the final test checks no chain files or RPC cookies instead.

## Boundaries and next work

- Single-key signing and recovery prototype; no HD rotation, contact UI, hardware-backed live
  keys, automatic consumer recovery flow or production account discovery service.
- New working wallets use passphrase-encrypted vaults; historical protocol fixtures
  still use disposable plaintext seed files. Python cannot guarantee secret-memory
  erasure. Restoration does not revoke stolen key copies.
- No RandomX, production issuance/difficulty rules, public testnet/mainnet or paid cloud API.
- No sustained hostile-network/fuzzing/sanitizer runs, full upstream Python functional suite,
  full cross-platform recovery matrix, cross-implementation signature verification, mobile measurements,
  reproducible signed release or independent specialist security audit yet.
- CI builds the required OpenSSL on Linux and verifies dependency selection before
  Python tests that need the native signer. It also includes the encrypted-wallet
  and wallet-app private-network drills. It has not been run on hosted CI.
- Host macOS 27 / selected SDK 26.5; locally installed OpenSSL/libevent target macOS 27 and
  generate linker warnings. Local success does not demonstrate compatibility with older Macs.

Next: harden and broaden the measured protocol, test independent implementations and the remaining platforms,
then design HD rotation, hardware-backed custody and RandomX/economics as separately reviewed milestones.
The [historical stage-0 report](STATUS-FOUNDATION.md) preserves the earlier foundation evidence.
