# QLU private v1 status

Date: 2026-10-19 (America/Chicago; verification timestamps continue into 2026-10-20 UTC).

**Implemented and locally verified:** separate QLU development identity, mandatory ML-DSA-65
AND Schnorr spending, encrypted recovery, and restored-key spending on four loopback nodes.
Test coins have no value. Both laboratory networks are stopped after tests.

Follow-on milestone: [performance baseline](PERFORMANCE.md) now passes locally,
including an actually connected 256-authorization block and a fresh-process
offline-response recovery rehearsal. The separate MacBook test is prepared through
[device recovery tooling](MACBOOK_RECOVERY.md); physical completion remains pending.
Recovery across Mac, native Windows, Linux, iPhone, and Android is now a mandatory
[release gate](RECOVERY_RELEASE_GATE.md), not an existing support claim.
The follow-on Python suite passes 106 tests, covering the prior behavior plus the
offline challenge, coordinator, shared port lock and source-kit integrity. The
extracted MacBook source kit also builds locally and passes its native self-test
and 46 packaged recovery tests. It has not yet run on macOS 26.4. Historical counts below
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

The recovery drill proves a fresh process and file on the same Mac, not a second physical
device. Disposable backup/code files are colocated under ignored `.local/recovery-drills/`
for automation; real offline separation is still required for users.

## Evidence

Ignored `.local/evidence/` retains timestamped build/CTest logs and pass/failure attempts.
`verification-summary-private.json` identifies the final implementation revision, source tree,
node/keytool hashes and current reports. Main reports are `qlu-private-latest.json`,
`devnet-smoke.json`, `provider-startup-negative.json`, and `python-tests-private.log`.
CTest XML is `build/qlu-foundation/qlu-ctest.xml`. No private wallet/code/cookie files are committed.

Development failures were retained and corrected: missing OpenSSL test include propagation
and CMake target scope, a narrowed integer in a test fixture, and a block-rejection test that
encountered already-processed peer headers. Each node now receives a distinct solved invalid
header so the test checks independent rejection. The startup negative test initially treated
creation of empty data directories as chain startup; inspection confirmed only empty directories
existed, and the final test checks no chain files or RPC cookies instead.

## Boundaries and next work

- Single-key signing and recovery prototype; no HD rotation, contact UI, hardware-backed live
  keys, automatic consumer recovery flow or production account discovery service.
- Live wallet files contain plaintext seeds protected by mode 0600; backups use AES-256-GCM.
  Python cannot guarantee secret-memory erasure. Restoration does not revoke stolen key copies.
- No RandomX, production issuance/difficulty rules, public testnet/mainnet or paid cloud API.
- No sustained hostile-network/fuzzing/sanitizer runs, full upstream Python functional suite,
  second-device recovery, cross-implementation signature verification, mobile measurements,
  reproducible signed release or independent specialist security audit yet.
- CI workflow now builds the required OpenSSL on Linux, checks dependency selection, and tests
  both networks plus recovery. It has been syntax checked, not run on hosted CI.
- Host macOS 27 / selected SDK 26.5; locally installed OpenSSL/libevent target macOS 27 and
  generate linker warnings. Local success does not demonstrate compatibility with older Macs.

Next: harden and broaden the measured protocol, test independent implementations and a second device,
then design HD/live-key storage and RandomX/economics as separately reviewed milestones.
The [historical stage-0 report](STATUS-FOUNDATION.md) preserves the earlier foundation evidence.
