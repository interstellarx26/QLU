# QLU private v1 status

Updated: 2026-10-23 (America/Chicago; evidence timestamps are recorded in UTC).

**Implemented and locally verified:** separate QLU development identity, mandatory ML-DSA-65
AND Schnorr spending, encrypted working-wallet storage and recovery, and restored-key
spending on four loopback nodes.
Test coins have no value. Both laboratory networks are stopped after tests.

## Repeated private payments and resource baseline — 2026-10-23

The [fixed protocol workload](PAYMENT_WORKLOAD.md) passed **32 real transfers**
in eight batches on four fresh loopback nodes. An independent expected ledger
matched every outpoint, amount and script, each original signed transaction and
block's exact bytes, and the whole-chain UTXO hash on all four nodes. Two graceful
node restarts preserved that state. Submitting an original confirmed transaction
again to all four nodes created no additional transaction, fee or balance change.

The run crossed the existing laboratory halving at height 150. It read and checked
all 149 setup rewards and eight workload rewards, including actual fees. Total
subsidies and final UTXOs were 7,650 test QLU. The 32 payments paid 0.032 test QLU
in fees, which returned through coinbases; fees were not mistaken for new issuance.
These are temporary laboratory rules, not production economics.

All **562 Python tests passed** in both the isolated Python 3.12.13 and app
Python 3.14.6 environments, including 20 new workload checks. Negative tests cover
changed witness bytes with the same transaction ID, missing/duplicate payments,
double-used inputs, wrong fees/rewards/scripts, incorrect node state, unsafe
fixture files, expired budgets, foreign processes and failed evidence writes.
Separate agent review found no unresolved blocker. Its diagnostic finding was
fixed: hosted failures retain a safe allowlisted summary even if writing the
local evidence fails. This review is not an independent specialist audit.

The local run used an Apple M4, 16 GiB, eight physical CPU cores, macOS 27.0.1,
Python 3.14.6 and cryptography 50.0.2. Samples include helper/process startup,
serialization, loopback RPC and polling; desktop load was uncontrolled.

| Observation | Result | Scope |
| --- | --- | --- |
| One-input payment bytes | 5,462 | All 32 payments |
| Four-payment block bytes | 22,110 | All eight workload blocks |
| Signing median | 9.001 ms | 32 helper-inclusive samples |
| Preflight median | 4.610 ms | 32 node-admission samples |
| Broadcast RPC median | 4.614 ms | 32 samples, not confirmation |
| All-mempool observation median | 4.452 s | Eight batches, polling included |
| Mining RPC median | 8.137 ms | Eight on-demand laboratory blocks |
| Same-tip observation after mining median | 17.624 ms | Eight batches, not finality |
| Graceful stop/start/agreement | 0.711 s and 0.720 s | Two controlled restarts |
| Largest observed per-node RSS | 59.875 MiB | Snapshots, not peak memory |
| Four-node fixture after stop | 69.886 MiB logical; 3.402 MiB allocated | File sizes only; excludes directory metadata and evidence |

No compilation or document rendering ran alongside this measurement. It is a
short fixed protocol test, not a TPS benchmark, endurance soak, encrypted GUI or
history-journal test, crash/power-loss test, internet measurement or production
capacity claim. Its 100 MiB disk threshold is sampled, not a filesystem quota.

Attempt `75669b08817447e385756438875aecce` ran from
`2026-10-23T05:32:13.992046Z` to `2026-10-23T05:32:54.285175Z`.
Evidence remains ignored under `.local/evidence/payment-workload-<attempt>.json`;
full suite logs are `payment-workload-unit-python312-final.log` and
`payment-workload-unit-python314-final.log`. The recorded Git base is
`4ec966aec4f7c17428ab2be32ae2eeabaad9ba48` plus the new workload sources, whose
before/after hashes match. The unchanged node executable SHA-256 is
`b13126309cbb1bb8d088a05aeb38fb4e2861d7e492f22e0cea1b84c749260bcc`.
All owned nodes stopped, all eight ports were free, and all four protected user
vault/backup/history files retained their prior hashes.

The published implementation, `94a5e7772ad8d92f1e6279844a0d1bc67fd7102f`, passed
hosted [run 39906540092](https://github.com/interstellarx26/QLU/actions/runs/39906540092)
on October 23. Both Ubuntu 24.04 and macOS 15 passed **562 Python tests** with
no Python skips, **154 core tests**, every private-network drill, the new
32-payment workload and cleanup. Of 155 registered core targets, the optional
`script_assets_tests` target was skipped because its external corpus was not
configured; that target is not counted as an executed pass. macOS also passed
**70 native wallet model checks**. The Linux workload attempt was
`c5185c4181b745378cb8d6631e5c1c58`; the Mac attempt was
`d7dbdf5b446840e8af5c0d1be18c2f37`. Both reported `passed: true` and
`phase: complete`. Later documentation-only result recording does not change
the implementation tested in that run.

## Password-helper timeout and recovery — 2026-10-22

Native Argon2id derivation now runs in a fresh isolated helper with a shared
15-second queue/execution deadline and bounded private pipes. A hung, malformed
or failed helper is stopped and reaped; an unreaped child blocks new helpers
until its exit is observed. Failed unlock revokes prior authority; failed
derivation during create/restore publishes no vault. Encryption costs, the
v1 vault format and recovery formats remain unchanged. See
[the design, acceptance rules and limits](WALLET_KDF_TIMEOUT.md).

**534 Python tests passed** in both the local Python 3.12.13 CI environment and
the Python 3.14.6 app environment. Coverage includes a pre-change Argon2id vector,
a literal old-format vault, real stalled/crashed/flooding children, bounded
queue waiting, late exit, cancellation, quarantine and successful retry. A
review found that interruption during cleanup could lose ownership of a live
child; its regression failed before the fix and passed after ownership was
retained throughout cleanup. An existing port-lock test also assumed a permissive
umask; its fixture now explicitly sets its initial mode, preserving the same
assertion that refusing a symlink must not alter the target's permissions.

The fresh four-node fault drill passed **7 checks**. The unmodified 15-second
deadline stopped a deliberately stalled helper in 15.003 seconds; three shorter
test-only deadlines exercised other failure paths. All four helper children were
already reaped by production cleanup. The drill verified no partial vaults, no
payment side effects during password failure/retry, preserved wallet identity,
backup receipt, history and pending guard across restart, and one explicit resume
of the exact saved payment on all four nodes. Its final self-transfer balance
was 0.99800000 test QLU. Source and binary hashes stayed unchanged and all eight
private ports were free afterward.

The normal encrypted-wallet recovery drill and remembered-backup restart drill
also passed (8 and 7 checks respectively) using the app's Python environment.
The four original user vault/backup/history files matched their existing SHA-256
fingerprints after all local tests.

Final fault-drill attempt: `99cca7c544324c4d8cfc8a87927046ea`, with private evidence
in `.local/evidence/kdf-timeout-latest.json`. Full local suite logs are
`.local/evidence/kdf-full-unit-final-python312.log` and
`kdf-full-unit-final-python314.log`. The source kit includes the new helpers and
tests; CI includes the real stalled-helper drill. Hosted results must be checked
against the published revision. Independent agent review found no unresolved
blocker; it is not a specialist security audit. Deadline enforcement requires a
live controlling process and normal OS scheduling; abrupt parent termination can
orphan a helper. No new physical-device or public-network claim is made.

Hosted [run 39897768797](https://github.com/interstellarx26/QLU/actions/runs/39897768797)
at `c36df732c5aa8ef95d5c3c72d2385091ed5bc99d` passed the complete Linux job,
including the new helper-fault drill. The Mac job passed compilation, 534 Python
tests, 70 native model checks, 154 core tests (one optional external-corpus test
skipped) and the preceding live
drills, then failed the existing network-resilience drill. Its original log did
not identify the failure location. One local reproduction and three further
frozen-source repetitions each passed all 17 resilience checks; these passes do
not establish the cause of the hosted failure. The drill now emits an explicitly
allowlisted diagnostic summary on failure, without exception text, secrets,
source lines, local variables or absolute paths. Assertions and failure exit
status are retained. Both local Python environments passed the expanded
536-test suite after the diagnostic change.

A controlled RPC regression then established a separate test-controller race:
an owned connection could finish between two partition snapshots, causing an
immediate failure despite time remaining in the existing ten-second convergence
budget. Two late-arrival regressions failed before the fix. The controller now
keeps converging within that same budget; incomplete handshakes cannot pass,
foreign/malformed/non-loopback peers still fail immediately, and the final
partition assertion remains strict. Six new regressions cover success, late
arrival, unsafe peers and nonconvergence. This proves and fixes that controller
race, but does not prove it caused the original hosted failure.
With this follow-up, both local Python environments passed all **542 tests**.
The final real-node resilience drill passed all **17 checks** in attempt
`143249a96d934cbe937a5b466f1799b3`, with unchanged source/binary fingerprints,
all owned nodes stopped and all eight ports free. Independent review found no
blocker in the convergence fix. A fresh hosted run must validate this revision.

That final revision, `4ec966aec4f7c17428ab2be32ae2eeabaad9ba48`, passed hosted
[run 39901214881](https://github.com/interstellarx26/QLU/actions/runs/39901214881),
checked October 23. Both Ubuntu 24.04 and macOS 15 passed **542 Python tests**,
**154 core tests**, all private-network drills and cleanup. Of 155 registered
core targets, **one optional `script_assets_tests` target was skipped** because
its external corpus was not configured; it is not counted as an executed pass.
macOS also passed **70 native model checks**. This closes hosted validation of that
revision, while leaving the original earlier failure's cause unproven.

## Hosted CI compatibility — 2026-10-22

The first GitHub Actions run registered and built successfully on Ubuntu, then
hung during the Python wallet tests until the job timeout. The macOS 14 job
failed earlier: its Xcode 15.4 compiler does not support the C++20 aggregate
features used by the inherited source. Neither job passed the full suite.

The workflow now selects macOS 15 with Xcode 26.3 and records the compiler version.
Python tests retain every assertion and gain a five-minute fatal thread-stack
dump plus a ten-minute step limit, so a repeated hang produces useful diagnostics.
The next hosted Mac and Linux builds passed. Both diagnostic traces then found
the concurrent wallet-creation threads inside Argon2id derivation for five minutes. Local Python
3.12 passed all 513 tests and 100 repetitions of that creation test, so the hosted
trace supplied evidence that local runs did not reproduce.

A shared gate now serializes only native Argon2id construction and derivation,
including when script and package imports coexist. Encryption parameters and
formats are unchanged; atomic publication still runs concurrently and the test
still requires exactly one winner. Regression checks cover concurrent entry and
gate release after failures. See [the design and limits](SECURE_WALLET.md).
The cross-import concurrency regression failed against the previous code; all
515 Python tests pass locally with the mitigation and the new recovery-kit helper.
Hosted validation of that mitigation passed at commit
`a223137736b80ee8b7185e305f6a6b75a0586870` in
[run 39887926455](https://github.com/interstellarx26/QLU/actions/runs/39887926455):
515 Python tests and 154 passed core tests plus one optional external-corpus
skip on each OS (155 registered targets), 70 native Mac model
checks, every private-network drill and both cleanup steps. Later changes need
their own validation; this result applies to that exact revision.
Current hosted evidence is available in [GitHub Actions](https://github.com/interstellarx26/QLU/actions/workflows/qlu-foundation.yml);
older milestone notes below describe the validation available at their own dates.
All network exercises continue to use disposable loopback-only qludev/regtest nodes.

## Interrupted original-payment recovery — 2026-10-22

The wallet now durably saves the exact authorized transaction before broadcast.
After an interruption, **Review original payment** and **Resume original payment**
reuse its signed bytes and existing operation. No new input selection, signing,
recipient, amount, transaction ID or fee is created. Four-node preflight checks,
wallet identity, exclusive journal ownership, one-use review, and conflict guards
are checked again before submission. Any other uncertain outgoing payment blocks
resumption. Legacy records without the saved bytes and previously confirmed or
conflicted entries remain conservative. See [the design](INTERRUPTED_PAYMENTS.md).

The v4 journal retains the signed outbox privately under `.local/`; it is excluded
from native state, public receipts, logs and published source. Version 1–3 history
is validated before migration. Backup portability does not transfer the local
history/duplicate guard to another device. This is not a universal exactly-once
guarantee, public-network deployment or specialist security audit.

Verification on this Mac passed **513 Python tests**, **70 native model tests**,
and **13 live four-node scenarios** using disposable wallets and fresh worker
processes. The live drill includes exits immediately after durable save, before
a resume RPC, and after accepted submission; partial mempool persistence across
restart; lost accepted responses; cancellation, expiry, lock, offline-node and
reorganization refusal; corrupt bytes/intent; invalid signatures; legacy history;
and active/historical conflicts. Resumes performed zero signing operations,
retained the original transaction/fee/history entry, and produced the expected
sender and recipient balances. All fixture workers were reaped and all eight
private ports were free at completion. Original user vaults, backup and payment
history matched their pre-test SHA-256 fingerprints (four files).

A native transport-loss regression exposed two issues and failed before each
fix: `confirm_resume` was not classified as uncertain submission, and a failed
reply could discard the known transaction ID. It now preserves that ID, consumes
the review and keeps new payments blocked. A separate production-source native
UI probe verified review/cancel, one resume with zero new payments, legacy refusal,
offline refusal and the gold/green layout. That UI probe used synthetic responses;
actual chain behavior was tested separately by the real-node drill.

The first live harness attempts are retained honestly: an expected-error result
was incorrectly unwrapped as success; a restart test incorrectly required automatic
propagation to every mempool; and a balance report attempted to JSON-encode internal
byte scripts. The harness now preserves the same payment assertions, permits the
actual partial-propagation state, and reports only public balance strings. None of
those failed attempts is counted as a passing run.

Evidence is private under `.local/evidence/payment-resume-*`; the successful live
run is `802f99a84ced4f1db6f4b823ca9d5062`. The native source fingerprint is
`f445f7dc666d674bea24ae7def2a28e1172127aff4ff4e7b2ffe6de8736180fe`, and the
rebuilt local app executable is
`dbe24db2ce75be564fa87ac02daff01219d9bb86a5f2550de8500d5bbc4b7c2d`.
Scoped independent agent review found no unresolved blocker; it is not an external
specialist audit. CI includes the new drill; hosted results must be checked against
the exact published revision.

## Public source — 2026-10-22

The reviewed source is published in the public MIT-licensed
[`interstellarx26/QLU`](https://github.com/interstellarx26/QLU) repository.
Private vulnerability reporting is enabled. Publishing source does not launch a public network. Only source,
tests, documentation and intentional project metadata are included. Wallets,
recovery codes, node data, signed outbox files and raw test evidence remain local.
Personal home-directory prefixes were removed from eight QLU-added historical
commits in an isolated publication copy. Full Bitcoin ancestry and the exact
v31.1 base were preserved. Original development history is preserved privately.
See [publication boundaries](OPEN_SOURCE.md) and [security reporting](../SECURITY.md).

## Wallet identity and journal ownership — 2026-10-21

An encrypted wallet file can no longer silently change which wallet owns an
already open session. Previously, replacing locked wallet A with a valid wallet
B could pair B's authenticated keys with A's retained history and cached balance.
Four regressions reproduced this and related cleanup failures against the exact
previous bridge source, verified by its recorded SHA-256. That baseline was run
only from an evidence copy; production source was never reverted.

Open now pins the selected encrypted bytes. Unlock checks and decrypts the same
single file read, then checks the authenticated digest and previously known
commitment before publishing keys or attaching history. Create and Restore pin
the bytes produced by their authenticated sessions. A changed file closes the
selection and requires explicit Open again, including same-seed re-encryption.
An otherwise safe byte-identical copy remains valid. Failed unlocks clear cached
availability, approvals and authenticated state; wrong-passphrase retry on the
unchanged selection still works. Failed history acquisition during Create or
Restore locks and discards the new session while preserving the encrypted file.

The bridge independently checks journal ownership before reconciliation, replay,
state publication and spending. The native interface clears the previous wallet's
details and approval, displays the explicit-reopen explanation, and refuses stale
status, review and lock callbacks. The existing history lock remains exclusive;
no lockfile or pending record is removed to bypass another instance.

Local verification passed **475 Python tests**, **61 native model tests**, and
**58 real four-node checks**: identity/ownership 10, wallet 10, durable history 7,
remembered backup verification 7, incoming payments 7 and conflict/resilience 17.
The identity drill used distinct funded wallets with a deliberately interrupted
payment in B's journal. Replacement could not bypass B's pending guard; A's and
B's journals stayed byte-identical and no identity trial signed, broadcast or
mined a payment. Actual child-process contention and forced owner death verified
lock release without removing lockfiles or history. All eight child workers and
all fixture nodes stopped; all eight private ports were free afterward. Backend
sources, native source and node/CLI/keytool binaries stayed unchanged across the
final regression sequence.

The native bundle rebuilt and passed local ad-hoc signature verification. A
disposable synthetic UI probe verified the actual changed-file explanation,
welcome screen, removal of the previous payment review and public wallet details,
and refusal of an old status callback. This was separate from live-node testing.
The probe was closed and the updated actual app reopened at its welcome screen
without unlocking a user wallet. The two original encrypted wallets, selected
backup and existing payment journal stayed byte-for-byte unchanged.

A separate scoped source review found no remaining blocker; it is not a specialist
security audit. Hosted CI and other devices were not run. CI now includes the
identity drill. Logs, exact attempts, source/binary fingerprints, preserved baseline
failures and cleanup evidence are linked from
`.local/evidence/wallet-identity-summary.json` and
`wallet-identity-live-regressions.json`.

See [wallet identity rules and limits](WALLET_IDENTITY.md). This is selection
continuity, not continuous file monitoring or protection against a compromised
same-user process, operating system or whole-directory rollback. Consensus,
spending signatures, vault/backup formats, and mining economics are unchanged.

## Safe outgoing conflict resolution — 2026-10-21

New outgoing payments can now stop blocking the wallet when all four owned
private nodes prove that another active-chain transaction spends an exact input
of the original. The history records `conflicted`, keeps both transaction IDs,
and permits a separately reviewed new payment using available funds. The old
operation ID remains consumed and cannot sign or broadcast another payment.
This is a reversible last-check observation, not a permanent cancellation or refund.

Journal v3 stores canonical non-witness transaction bytes before broadcast,
validates their transaction ID, and derives the original inputs from those bytes.
Strict v1/v2 migration preserves existing history and guards. Legacy records
without that evidence remain conservative when unresolved; no input evidence is
invented. Public interface responses omit the internal transaction bytes. Signed
transactions, private keys and recovery material are not added to the journal.

New send/funding authorization rechecks every resolved outgoing conflict. The
network adapter independently checks them again against its own common chain
snapshot before signing and before the durable broadcast boundary, sharing a
lookup budget across records. Missing evidence, disagreeing/offline nodes, or a
reorganization restore pending and its outgoing block. The conflict hint remains
as history even after downgrade, so generic payment-status recovery cannot mine
a resurrected original automatically. An already confirmed original is reported
as fact. Reorganizations after the final check remain a blockchain limitation.

A missing original orphan-block header no longer prevents an active conflict
proof: only the explicit block-not-found RPC error falls back to bounded lookup.
Transport failures, other errors and malformed successful headers remain blocked.
The failing pre-fix regression is retained. The new live test injects that one
RPC condition; it does not claim to rebuild a physical node database.

Local verification passed **454 Python tests**, **55 native model tests**, and
**48 real four-node checks**: conflict/resilience 17, wallet 10, durable history 7,
incoming payments 7 and remembered backup verification 7. The conflict drill covers actual competing
hybrid spends, all-four double-spend block rejection, greater-work convergence,
fresh conflict proof, legacy no-evidence refusal, bad proof from one node, a
reorganization restoring the original input, stale approval refusal, a newly
reviewed payment broadcast exactly once, offline-node recovery and two fresh
Python reopen workers. The backup drill used another four separate Python workers.
Every final drill used the same production sources and node binaries. All owned
fixture workers/nodes stopped, and all eight private ports were free afterward.
A preliminary history run interrupted to incorporate the missing-header fix is
preserved as incomplete; the final full sequence passed after that fix.
A separate scoped source review found no remaining
blocker; it is not a specialist security audit.

The rebuilt native bundle passed local ad-hoc signature verification. A disposable
synthetic UI probe checked the actual conflict label, competing transaction ID,
paused send view after a reorg, restored review after a fresh status check, and
saved-conflict wording with an unavailable balance after a failed check. These
view checks are separate from real-node execution. The actual app was reopened
at its welcome screen without opening or unlocking a user wallet.
Both original encrypted vaults, the selected backup and the existing history
journal remained byte-for-byte unchanged.

See [conflict rules and limits](PAYMENT_CONFLICTS.md). Full regression results,
source/binary fingerprints, preserved/interrupted attempts and cleanup evidence
are collected in `.local/evidence/conflict-resolution-live-regressions.json` and
`conflict-resolution-summary.json`. No consensus, hybrid-signature, vault,
portable backup, mining-economics or public-network behavior changed. Hosted CI
and additional physical devices were not exercised for this milestone.

## Conflicting payments, disconnected nodes and chain recovery — 2026-10-20

The isolated resilience drill passed **10 real four-node checks** using fresh
encrypted wallets and valid hybrid signatures. An actual two-versus-two partition
created two valid competing spends of the same output. Each half retained its
original mempool transaction and rejected the equal-fee rival. Separately, all
four nodes rejected directly submitted blocks containing both spends, without
advancing their active tips. On reconnect, the valid branch with greater
accumulated work won; all four nodes agreed on the tip and full UTXO digest.
An offline fourth node blocked new authorization, restarted with a fresh ownership
token, and caught up from its existing data. Wallet/node restart and replay kept
the winning transaction confirmed without another signature, broadcast or fee.

The tests exposed wallet-adapter gaps, now fixed: identical tips on disconnected
nodes could pass validation, available funds depended on only one mempool, and
confirmation lacked a final common-chain check. New authorization now requires
all four owned nodes with active networking and completed connections to the other
three. Available outputs are checked against every node, and scanning/submission
end with a shared height/tip check. A change after broadcast retains the exact
transaction as pending. These changes harden the wallet adapter; the inherited
chain-selection and QLU consensus/signature rules did not change.

Failed network checks or freshly discovered insufficient funds now clear stale
balances and invalidate payment reviews. The interface requires a successful
refresh before new authorization, while address display and backup remain usable
offline. Saved confirmations are labeled as the last checked result, including a
clear needs-checking state after failure. A late prepare response cannot restore a
review after locking. Harmless address/amount input errors preserve checked state.

Final local verification passed **422 Python tests**, **52 native model tests**,
**9 focused QLU consensus/cryptography C++ cases**, and **41 real four-node checks**:
resilience 10, wallet 10, durable history 7, incoming payments 7 and remembered
backup verification 7. The last drill used four separate Python workers. All
fixture workers/nodes stopped and all eight private ports were free afterward.
The native bundle built, its local ad-hoc signature verified, and a disposable
synthetic UI probe checked unavailable balances, saved-status labels, disabled
review, refresh recovery and incoming-pending behavior. This UI probe is distinct
from the real-node backend drills. The updated actual app was reopened at its
welcome screen without unlocking a user wallet. Both original encrypted vaults,
the selected backup and the existing history journal stayed byte-for-byte unchanged.

An independent scoped agent review found no remaining code blocker after fixes;
this is not a specialist security audit. Earlier failed unit cases are retained.
The first real drill also exposed a harness reconnect timeout: persistent peer
retries could take 60 seconds against a 40-second wait. An explicit connection
attempt to the same owned loopback peers fixed the harness without weakening
handshake or isolation checks. Its failed report and cleanup evidence remain saved.

**Limit at this earlier milestone:** a losing conflicting outgoing payment stays pending and blocks
new outgoing payments. The journal lacks the original-input/conflict evidence
needed for safe automatic resolution; no force-clear or blind retry was added.
The later conflict-resolution milestone above supersedes this for new records
with verifiable original transaction evidence.
Four nodes on one Mac do not prove public-network security or device portability.
No public networking, mining economics, recovery format or consensus cryptography
was changed. CI includes the new drill, but hosted CI was not run for this milestone.

See [network rules and limits](NETWORK_RESILIENCE.md). Evidence:
`.local/evidence/network-resilience-summary.json` and
`network-resilience-live-regressions.json`, with exact run IDs, source fingerprints,
separate binary fingerprints, cleanup results and linked test/UI/build logs.

## Two-wallet payments and VibexHQ colors — 2026-10-20

The private Mac wallet can check an incoming payment by the sender's public
transaction ID and save a received record. The check validates the actual amount
to this wallet against canonical transaction bytes, active-chain membership and
validated previous outputs from all four owned private nodes. It refuses foreign
payments, coinbase, self-transfers, change, mixed ownership, disagreement and
unavailable proof data. It never signs, broadcasts or mines a new payment.
Checking the same transaction again does not create another history record.

History v2 preserves prior outgoing intents and uncertainty guards through strict,
atomic migration. Received entries are bound to the journal wallet, carry no
receiver-paid fee, survive restarts and remain verifiable after their outputs are
spent. A lost incoming confirmation becomes pending without blocking unrelated
outgoing payments. Reconciliation prioritizes outgoing records and shares one
25-second RPC budget across the batch; an already-started RPC can add its existing
15-second transport timeout. Incoming checks are deferred during authorization.
This is a lookup budget, not a strict wall-clock completion guarantee.

The app explains self-transfers before approval, including both the amount plus
fee needed to construct the payment and the fee-only net balance reduction.
History distinguishes sent, received, test funding and self-transfers. The palette
now follows VibexHQ's near-black, warm gold and dark green. Mac file-access usage
descriptions are included; a fresh OS permission-prompt presentation has not been
tested or claimed.

Local verification passed **404 Python tests**, **46 native model tests** and
**31 real four-node checks** across four isolated drills. The new seven-check drill
sent 0.1 QLU between distinct wallets: the sender held 0.899 QLU and the recipient
0.1 QLU after the 0.001 fee. It covered duplicate checks, wallet-owner and node
restarts, already-spent incoming outputs, invalid claims, lost confirmations and
reconfirmation of the same transaction. The earlier wallet, durable-history and
separate-process backup drills passed 10, 7 and 7 checks respectively; the last
used four fresh Python workers. All fixture nodes/workers were stopped afterward.

Native acceptance opened the existing **Wallet 7114ebed** using only its passphrase.
Its v1 journal upgraded to v2 with the existing record exactly preserved. On the
original four nodes its 0.01 self-transfer retained the same transaction ID and
confirmation, and the balance stayed **0.997 test QLU**. Attempting to count that
same transaction as new income correctly failed in the actual native interface.
No new user-wallet payment was made; both encrypted vaults and the selected
recovery backup remained byte-for-byte unchanged. QLU was left open and locked,
with all private nodes stopped and their eight ports free.

An isolated visual probe using the exact production Swift views also checked
received history without a receiving fee, incoming lookup results, self-transfer
review amounts and the available send form when only incoming confirmation was
unavailable. These synthetic view checks are separate from the real-node backend
drills. The native bundle built and its local ad-hoc signature verified.

A separate scoped agent review found two issues—aggregate lookup time and
cross-wallet receipt binding—which were fixed and covered by regression tests;
the follow-up review found no remaining blocking issue in the reviewed scope.
This remains an engineering review, not an independent specialist security audit.

See [rules and limitations](WALLET_APP.md#two-wallet-payments-and-incoming-verification)
and the [engineering roadmap](ENGINEERING_ROADMAP.md). Incoming lookup is manual,
limited to 10,000 recent blocks without a retained block hint, and needs the
private nodes' block/undo history. It is not automatic incoming discovery or an
independent light-client proof. History stays local and is not included in portable
recovery backups. No public network, production economics, mining algorithm or
consensus signature format changed in this milestone.
Evidence: `.local/evidence/received-payment-summary.json` and
`.local/evidence/received-payment-live-regressions.json`, with linked Python/native
logs, build report and each isolated drill result. The new drill is included in
CI configuration; hosted CI and other physical devices were not run for this change.

## Remembered backup verification — 2026-10-20

The private Mac wallet now remembers a successful backup check in an authenticated
local receipt tied to the exact encrypted vault. Correct passphrase unlock checks
the receipt; no recovery code or backup file is needed on a normal restart.
Missing, changed or unsafe receipts require verification again. Receipt creation
requires real backup recovery and full wallet comparison, followed by durable
publication and authenticated readback. Creating a backup alone does not enroll
verification. Vault, portable recovery and on-chain formats are unchanged.

Local verification passed **354 Python tests**, **43 native model tests**, and
**24 real four-node checks** across three drills. These cover field/MAC tampering,
wrong-vault replay, lock and expiry during verification, unsafe storage,
interrupted writes, remembered access, persistent history, uncertain outcomes,
and duplicate-payment prevention. The new 7-check drill used four separate
Python worker processes; normal reopening received only the passphrase while
the original backup path was absent. The existing wallet and payment-history
drills passed 10 and 7 checks respectively. An independent scoped agent review
found no blocking issue; this is not a specialist security audit.

The actual native app enrolled the previously checked **Wallet 7114ebed**, then
quit completely and reopened. Entering only the daily passphrase returned to
the wallet with remembered verification and saved payment history. Starting the
original private network showed the existing 0.01 test QLU payment confirmed on
all four nodes and the unchanged **0.997 test QLU** balance. No new payment was
made in this user-wallet check. The two original encrypted vaults and selected
backup remained byte-for-byte unchanged. The app was left open, locked, with
its private nodes stopped. Earlier in this conversation the user independently
reported the same payment ID and balance surviving the previous history restart
test; that human report is distinct from this observed native acceptance.

The first native backup read paused while macOS requested Downloads-folder
access, then completed. A process sample and system log identified the wait;
there was no receipt/cryptography deadlock. The ad-hoc app had no explicit
Downloads usage-description string at that point. The two-wallet milestone above
adds it; testing fresh prompt presentation remains a packaging follow-up. No permissions
were changed or workarounds used during diagnosis.

Newly generated encrypted-wallet device kits include the new vault dependency;
previously transferred kits remain unchanged. Local app build and ad-hoc signature
checks passed. CI includes the new private receipt drill, but hosted CI and other
physical devices have not been exercised for this feature.

See [design and limits](WALLET_APP.md#remembered-backup-verification). This records
a past successful check, not continuing backup possession, expiry or revocation.
Evidence is collected in `.local/evidence/backup-verification-summary.json`,
with Python/native logs, the three live-drill reports, and native acceptance.

## Persistent wallet payments — 2026-10-20

Implemented durable local payment history, restart recovery, and backend duplicate
prevention in the private Mac wallet. A payment intent and its transaction ID are
saved before broadcast. Repeating the same approved operation returns its stored
receipt; an unresolved operation blocks new sends and test funding across restarts
and restored copies using the same local installation. The history card shows the
latest 20 records and provides `Check payment status`. That action can confirm an
existing transaction, including mining its exact existing mempool transaction in
this private laboratory; it never signs or broadcasts a replacement payment.

Local verification passed **325 Python tests** and **39 native model tests**.
The journal tests include actual subprocess exits without cleanup before and after
the durable broadcast marker. An independent scoped code review checked journal
publication/locking, reorganization handling, replay and uncertainty guards.

The new real four-node drill passed **7 scenarios** with fresh fixture wallets:
recorded funding/payment; full app-owner and node restart with exact request replay
and no second signing, transaction or fee; historical confirmation after all
outputs were spent; reorganization followed by confirmation of the same transaction;
corrupt-history refusal; interruption after recording but before broadcast;
and a timeout after actual broadcast followed by restart and recovery of that exact
transaction without another signature or broadcast. Nodes were stopped and all
eight loopback laboratory ports released afterward.
The existing **10 real bridge checks** also passed against the completed change,
covering backup, payment review, restored spending, balances and node cleanup.

The native history screen was inspected with the actual production views and a
synthetic bridge: pending records showed the pause notice and blocked the send form
and funding button; a status check updated the same record to confirmed and released
the send form. This visual check is separate from the real-node backend drill.
The app bundle compiled and its local ad-hoc signature verified.

The live restart drill exposed unfinished extra loopback peer handshakes. Validation
now briefly retries an empty peer identity while repeating every ownership, genesis,
configuration and peer check. It never accepts an unidentified peer; foreign or
non-loopback peers fail immediately. Targeted tests cover eventual handshake success,
deadline failure, foreign peers, and changed process ownership.

History starts with newly recorded payments. Earlier payments and activity from other
devices are not imported; portable recovery backups do not carry this local journal.
An absent uncertain transaction remains blocked, including the conservative case
of interruption between recording its ID and submission. There is no force-clear or
blind retry. These are private-network results, not a production audit or a claim of
universal exactly-once payments. See [wallet rules](WALLET_APP.md#persistent-history-and-status-recovery).

Evidence: `.local/evidence/payment-history-python-tests.log`,
`.local/evidence/payment-history-native-tests.log`,
`.local/evidence/payment-history-latest.json`, and
`.local/evidence/payment-history-build.log`, with the original bridge regression in
`.local/evidence/payment-history-existing-smoke.log`. Final verification is collected
in `.local/evidence/payment-history-summary.json`. The new real-node drill is also included
in CI configuration; hosted CI has not been run for this uncommitted work.

## Native wallet acceptance follow-up — 2026-10-20

The human backup retry now displayed the recovery code, verified its encrypted
backup, funded the wallet and confirmed a self-payment on all four local nodes.
The user's screenshot showed the expected 0.999 test QLU after its fee.

During the authorized takeover, the managed wallet directory contained only the
original wallet. The proposed recovery passphrase did not unlock that file; the
original passphrase did. The reported earlier recovery was therefore not treated
as proof of a separate restored file. The application backend was used to restore
the verified backup into a new encrypted managed vault using the already chosen
test passphrase. Its address matched, and the original file remained unchanged.
The restored copy was then opened, unlocked and backup-verified through the actual
native app after a fresh launch. Restarting the original private network recovered
the same 0.999 balance.

Actual native UI checks rejected a wrong passphrase, blocked receiving before
backup verification, rejected an invalid recipient, zero amount and insufficient
funds, cancelled a review without spending, and cleared a review on manual lock.
A review left open for more than two minutes was rejected without spending.
A fresh 0.01 self-payment from the restored copy then confirmed on all four nodes;
independent node reads agreed on 0.998 test QLU after its 0.001 fee. The transaction
reference and public node evidence are in ignored acceptance records, not secrets
or passphrases in this document.

The current Python suite passed **256 tests**. The native model suite passed
**35 tests**, including three new uncertain-payment regressions. A separate,
fresh-fixture application-bridge drill passed **10 real four-node checks**:
backup readback, wrong-passphrase refusal, cancelled/locked reviews, exact fees
and change, one-use approval, recovery into a separate vault, restored spending,
balances surviving node restart and owned-node cleanup. It used its own data and
keys and released all laboratory ports before the user's app network restarted.

At this earlier checkpoint, recent-payment display and uncertain-payment protection
were session-only. The persistent-payment milestone above addresses that local
limitation. These earlier acceptance results do
not establish other operating systems, private custody, independent security
review, or all physical sleep/Lock Screen notification paths. The credentials
shared for this acceptance wallet are disclosed disposable test material.

Evidence: `.local/evidence/wallet-acceptance-restored-copy.json`,
`.local/evidence/wallet-acceptance-pre-payment.json`,
`.local/evidence/wallet-acceptance-recovered-payment.json`,
`.local/evidence/wallet-acceptance-real-bridge-summary.json`,
`.local/evidence/wallet-acceptance-native-final.log`, and the timestamped
`wallet-acceptance-python-*` log. Final evidence is in
`.local/evidence/wallet-acceptance-summary.json`.

The real idle trial stayed unlocked at 280 seconds and was observed locked at
318 seconds with the normal 300-second deadline and status polling unchanged.
Native minimize and explicit hide both locked the wallet. Normal quit stopped
the app and all owned nodes; a full relaunch, backup readback and network restart
retained the recovered-wallet payment and 0.998 balance. The final state is the
recovered wallet loaded and locked, network stopped, all eight laboratory ports
free. Original wallet and backup hashes remained unchanged. No production-source
change was needed during this acceptance run; three native regression tests and
these records were added. Physical sleep/Lock Screen and cross-platform tests
remain distinct acceptance work.

## Earlier development milestones

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
were added. The initial build relocked an unlock request received while the app
was inactive. Full human foreground hide/minimize, new-wallet backup-code and
restoration flows remain acceptance work; automated UI fixtures do not establish
secret custody. This app is tied to the local checkout and dependencies, not a
portable or notarized release. Source review and local tests are not an audit.

The first human backup attempt exposed a native UI interruption: switching to
chat while the Save dialog was open could cause Save to silently return after
locking. The fix preserves the selected destination, explains the interruption,
and requires an explicit continuation after unlock. The recovery code now opens
in a dedicated window, with a separate hint when a wallet passphrase is entered
as a recovery code. Locking still clears the code; delayed callbacks cannot
reveal it or erase a newer code window. **23 native model regressions passed**
and all **256 Python tests passed again**. The code-window layout was checked
with synthetic data; actual human backup verification is still pending. The
backup format, encryption and private-network rules are unchanged. Evidence:
`.local/evidence/native-backup-flow-tests.log`,
`.local/evidence/python-tests-backup-fix.log`, and
`.local/evidence/backup-code-layout.png` (synthetic code only).

The human retry still reported no visible code before the hidden-code notice.
The display now uses a popup within the wallet window, independent of native
sheet bindings and dismissal. A new regression resets the previous sheet binding
to nil before delivering its dismissal callbacks; the recovery code remains
visible. An actual native UI probe with a synthetic bridge displayed the popup
after Save, kept it visible through Escape, disabled the underlying interface,
and returned to verification on acknowledgment. That probe overrides the model's
active-app predicate for background automation. The original sheet also displayed
in the probe, so this is not a reproduction of the user's specific failure.
Human acceptance is still pending. Logs under `.local/backup-ui-integration/`
contain only synthetic event names and presence flags, not user recovery material.

The user's multi-monitor trial showed that locking on every app switch was too
disruptive. The revised policy keeps the session unlocked during ordinary app
switching and covers the recovery code temporarily. Returning to QLU requests
fresh status before revealing it; failed or stale responses leave it covered.
The unchanged five-minute idle deadline, manual lock, hide/minimize, system/display sleep, session deactivation and
quit still lock. A true lock clears the code and remains locally latched until
a fresh explicit unlock/create/restore succeeds. Earlier access replies cannot
undo it. **32 native model tests passed**, including background backup completion,
stale foreground status, expiration while covered and late access after a true
lock. Human acceptance on the user's two-monitor setup is still pending.
The synthetic native popup also passed cover/return and expiry-on-return checks.
The rebuilt ad-hoc-signed app was reopened with the existing wallet locked;
its encrypted wallet and backup hashes stayed unchanged. Explicit display-sleep
and session-deactivation handlers compiled, but their physical notification
delivery and every macOS Lock Screen gesture remain manual acceptance work.
Evidence: `.local/evidence/wallet-focus-fix.json` and
`.local/evidence/native-backup-focus-tests.log`.

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
At that earlier milestone the most recent payment and uncertainty notice were
session-only. The persistent-payments milestone above supersedes that limitation.

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
  and wallet-app private-network drills. Hosted results above apply to their
  exact revisions; the earlier stage-0 notes predate hosted execution.
- Host macOS 27 / selected SDK 26.5; locally installed OpenSSL/libevent target macOS 27 and
  generate linker warnings. Local success does not demonstrate compatibility with older Macs.

Next: harden and broaden the measured protocol, test independent implementations and the remaining platforms,
then design HD rotation, hardware-backed custody and RandomX/economics as separately reviewed milestones.
The [historical stage-0 report](STATUS-FOUNDATION.md) preserves the earlier foundation evidence.
