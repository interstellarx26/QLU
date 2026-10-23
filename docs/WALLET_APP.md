# QLU private Mac wallet app

The first native Mac interface uses the existing encrypted wallet and the four
local QLU development nodes. Coins have no monetary value. This is a local
development app tied to this source checkout, not a public wallet release or
a portable installer.

## Scope and decisions

- Use native SwiftUI screens for creating, opening, backing up, restoring,
  receiving and reviewing payments. The receiving screen shows the exact QLU
  address and a QR code; contact names are a later feature.
- Keep the existing Argon2id/AES-GCM working vault, portable backup format and
  mandatory ML-DSA-65 plus Schnorr authorization unchanged.
- The Mac process launches the pinned Python wallet through private process
  pipes. There is no browser, HTTP wallet server, cloud account or public API.
  Only a bounded set of named operations is accepted. Errors must not repeat
  passwords, recovery codes, raw requests or private keys.
- Passphrases and recovery codes enter native secure fields. A newly created
  recovery code is displayed for the person to record separately from the
  encrypted backup. It is not automatically copied or saved by the app.
  No app can prove that a screen, keyboard, clipboard or computer is private.
  Swift and Python do not guarantee secret-memory erasure.
- Creation saves a new encrypted wallet and requires a saved-backup readback
  check before receiving or sending. Restoration creates another encrypted
  file directly and verifies the supplied backup. Existing wallets and backups
  are never overwritten. A successful explicit backup check is remembered using
  an authenticated local receipt. Normal reopening requires the passphrase;
  missing or invalid receipts require a new backup check. This records a past
  successful check, not continuing possession or safe storage of the backup.
- Locking, expiration, switching wallets and quitting invalidate an outstanding
  payment review. Status polling must not extend the five-minute key deadline.
  Ordinary app/monitor switching keeps the wallet unlocked. Hiding, minimizing,
  system/display sleep, session deactivation and manual locking still request a real lock. An earlier create,
  restore or unlock response cannot undo a later real lock.
  Switching apps covers a displayed recovery code without discarding it. On
  return, a fresh public status check must confirm the session before revealing
  it; failed or stale checks leave it covered. These checks do not extend idle time.
- Open pins the selected encrypted bytes. Unlock must authenticate that same
  file identity before it can attach payment history or trust remembered backup
  verification. A changed file closes access and requires explicit Open again;
  wrong-passphrase failures clear cached availability and approval. See
  [wallet identity continuity](WALLET_IDENTITY.md) for rules and limits.
- Sending first validates a QLU development address and exact decimal amount,
  then selects confirmed mature inputs and presents the recipient, amount,
  fee and total. A review expires after two minutes and authorizes at most one transaction.
  Confirmation rechecks the inputs and requires an unlocked wallet.
- The fixed fee of 0.001 test QLU and a button to obtain 1 test QLU are laboratory
  conveniences, not production fee or issuance rules. The app owns a separate,
  persistent four-node data directory and the existing laboratory port lock.
  Starting it must never take over nodes belonging to another test.
- A successful send requires the exact payment to confirm on all four nodes.
  A failure after a possible broadcast must retain the transaction identifier
  and report uncertainty rather than encourage another payment.
  The backend persists the payment before broadcast and blocks new sends and
  funding while any recorded outcome is uncertain, including after restarting.
  A repeated operation identifier returns the recorded result without another
  transaction. A transport failure may occur before the interface receives the
  transaction ID; the journal retains it independently of that reply.
- Node startup is an explicit app action. Normal shutdown locks the wallet and
  stops owned nodes. A forced process kill, system crash or failed cleanup may
  require investigation; startup must fail safely instead of adopting or
  force-killing an unknown process.

## Remembered backup verification

After the person selects their saved encrypted backup and enters its separate
recovery code, the unlocked session restores and compares the complete wallet.
Only that successful check may create a verification receipt. Merely creating a
backup and reading it back internally does not enroll verification. Recovery
into a new vault performs the same check and saves that new vault's own receipt.

The receipt is bounded, strict version-1 JSON with exactly `format`, `version`,
`network_id`, `genesis_hash`, `policy`, `vault_sha256`, `wallet_commitment`,
`backup_sha256`, `verified_at`, and `hmac_sha256`. It binds the exact encrypted
vault bytes authenticated at unlock (or published at creation), the QLU network
and signing policy, the wallet identity, and the checked encrypted backup's hash.
Its integer timestamp is informational, not a security clock or expiration rule.

Inside the unlocked session, derive an independent key as
`HMAC-SHA256(master_seed, "QLU local backup verification v1 / HMAC-SHA256 key\0")`.
Authenticate the canonical header without the MAC field using that key and the
prefix `"QLU local backup verification v1 / authenticated receipt\0"`.
Here `\0` denotes one NUL byte. These domains are separate from signing and
backup encryption. No receipt API exposes the key; no secret, passphrase,
recovery code, or backup contents enter the receipt.

Receipts live in `.local/wallet-app/backup-verifications/<vault-sha256>.json`.
The directory is `0700`, files are `0600`, and bounded reads reject unsafe
ownership, permissions, symlinks and hard links. Publication flushes the complete
file, atomically installs it, synchronizes the directory and checks readback.
The bridge authenticates the saved readback before reporting success. A safely
owned corrupt receipt can be replaced only after another successful backup
check; unsafe files are refused. An interrupted publication can leave a complete
receipt or a temporary/hard-linked file. Failure is not reported as success;
an unsafe leftover must be investigated rather than silently repaired.

Opening still starts locked. Correct passphrase unlock decrypts the vault before
authenticating any receipt; a public boolean, changed metadata or copied receipt
for another vault cannot enable receiving or spending. Missing, malformed,
tampered or unsafe receipts leave the backup gate closed. Ordinary status polls
do not reauthenticate receipts, perform key work or extend the idle deadline.
Manual lock, idle lock and payment-review rules remain unchanged.

This is historical verification with no revocation or anti-rollback promise.
A previous valid receipt for identical vault bytes still works, including a
byte-identical copied vault on this installation. Newly restored/re-encrypted
vaults have a different identity. Removing the receipt requires verification
again. Existing pre-upgrade wallets require one real check to enroll. The
portable backup format is unchanged and does not contain the receipt. Recovery
still requires the encrypted backup and separate code; a receipt cannot restore
keys, prove the backup/code still exists, or protect a compromised same-user
process. Independent specialist review remains a public-release requirement.

## Persistent history and status recovery

The payment history card shows the latest 20 locally recorded attempts, with
amount, recipient, fee, date, transaction ID, and confirmed / needs checking /
not sent state. Up to 10,000 records remain on disk; reaching that bound pauses
new payments rather than deleting records. An unresolved older payment also has
a separate visible transaction ID. Unlocking loads saved history; network
startup, Refresh, and payment preparation check its chain status. Ordinary
five-second status polling only reads local records and does not extend key
access or mine blocks.

`Check payment status` checks the existing transaction on all four private
nodes. If it is already confirmed, it updates the stored result. If the exact
transaction is in all four mempools, this explicit action can mine a private
confirmation block containing that existing transaction ID. It does not sign,
rebuild, or broadcast a replacement payment. If the transaction cannot be
found or nodes disagree, sending stays paused. Absence is never treated as
proof that repeating the payment would be safe.

The store is `.local/wallet-app/payment-history/<key-commitment>.json`, with
a separate stable lockfile. The directory is owner-only (`0700`) and files are
`0600`; no wallet keys, passphrases or recovery codes are stored there. Journal v4
also stores exact signed outgoing transactions and their input values/scripts
before broadcast. Those bytes can broadcast only the already-authorized payment;
they are private outbox data and are never returned to the UI or public receipts.
The journal is not encrypted and stays in ignored `.local/` storage. Restored copies of
the same wallet in this installation share the same history and exclusive lock.
Another process cannot authorize through that journal while it is owned.
Existing portable wallet backups do **not** include this history or transfer
the duplicate guard to another device. Pre-upgrade outgoing payments and payments
from other applications/devices are not automatically imported. An explicit
incoming-payment check can add an independently checked receipt as described below.

Durability and authorization ordering:

1. Persist a unique operation ID and `preparing` intent before network work.
   The send review ID is its operation ID; funding has a separate random ID.
2. Validate and sign the reviewed transaction. Persist its locally computed
   transaction ID, canonical non-witness and signed transaction bytes, input
   values/scripts and public details as `pending`, atomically replacing and
   synchronizing the journal, **before** any possible broadcast.
3. Submit and confirm the payment. Persist `confirmed` only after verification.
   Losing the reply or crashing before this final write leaves a recoverable
   pending record, not permission to pay again.
4. On restart, a `preparing` record without a transaction ID becomes `not_sent`:
   the broadcast boundary could not have been reached. Any record with a durable
   transaction ID remains conservative until checked against the chain. A crash
   after that write but before submission can now be recovered by explicitly
   reviewing and resuming the original signed bytes. Older entries without them
   remain pending. There is no blind retry or force-clear button.

Use **Review original payment**, then **Resume original payment** to resume an
eligible interruption after unlocking. The amount, fee and transaction ID remain
unchanged. A fresh four-node check, one-use review and journal guard are required;
no new signing occurs. Previously confirmed or conflicted payments cannot use
this flow. See [the interrupted-payment rules](INTERRUPTED_PAYMENTS.md).
Signed outboxes are retained with their records. The 16 MiB journal byte cap can
be reached before the 10,000-record cap; either limit fails closed before a new
broadcast. Archive/pruning support is separate future work.

Confirmed entries are rechecked too, so a chain reorganization can return them
to pending. Confirmation uses active-block membership of the exact transaction
ID on all four nodes; spending its outputs later does not erase its history.
A saved block remains a lookup hint after a temporary failure. Historical scans
are bounded at 10,000 blocks; an exact unanimously pooled transaction can still
be finished outside that window, except an original payment previously resolved
as conflicted, which generic status recovery never mines. Deeper reorganizations may require engineering
investigation while sending remains paused.

Malformed, missing, changed, unsafe, concurrently owned, or unwritable history
fails closed. The app never silently resets an existing journal. Atomic local
storage does not protect against malicious same-user processes, removal or
rollback of the entire app directory, or hardware/filesystem failures outside
the tested guarantees. This is a private-network implementation, not a claim of
universal exactly-once payments or production financial custody.

Run `python3 qlu/payment_history_smoke.py` for the isolated real-node interruption
and restart drill. It uses fresh fixture wallets and node directories and requires
the other laboratory networks to be stopped.

## Two-wallet payments and incoming verification

The native Receive screen accepts a sender's public transaction ID. This is a
manual lookup for this private prototype, not automatic payment notifications or
a complete account index. `verify_received` is a read-only bridge operation: it
does not sign, submit, mine, repeat a payment, or trust an amount claimed by the
sender. Unlock and completed backup setup are required to use the wallet flow.

The network adapter validates node identity, ownership, loopback peers, common
height and tip. It searches at most 10,000 recent blocks, using a previously
verified block only as a height hint. It then checks active-block membership on
all four nodes. Transaction bytes are bounded and parsed canonically; their
computed transaction ID must match the requested ID. The received amount is
the exact sum of outputs to the wallet's script. Coinbase transactions and
transactions spending any wallet-owned input are refused as incoming payments,
including self-transfers, change and mixed ownership. Previous-output scripts
come from the owned nodes' validated undo data via `getblock` verbosity 3, and
all four nodes must agree. Missing undo data, disagreement, an unresolved lookup
or a changed chain snapshot cannot produce a verified receipt. This is agreement
among the private full nodes, not an independently checked light-client proof.

Incoming verification has a 25-second budget in addition to the block limit;
one in-flight RPC can add its existing 15-second transport timeout. An entire
history-reconciliation batch shares one 25-second budget, including inherited
identity RPCs. Outgoing records take priority; later unchecked rows become pending
without another RPC. Incoming checks are deferred during outgoing authorization,
and status recovery does not immediately repeat the same reconciliation batch.
Saved receipts are rechecked through the same verifier on explicit refresh,
network startup and payment-status checks. Losing confirmation marks the incoming
entry as needing checking while retaining its block hint. It does not create an
outgoing-payment lock: sending is governed by actual spendable funds and any
unresolved outgoing operations. A received output may later be spent without
erasing its historical confirmation.

History v2 introduced strict `receive` records with amount, recipient, transaction ID,
lookup origin, block and four-node confirmation. They omit a fee field because
the recipient did not pay the sender's transaction fee. `observe_received` accepts
only the verified adapter receipt and deduplicates by transaction ID, including
matching existing send/funding records. Received recipients must
match the canonical address derived from the journal's wallet commitment both
when observed and when loaded; a valid receipt for another wallet is rejected.
Incoming records cannot enter outgoing
authorization methods or be replayed as a send. V1 journals must pass their exact
original schema before atomic migration; existing operation IDs, payments,
uncertainty guards and block hints are preserved. A failure never resets history.
The current journal is v4, adding the immutable signed outbox to v3 conflict
evidence while retaining those incoming rules. Versions 1–3 are validated against
their exact original schemas before migration to v4. Older app builds cannot read v4 journals
and must not be used to downgrade them.

The send review distinguishes a transfer to the wallet's own address from a
payment to another wallet. For a self-transfer, the amount stays in this single-key
wallet and only the fee leaves its balance; the screen separately shows the
amount plus fee required to construct the transaction. For an external payment,
the displayed wallet debit is the amount plus fee. History labels sent, received,
test funding and self-transfers distinctly.

## Network failures and changing chains

The private wallet requires four owned nodes with active networking and a
completed connection to each of the other three nodes before payment checks.
An identical cached tip on disconnected nodes is insufficient. Scans check
outpoints against all four mempools and finish with a common height/tip check.
Submission also repeats that common check after inspecting outputs and spent
inputs; a post-broadcast failure keeps the exact transaction pending.

`network_running` describes the owned lifecycle; `network_healthy` separately
records whether the last balance/network check succeeded. A failed check or a
fresh insufficient-funds result clears cached balances and the review. The
native interface disables new payment authorization until a fresh check succeeds,
while receiving-address display and backup remain available offline. Invalid
address/amount input does not by itself invalidate a successful network check.
Status polling does not continuously probe the chain, so confirmations are labeled
as being **at the last check**, and an unavailable network shows saved confirmation
without presenting it as a current result. Pending outgoing guards remain durable.

See [private conflict and recovery rules](NETWORK_RESILIENCE.md) and the
[safe conflict-resolution design](PAYMENT_CONFLICTS.md). New outgoing records
bind original inputs to their transaction ID using canonical non-witness bytes.
All four nodes must prove an active competing spend of one exact input before
the record becomes `conflicted` and stops blocking new reviewed payments. Saved
conflict hints are rechecked before authorization and at submission; a reorg or
unavailable proof restores pending. Replaying the original operation never
resends it. The interface labels the result as a last-check observation, not a
permanent cancellation or refund. Legacy records without original transaction
evidence remain conservative; no input metadata is invented during migration.

## Visual direction

The private app follows [VibexHQ](https://www.vibexhq.com/)'s observed colors:
near-black `#070A09`, warm gold `#D0B681`, ivory `#F3F0E9`, with deep-green
`#102019` panels and readable muted text. Color is supplementary; payment status,
warnings and private-network scope remain explicit text. QR codes retain a white
background. The app includes usage descriptions explaining access to encrypted
wallet/backup files selected in Downloads, Documents and Desktop; these strings
do not grant permission or bypass macOS controls.

## Local build

With the foundation binaries and pinned Python environment already built:

```sh
.local/recovery-venv/bin/python qlu/build_wallet_app.py --open
```

The output is `build/qlu-wallet/QLU Wallet.app`. Its local ad-hoc signature is not
Apple notarization or a developer distribution signature. Its embedded project
path points to this checkout, including Python and native dependencies; moving
the app to another Mac does not install those dependencies. A UI deployment
target does not establish minimum-OS compatibility for the whole wallet.

Managed encrypted wallets live under `.local/wallet-app/wallets/`. The person
chooses where to save an encrypted portable backup. Keep the recovery code on
separate offline storage. Existing disclosed test codes and passwords must
never be reused for this app.

## First use

1. Choose **Create a wallet** and enter a new private passphrase twice.
2. Choose **Save new backup**, save the encrypted file, and write down the
   displayed recovery code separately offline.
3. Choose **I saved my code**, enter that code, and choose **Verify backup**.
4. From **Wallet**, choose **Start network**, then **Add 1 test QLU**.
5. Use **Receive** to share the address or QR with another wallet on this same
   local network. **Send** requires the full address and an amount, followed by
   **Review payment** and **Confirm and send**.

Saving a new backup now opens a **Write down your recovery code** popup inside
the wallet window. This code starts with `QLU1-`; the daily wallet passphrase cannot verify
a backup. Record the complete code and hyphens before acknowledging it. Each new
backup has a new code, so keep track of which file it belongs to.

Switching away while the Save dialog is open no longer locks the wallet. Saving
after returning proceeds normally. If the wallet actually locks while the dialog
is open, the app keeps only the chosen destination, explains that nothing has
been saved, and offers **Create backup and show code** after unlock. Unlocking
alone does not write a file. A selection accepted while QLU is inactive likewise
waits for explicit continuation. A late save result during an ordinary app switch
retains its code behind the cover. A real lock or wallet change discards that
code. If a file was saved but its code was discarded, save a new backup with a
new filename; the app never overwrites the earlier file.

The code is cleared on lock. The explanation survives unlocking. Recovery-code
display is independent of credential-sheet presentation, so resetting an old
sheet's binding or delivering its dismissal callback cannot erase the code.
The popup disables the interface behind it and does not close on Escape or a
click outside it. While covered, the code view is removed from the visible and
accessibility trees; only a cover and status-retry button remain. Acknowledgment
or an actual lock clears the code. App switching alone does not.
Pending destinations and delivery status are limited to the current app session
and wallet. The save dialog initially opens Downloads; the user can choose a
different destination.

Quit normally to lock the wallet and stop its nodes. After relaunch, open and
unlock the same wallet. A valid authenticated backup-verification receipt
remembers the completed check; a missing, changed or invalid receipt requires
verification again. The receipt proves a previous check, not continued possession
of the backup or recovery code.
The faucet has no persisted signing key: after restarting it may mine additional
temporary development blocks. Eventually those temporary halving rules can
exhaust its ability to provide another whole test coin; the app will report that
without deleting or resetting the chain.

## Required checks

Verify malformed and oversized requests, error redaction, backup gating,
wrong passphrases, locked signing, idle behavior without polling extending it,
exact amount/address parsing, stale inputs, review expiration and replay,
wallet switching, cleanup, and uncertain-broadcast reporting. Exercise the
bridge against actual four-node payments and a restored encrypted wallet,
and inspect the native screens.

Run `python3 qlu/test_wallet_native.py` on macOS for deterministic native-model
checks. The 39 cases use synthetic data and a queued bridge to cover interrupted
and cancelled dialogs, explicit continuation, stale callbacks, wallet changes,
sheet dismissal, idle locking, passphrase confusion, temporary focus cover,
failed/stale foreground checks, late access replies after a real lock, and
uncertain-payment blocking across status/lock/unlock, loaded persistent history,
status recovery, late confirmations that must retain uncertainty, and unique
funding operation identifiers. These checks run in the
macOS CI job; a local pass does not imply a hosted CI run. The native interface
was also exercised in a separate app with the real Save dialog and a synthetic
bridge: Save displayed a readable popup, Escape left it visible, the interface
behind it was disabled/absent from accessibility, and acknowledgment returned to
verification. The synthetic app overrides the model's active-app predicate for
background automation; this does not establish actual user focus behavior. The
earlier sheet version also displayed in that probe, so the reported immediate
disappearance was not reproduced there. The later human retry displayed the
code and successfully verified the backup. The user subsequently disclosed the
test code in chat and authorized its use for private acceptance checks; those
materials are test-only and are not evidence of private secret custody.

The original app checkpoint passed 256 Python tests and ten actual four-node bridge checks.
The native bundle compiled, its ad-hoc signature verified, and UI inspection
exercised opening/unlocking an isolated fixture, backup file selection and
verification, QR display, test funding, payment review, a confirmed self-payment
and shutdown. Creation and restoration were exercised through the real bridge;
the human creation/backup/payment flow was subsequently demonstrated. A reported
human recovery was not sufficient evidence of a separate restored vault: takeover
found only the original managed file. A separate copy was then restored through
the application backend, opened in the actual native app and checked. The
initial build relocked background unlocks; the revised focus policy deliberately
keeps those unlocked unless a real lock intervened.

The later takeover acceptance exercised a separately restored managed vault in
the actual native app: wrong/right passphrases, backup gating/readback, matching
address and funds after restart, invalid recipient/amount/insufficient-funds
refusals, cancellation, manual-lock review invalidation, a real two-minute
expired review and a confirmed restored-key self-payment. The ordinary 300-second
idle timer locked during normal polling (observed unlocked at 280 seconds and
locked at 318); native hide/minimize also locked. Full app/node restart retained
the payment and final 0.998 test balance. Normal shutdown released all owned
nodes and ports. The original encrypted files remained unchanged. See
`.local/evidence/wallet-acceptance-summary.json`; physical sleep/session/Lock Screen,
ordinary foreground switching across monitors, other operating systems and
private custody are not inferred from this automated acceptance run.

The persistent-payment follow-up passed 325 Python tests, 39 native model tests,
and seven additional real four-node interruption/restart scenarios. The actual
native views were also checked with synthetic history: pending records blocked
new payments, checking status changed the same record to confirmed, and the send
form became available. See the current milestone in [status](STATUS.md) for precise
scope and the recorded evidence.

MacBook transfer, secret-custody acceptance, other operating systems,
hardware-backed storage, independent cryptography/operational review and the
full [recovery matrix](RECOVERY_RELEASE_GATE.md) remain separate gates. See
[current status](STATUS.md) for evidence actually collected.

Native interface references: [Apple SecureField](https://developer.apple.com/documentation/swiftui/securefield)
and [Foundation process output](https://developer.apple.com/documentation/foundation/process/standardoutput).
