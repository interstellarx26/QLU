# Interrupted private payments

QLU can resume an outgoing payment interrupted after signing but before verified
four-node confirmation. This is a private `qludev` wallet feature, not a public
network or a change to consensus, signature policy, fees, or mining.

## Rules

1. Before the first possible broadcast, atomically save the operation ID, original
   intent, transaction ID, canonical unsigned transaction, exact signed transaction,
   and the input values/scripts that its authorization covers. The existing journal
   uses private owner-only files, exclusive process locking, durable replacement,
   and external-change detection. A failed save prevents broadcast.
2. A restart preserves this one pending operation. It never selects new inputs,
   signs again, changes the recipient, raises a fee, or silently sends a replacement.
   Read-only status refresh never rebroadcasts a transaction.
3. The user unlocks the same wallet and explicitly reviews **the original payment**.
   The review shows its original recipient, amount, fee, and transaction ID. A
   confirmation is one-use, expires after 120 seconds, and is invalidated by wallet
   changes, locking, cancellation, or an incompatible payment status.
4. Preparation and confirmation both check all four owned loopback nodes. Each
   original input must still exist on the shared active chain with the saved value,
   script, and required maturity. A node lacking the original transaction must
   also have no mempool spend of those inputs and must accept the exact saved bytes.
   Nodes already holding it must return byte-for-byte identical signed bytes.
5. Confirmation rechecks wallet identity, journal ownership, immutable outbox data,
   the reviewed chain snapshot, and earlier conflict resolutions. Only then may it
   submit those original bytes to peers missing them. It mines only that same
   transaction ID in this private laboratory, then verifies active confirmation on
   all four nodes. Any other unresolved outgoing operation blocks resumption too,
   including a prior conflict returned to pending by a reorganization. The journal
   operation is updated in place.
6. Timeouts or another interruption leave the original pending operation intact.
   A subsequent explicit review can retry those bytes. Propagation races are
   accepted only when the peer demonstrably holds the exact original bytes.
7. Legacy records without signed bytes cannot be reconstructed or blindly retried.
   A payment that was previously confirmed or conflicted cannot use this resume
   flow even if a reorganization later makes it pending. The retained block and
   conflict markers are monotonic history, not current chain authority. Existing
   status checking and separately documented conflict handling still apply.

## Storage and trust boundary

Journal version 4 adds an optional immutable pair: `signed_transaction` and
`spent_outputs`. Strict migration preserves v1–v3 records without manufacturing
missing authorization. Local checks bind canonical encoding, txid, output intent,
fee, witness shape, public-key commitment, and wallet identity. Four nodes perform
the actual signature and spend validation.

Signed bytes can broadcast the payment that the user already authorized. They
contain no private keys or recovery code, but are sensitive before broadcast and
remain in ignored `.local/` owner-only storage. They are excluded from bridge
responses, native UI state, public receipts, logs, and published source. The journal
is not a substitute for the encrypted wallet backup. These checks do not defend
against an attacker already controlling the user's OS account or wallet process.

The journal has a 16 MiB file cap and each signed transaction a 262,144 hex-character
cap. Capacity exhaustion fails closed before a new broadcast. The laboratory uses
a fixed 0.001 QLU fee and automatic block creation; these are not production policy.

## Validation

`qlu/tests/test_payment_resume.py` exercises malformed outboxes, identity and intent
binding, partial propagation, lost RPC responses, changed chain state, offline
nodes, and the durable-history guard. Journal, bridge, and native tests cover
migration, private-field redaction, one-use review, lock/cancel/stale callbacks,
and original operation continuity.

`qlu/payment_resume_smoke.py` uses fresh subprocesses and disposable four-node
fixtures to test interruption boundaries with real hybrid signatures. It never
uses a person's wallet, backup, passphrase, or recovery code. Its process cleanup
is fixture-owned; it is not a claim of production automatic orphan-node adoption.
See `STATUS.md` for the results actually observed on a particular host.
