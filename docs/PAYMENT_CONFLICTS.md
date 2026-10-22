# Safe private-wallet conflict resolution

An outgoing transaction can stop blocking the wallet only when every owned
private node proves that another transaction in its active chain spends an
exact input of the original transaction. Missing outputs, transaction absence,
a mempool rival or a saved status alone are not sufficient.

## Evidence and state

Before any broadcast, new outgoing journal records retain the canonical
non-witness transaction bytes. Their recomputed txid must match the saved
transaction ID; input lists alone would not establish that binding. This is
public transaction data without signatures or spending keys. Journal v3 strictly
migrates existing v1/v2 records. Older records lacking those bytes retain their
conservative behavior; migration does not invent input evidence.

A `conflicted` record contains a competing txid, active block hash and height,
and one intersecting outpoint. These fields are lookup hints on later checks.
Resolution requires canonical competing transaction bytes, active membership
and identical evidence on all four owned nodes at a common chain snapshot.
The lookup is bounded by the existing 10,000-block scan limit and shared RPC
budget. A directly verified saved hint can work outside that search window.

Conflict state is reversible. Every new send or test-funding authorization
rechecks resolved conflicts; missing proof, changed chains, unavailable nodes
or exhausted lookup budgets restore `pending` and its outgoing block. The
submission adapter also rechecks all conflict guards against its own chain tip
before signing and immediately before the durable broadcast boundary. Funding
checks happen after any laboratory mining. Each guard shares one lookup budget
across its records. This closes a reconciliation-to-submission gap without
claiming atomic finality against a chain change after the last check.

The original operation ID remains consumed. Replaying it cannot resign or
resend the losing transaction. A new payment always requires a separate review
and approval using currently available funds. Conflict does not mean refunded,
permanently failed, or safe to automatically pay the recipient again. If the
competing transaction disappears in a later reorganization, the original may
return to pending or become confirmed.
The historical conflict hint is retained across those transitions. Generic
status recovery never mines a resurrected original that was previously resolved
as conflicted, even if all nodes now hold it in their mempools.

## Scope and verification

Only the private `qludev` wallet adapter, journal and interface change. Consensus,
hybrid signatures, encrypted vaults and portable backups stay unchanged. Tests
use fresh encrypted fixtures and four loopback nodes. Required checks include
malformed proof, wrong inputs/txids, node disagreement, orphaned competing blocks,
stale guards before signing/broadcast, restart, original-operation replay and a
new independently reviewed payment after resolution. Keep older failure reports
and test no-evidence legacy entries separately.

This is a same-Mac private-network experiment, not an independent chain proof,
public deployment or finality guarantee. See [STATUS.md](STATUS.md) for measured
results and [NETWORK_RESILIENCE.md](NETWORK_RESILIENCE.md) for the preceding drill.
