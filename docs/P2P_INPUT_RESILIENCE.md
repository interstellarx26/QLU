# Private P2P input resilience

Status: implemented and verified locally on Mac and in fresh hosted Mac/Linux
builds. [STATUS.md](STATUS.md) records failures, corrections and the exact tested
revision; the scope below remains a private-network regression gate.

## Purpose and boundary

The existing independent conformance drill submits transactions through RPC and
direct block validation. This milestone exercises actual QLU peer connections:
bounded malformed v1 messages, hybrid transaction rejection, and valid payments
after those messages. It changes no consensus, signing, recovery or mining rules.

Use only four fresh, owned `qludev` nodes on literal IPv4 loopback. The normal
wallet network, user wallets and earlier q-chain folders are not test inputs.
All coins and keys are disposable. No public-network connection, address gossip,
large payload flood or arbitrary destination is permitted.

## Required behavior

1. Acquire the existing private-port lock and a new UUID fixture. Verify process
   ownership, exact configuration, QLU chain and genesis before connecting. Match
   the probe's ephemeral address and unique subversion marker. A probe must never
   weaken the shared controller's peer-ownership checks.
2. Complete a valid QLU version/verack handshake and explicitly verify v1
   transport before sending malformed frames. An invalid first message could
   otherwise enter inherited v2 transport negotiation and test a different path.
   Prove normal framing with fragmented header/payload and coalesced ping controls.
3. Exercise these twelve fixed malformed wire cases against each node:
   wrong magic; declared length 4,000,001; declared length 0xffffffff; bad checksum;
   nonprintable command; a command with nonzero bytes after a NUL terminator;
   empty and seven-byte ping payloads; empty and truncated-version transactions;
   noncanonical and excessive CompactSize transaction counts. Oversized declarations
   send only the 24-byte header, never the declared body.
4. Require peer disconnection for wrong magic and oversized declarations.
   Bad checksums/commands must discard the message and preserve a valid following
   ping on that connection. Deserialization failures must produce fresh,
   peer-scoped error evidence and a valid following ping. Silence alone is never
   a successful rejection. Check exact pong nonces, including forbidden responses
   to a deliberately corrupted ping.
5. Separately exercise an incomplete header and incomplete payload followed by
   client closure. These demonstrate bounded partial-frame handling and continued
   node health; they do not claim an immediate server rejection or timeout test.
6. Require completed initial block download before transaction tests. With a
   separate mature synthetic input for each target node, send corrupted ML-DSA,
   corrupted Schnorr and missing-witness variants. Require the intended QLU
   rejection reason and unchanged chain/mempool/UTXO state. Then send the original
   valid transaction through P2P, without an RPC broadcast, to prove bad witnesses
   sharing its transaction ID did not block valid spending.
7. Confirm all four payments and their exact transaction bytes and output values
   across all four nodes. Check recipient totals and fees. Restart the owned
   nodes, verify persistence, and replay each original payment through P2P without
   creating another payment or changing the confirmed state.
8. Compare all four chain tips/heights, relevant UTXOs, mempools and process tokens
   around malformed-input batches. Close each probe before checking the normal
   owned peer mesh. Cleanup closes sockets and stops only this fixture's nodes;
   all eight laboratory ports must be free afterward.

## Limits and evidence

The work budget is 600 seconds, checked before and after controller operations.
An existing controller RPC may take up to its 15-second bound to finish after a
deadline; cleanup has its own bounded controller timeouts. Socket handshake and
case processing use a ten-second monotonic deadline rather than renewing the
timeout after every read. The client checks lengths before allocation and caps
each received frame at 64 KiB and messages per connection at 256. Actual case
payloads are at most 8 KiB; per-node traffic is capped at 1 MiB sent and 2 MiB
received. Probes run sequentially, with no connection or inventory flood.

Fresh log reads are capped at 64 KiB and matched to the current peer/case.
Inherited parser-exception lines omit the peer ID, so those cases require the
exact command, size and peer receipt followed by its matching exception before
another message receipt. Transaction rejection lines must include the exact
peer, transaction ID, witness transaction ID and QLU rejection reason. The
fixture is sampled against the existing 100 MiB disk budget; this is a sampled
bound, not a filesystem quota. Record the fixed corpus, source and binary hashes,
case outcomes, valid controls, confirmed payments and cleanup. Preserve failed
attempts under ignored `.local/evidence/`; public summaries must exclude private
keys, RPC cookies, raw secrets and arbitrary exception text.

Focused tests must cover the probe's partial reads/writes, deadlines, reply size
limits, wrong checksums/magic/nonces, EOF, ownership restrictions and cleanup.
Run the live drill locally on Mac and in the hosted Mac/Linux workflow, together
with the existing safety, wallet, core and private-network regression gates.

This is a fixed v1 wire and transaction-admission regression corpus. It does not
establish v2 transport safety, full-node sanitizer coverage, sustained hostile
network capacity, general denial-of-service resistance, coverage-guided fuzzing,
independent implementation of the node, or production security. Specialist review
and broader release gates remain required before public deployment.
