# Private network conflict and recovery rules

This milestone tests QLU's existing hybrid-signed transactions and inherited
proof-of-work chain selection under deliberate failures. It does not change
consensus, key formats, mining economics or public connectivity. All nodes bind
loopback, all wallets are newly generated fixtures, and all coins have no value.
The user's existing wallet and the three old q-chain projects stay untouched.

## Required behavior

- A conflicting spend must not spend the same output twice in an active chain.
  Test mempool rejection and direct block validation independently.
- A partition may produce two separately valid competing chains. Reconnecting
  the nodes must select the valid chain with greater accumulated work and agree
  on the chain tip and UTXO state. Greater work is checked explicitly; height
  alone is not the general chain-selection rule.
- Wallet authorization requires all four owned nodes, active networking, and
  completed connections to all three distinct owned peers. Equal old tips alone
  are insufficient. A missing node, disabled network or incomplete mesh prevents
  a new authorization; the private wallet intentionally sacrifices availability
  during these failures.
- Available coins are checked against all four nodes with mempool spends included.
  An outpoint spent in any node's mempool is unavailable to a new wallet payment.
  Invalid output metadata or a changed common chain snapshot fails the scan.
- Submission finishes with a common height/tip check after checking outputs and
  consumed inputs. A change after broadcast retains the exact transaction ID as
  pending. It never silently signs or sends a replacement.
- Failed network checks clear cached live balances and invalidate payment reviews.
  A saved historical confirmation must not be presented as a fresh network check
  after a failure. Recovery rechecks the existing transaction and journal.
- A stopped node must catch up from its existing data after restart, and wallet
  replay must return the existing result or remain blocked without another spend.

## Controlled fault injection

The isolated drill uses a unique directory and the existing exclusive laboratory
port lock. Its test controller disables automatic peer connections at process
launch and adds only the other owned loopback nodes. This permits repeatable
two-versus-two partitions without changing system firewalls, touching production
configuration, or contacting external peers. Ownership markers, genesis, paths
and peer identities are still checked. Restarts use fresh process ownership tokens.

The harness can deliberately submit separately authorized conflicting fixture
transactions to isolated halves. This is fault injection outside the consumer
wallet's send gate. The production wallet must refuse to authorize a new payment
while the same split exists.

Each run records public transaction IDs, chain work, UTXO digests,
assertions, source hashes and cleanup results under ignored `.local/`. The
milestone verification also records node/CLI/keytool binary fingerprints separately.
No recovery code, seed, passphrase or RPC cookie belongs in a report. Every owned
process must stop and the eight fixed loopback ports must be released even after
failure. Earlier failed runs remain evidence rather than being overwritten as
successes.

## Limits

The original resilience milestone kept losing transactions pending. The
[conflict-resolution follow-on](PAYMENT_CONFLICTS.md) adds txid-bound original
input evidence and fresh four-node competing-spend proof for new payments.
Resolution is reversible and rechecked before new authorization. Legacy records
without original transaction evidence still remain **pending and block new
outgoing payments** when their result is unresolved. There is no force-clear,
blind retry or claim of permanent finality.

The two-second peer-mesh retry window is not a strict operation deadline: an
in-flight RPC and synchronization helper retain their existing timeouts. Where
installed, the shared reconciliation deadline also applies to nested RPCs. No
hard real-time recovery guarantee is claimed.

The four nodes run on one machine. Tests cover selected failures, not hostile
Internet deployment, Byzantine consensus, economic resistance to majority hash
power, independent light-client verification, or all possible crashes. The test
network uses temporary SHA-256 regtest mining and is not RandomX. Engineering
review and local passing tests do not replace specialist security review.

See [STATUS.md](STATUS.md) for completed tests and current evidence.
