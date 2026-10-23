# Bounded private payment workload

This is a reproducible **node and transaction reliability experiment**, using
four localhost `qludev` nodes on one computer. It exercises the existing hybrid
signing rules and existing temporary SHA-256 laboratory mining. It does not
change consensus, fees, emission, cryptography, or wallet storage.

## Fixed acceptance contract

The harness creates a fresh UUID data directory under ignored `.local/`, holds
the shared private-port lock, and starts only its own four nodes. All wallet
seeds are freshly generated in memory. They reach the existing signing helper
only through stdin; the harness never saves a plaintext wallet, seed, passphrase,
or recovery code. Evidence contains public transaction identifiers and accounting.
Python and the OS cannot guarantee secret-memory erasure or protection from swap.

The run has no user-selectable size or recipient:

1. Mine 149 fresh setup blocks and read their actual serialized coinbase outputs.
   Four separate mature outputs fund four payment chains.
2. Make **32 one-input, one-output payments in eight batches of four**. Their
   owners rotate among four independently generated wallets; each payment sends
   its input value minus the existing test fee of **0.001 QLU** to the next wallet.
3. Require each original signed transaction to appear in all four mempools,
   mine one block per batch, and verify all four nodes store the same exact block
   bytes, including every original transaction witness. No replacement is signed.
4. After batches four and eight, gracefully stop and restart the owned nodes.
   Re-read all workload blocks and verify the exact stored bytes, original
   transaction IDs, chain tip, and complete expected UTXO ledger survive.
5. Submit one original already-confirmed transaction to each node again. Only
   the same transaction ID or the node's `-27` already-in-chain response is
   accepted. Require identical tips, empty mempools, UTXO fingerprints, counts,
   and balances before and after; no extra transaction, fee, or mining occurs.
6. Stop the owned nodes, check all eight private ports are free, and verify the
   relevant source files and binaries match their starting fingerprints.

The independent ledger tracks every spendable setup reward, workload reward,
and payment output. It refuses missing inputs, double use, unauthorized byte
changes, changed fees, duplicate transactions, or unrecognized scripts. Each
node's scan must match every expected outpoint, value, and script. Full-chain
UTXO count, monetary total, and hash must also agree across all four nodes.

Height 150 crosses the existing laboratory halving. The harness measures actual
coinbase values and checks them against the current temporary 150-block subsidy
rule **plus actual transaction fees**, rather than assuming every reward is
50 QLU. The fee total for a completed run must be 0.032 QLU. Mining fees return
through coinbases, so the full-chain UTXO total equals cumulative subsidies;
the accounting explicitly includes both sides of that transfer.

## Timing and resource evidence

Retained JSON includes each raw signing, preflight, broadcast, propagation,
mining, agreement, and graceful-restart timing; each payment and workload block's
serialized size; and owned-node RSS snapshots before payments, after each batch,
after restarts, and fixture-file disk sizes after cleanup. Timing includes Python,
native helper and CLI process startup, serialization, loopback RPC, and polling.
There are no speed thresholds or throughput claims, and no timing samples are
discarded as warmups. Desktop load, scheduling, temperature, and power state are
uncontrolled. Four peers on one host are not independent performance samples.

RSS snapshots are **not peak memory**. Disk figures sum logical and allocated
regular-file bytes, including block preallocation, databases, and logs. They
exclude directory/filesystem metadata and evidence JSON outside the node fixture.
Live directory walks are non-atomic observations, not exact simultaneous totals.
The 100 MiB fixture limit is checked at phase boundaries and after cleanup; it is
a sampled stop threshold, not an OS quota, and growth between checks is possible.
The controller also requires at least 1 GiB free before starting nodes.

Work has a 600-second monotonic budget checked around RPC calls, which themselves
retain the existing 15-second subprocess timeout. Individual controller startup,
peer agreement, propagation, and cleanup waits remain bounded. Cleanup may run
after the work budget expires. This is not a hard real-time guarantee against OS
failure or an uninterruptible process.

## Reproduce and limits

With the existing compiled QLU foundation and pinned environment:

```sh
.local/recovery-venv/bin/python qlu/payment_workload.py
```

Run without concurrent compilation or another laboratory test. Existing project
chains and wallets are not reset. Each attempt preserves its new data directory
and `.local/evidence/payment-workload-<uuid>.json`; `payment-workload-latest.json`
records the latest attempt, including a failure phase and cleanup status.
Failed and partial attempts are not performance results.
Failure output is restricted to a fixed public diagnostic allowlist: phase,
error class, traceback basename/line/function, cleanup and integrity status.
It excludes exception messages, source lines, local variables, and private paths.
That summary is printed even if final evidence-file publication fails.

This is a short fixed workload, not an endurance soak, hostile-network test,
wallet UI or payment-history benchmark, internet test, crash/power-loss durability
test, decentralization or finality proof, or production-capacity measurement.
The two restarts are controlled and graceful. Physical devices, independent
implementations, longer workloads, adversarial resource measurements, and
specialist review remain separate gates. No production readiness is established.
