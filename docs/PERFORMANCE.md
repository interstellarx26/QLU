# QLU private-network performance baseline

Measured 2026-10-19 America/Chicago (2026-10-20 UTC). **Passed locally; no public
throughput or phone-performance claim.** This host is an Apple M4, 16 GiB memory,
8 CPU cores, macOS 27.0.1, arm64. It is not the separate MacBook Air running 26.4.

## Results

| Operation | Median | Scope |
| --- | ---: | --- |
| Derive both public keys | 0.101 ms | Native, in process |
| Create both signatures | 0.419 ms | Native, includes key reconstruction and randomness |
| Verify both valid signatures | 0.092 ms | Native, excludes transaction digest construction |
| Sign a one-input payment | 9.64 ms | Current Python wallet plus native helper launches |
| Check a one-input payment | 4.77 ms | CLI, loopback RPC, policy and consensus checks |
| Check a 256-input proposed block | 195.07 ms | CLI/RPC and full validity check, excluding proof of work and persistence |

Native measurements use five batches of 1,000 operations per case, after 50 warm-ups
per case per batch. Every operation has an untimed correctness check; batch case
order rotates. Native valid verification p95 was 0.098 ms and p99 0.106 ms; signing
p95 was 1.073 ms and p99 1.535 ms. These tails describe the measured fixture pool,
not a worst-case bound. Rejection of a bad Schnorr signature measured 0.015 ms;
valid Schnorr with bad ML-DSA measured 0.092 ms.

### Payment size and wallet cost

Each shape has one output. Ten distinct transactions follow one full warm-up per
shape. Reported medians use the nearest-rank convention. Local acceptance checks
both policy and consensus signatures and does not broadcast or confirm a payment.

| Inputs | Serialized bytes | Weight-derived vbytes | Mempool effective vbytes | Sign median | Acceptance median |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5,462 | 1,436 | 1,560 | 9.64 ms | 4.77 ms |
| 4 | 21,683 | 5,584 | 6,240 | 23.47 ms | 7.32 ms |
| 16 | 86,567 | 22,174 | 24,960 | 81.76 ms | 17.60 ms |

The policy's verification-work allowance raises effective virtual size above
weight-derived size. Neither number establishes a future QLU fee. The large gap
between native signing and wallet signing identifies helper startup/communication
as one optimization opportunity; it does not justify changing cryptographic rules.
The 5.5 KB simple payment also makes bandwidth and storage important next measurements.

### Blocks

Three unique block proposals per size, with at most 16 inputs per transaction.
These small samples are exploratory; no reliable tail estimates are reported.

| Input authorizations | Transactions, excluding coinbase | Serialized bytes | Proposal check median |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 5,723 | 4.62 ms |
| 16 | 1 | 86,828 | 15.99 ms |
| 64 | 4 | 346,529 | 52.65 ms |
| 128 | 8 | 692,797 | 99.91 ms |
| 256 | 16 | 1,385,333 | 195.07 ms |

A 257-authorization proposal was rejected with `qlu-block-auth-limit`. The final
256-authorization block was solved and actually connected: submission took 191.99 ms,
followed by 240.23 ms until the controller observed the same tip on all four nodes.
Every new non-coinbase output was confirmed on every node. These are one-shot local
observations, including process/RPC/polling overhead, not independent peer samples,
production confirmation times, finality guarantees, or TPS.

The consensus limit is 256 authorizations. The stock block assembler's reserved
capacity and transaction packing can select fewer; the benchmark constructs a valid
block directly and does not claim that the assembler always fills the ceiling.

The post-run resident-memory snapshot was approximately 84 MiB for node 0 and 62 MiB
per peer. It is not peak memory or a long-running chain-storage measurement.

### Recovery

On this same host, 100 in-memory backup/restore samples had median encryption
0.031 ms and decryption/validation 0.028 ms. The encrypted backup was 767 bytes.
Ten restored-key derivations through the helper had median 4.16 ms. These warm-loop
timings exclude file transfer, human code entry, process startup, and chain discovery.

A separate fresh-process rehearsal restored the disposable wallet, produced a
signed response, and confirmed its payment on all four nodes. This remains a
**same-host rehearsal**. The first physical-device target is the user's MacBook Air
15-inch M4 (2025), 16 GB, macOS Tahoe 26.4. Its returned response subsequently
[passed origin verification and four-node confirmation](MACBOOK_RECOVERY_RESULT.md).
The target's single reported timing is recorded separately from this origin-host
benchmark. See the [MacBook guide](MACBOOK_RECOVERY.md) and the mandatory
[cross-platform release gate](RECOVERY_RELEASE_GATE.md).

## Reproduce and inspect

Use the configured release build and pinned recovery environment:

```sh
cmake --build build/qlu-foundation --target qlu-bench --parallel 2
.local/recovery-venv/bin/python qlu/benchmark.py
.local/recovery-venv/bin/python qlu/device_lab.py rehearse
```

The benchmark creates a new ignored data directory, mines fresh valueless rewards,
reads their actual amounts across the temporary subsidy halvings, and stops all
four owned nodes afterward. It holds the shared localhost port lock; stop other
QLU laboratory sessions first. Existing project chains and old q-chain folders are
not reset. Run measurements without simultaneous compilation or test workloads.

Raw evidence: `.local/evidence/performance-20261020T014523066194Z-b253e9cd.json`.
This records every timing sample, compiler/OpenSSL versions, host properties,
source-file fingerprints including untracked tools, binary fingerprints, setup,
limits, and stopped-node cleanup. `performance-latest.json` follows the latest
attempt, including failures/in-progress attempts. Base HEAD at measurement was
`ac3d5553cfd87b3d1c70417e360d52f900a26816`; the embedded file hashes identify the
working implementation actually measured. Later documentation/packaging edits
are not retroactively represented by that snapshot.

Rehearsal evidence:
`.local/device-tests/9da7d1031ff545598019e61e5f168586/receipt.json`.
One earlier benchmark failed because the controller preserves bitcoin-cli's empty
stdout representation of RPC null. The harness now recognizes that exact success
representation, while still rejecting all rejection strings. The failed report
is retained; it is not counted as a completed benchmark.

CPU frequency, scheduling, thermal state, and unrelated desktop load were not
controlled. The node paths include serialization and IPC overhead. QLU signature
checks remain enabled and do not use Bitcoin's successful-script cache. No
consensus, key derivation, signing, recovery encryption, or economic rule changed
for these measurements. Sustained load, hostile traffic, slower devices, independent
implementations and specialist security review remain outstanding.
