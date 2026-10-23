# QLU engineering direction

Authorized direction: build QLU's blockchain, native coin and approachable wallet
under autonomous engineering leadership. All current work remains on the private
`qludev` network with valueless test coins. Earlier q-chain folders are reference
material and stay untouched. Public deployment is not part of this authorization.

The goal is useful, measurable innovation: ordinary people can receive, verify,
send and recover their own money without requiring VibexHQ to hold their keys.
Visual direction is VibexHQ gold, near-black and dark green. Ease of use must not
weaken payment authorization, recovery requirements or honest status reporting.

## Milestones and evidence

1. **Two-wallet payment clarity.** Verify and remember incoming payments, explain
   self-transfers, preserve existing history, and prove exact balances across
   independent wallets and process/node restarts. Test false claims, missing
   history, changed confirmations and duplicate checks. Current implementation
   scope is manual transaction-ID lookup; contact-based delivery comes later.
2. **Adversarial private-network reliability.** Expand controlled partitions,
   conflicting spends, stale-node and reorganization testing. Measure recovery,
   confirmation semantics and bounded resource use. Review the hybrid consensus
   paths and eliminate actionable security findings before adding public peers.
   The first bounded [conflict and recovery drill](NETWORK_RESILIENCE.md) covers
   actual 2+2 partitions, double-spend blocks, greater-work convergence, offline
   nodes and restart/replay safety. [Safe conflict resolution](PAYMENT_CONFLICTS.md)
   now uses bound original inputs and fresh competing-spend evidence to release
   new-payment guards reversibly; legacy records without evidence stay pending.
   [Wallet identity continuity](WALLET_IDENTITY.md) prevents a changed encrypted
   file from pairing new keys with the previously open wallet's history or
   payment approvals. [Interrupted payment recovery](INTERRUPTED_PAYMENTS.md)
   preserves exact authorized bytes for explicit review and resumption across
   process restarts; legacy records without those bytes remain conservative.
   Absence alone cannot clear a payment or authorize a replacement.
   [Bounded password derivation](WALLET_KDF_TIMEOUT.md) isolates native encryption
   work so a stalled helper cannot indefinitely trap wallet unlock or recovery.
3. **Measured protocol and mining design.** Benchmark hybrid verification, block
   propagation, storage and denial-of-service limits on documented hardware.
   The [bounded payment workload](PAYMENT_WORKLOAD.md) checks 32 real transfers,
   exact reward and fee accounting, two graceful node restarts and harmless
   replay of an already-confirmed payment. Its raw timing and resource samples
   describe a short four-node laboratory run, not public-network capacity.
   Evaluate CPU-oriented mining, fair launch, supply and difficulty with explicit
   threat models and simulations. Current SHA-256 regtest mining is not RandomX
   or final economics. CPU availability alone does not guarantee fair mining.
4. **Independent implementations and devices.** Test Mac, Windows, Linux and
   supported phones against common recovery/signature vectors and real device
   trials. Build signed, reproducible distribution and stronger live-key custody.
   A test on one Mac does not establish portability or resistance to malware.
   [Independent payment conformance](INDEPENDENT_CONFORMANCE.md) defines a bounded
   cross-implementation check of the existing hybrid rules, portable synthetic
   cases and reverse signature validation through private-node consensus.
   [Native input safety](NATIVE_INPUT_SAFETY.md) adds sanitizer-instrumented
   malformed key/signature and signing-helper input checks using the actual
   native sources. It does not establish full-node or OpenSSL-provider coverage.
5. **Consumer experience and developer infrastructure.** Add authenticated
   contact/payment-request flows with clear identity and recovery tradeoffs.
   Build optional Vibex Developer Cloud read APIs, usage metering and business
   payment tools without customer spending keys. Validate costs and demand before
   treating suggested subscription prices as an established business model.

Each milestone has a documented design, bounded implementation, automated tests,
fresh private-network evidence and scoped review. Preserve failures and fix their
causes. Independent specialist security review is a release gate, not a claim
that agent review alone establishes security. External review services that cost
money or receive source/material require a concrete scope before engagement.

No benchmark, fair-launch claim, quantum-proof claim, revenue guarantee or
world-changing claim should be published without supporting evidence. Public
testnet/mainnet, production economics and a launch decision remain separate gates.
