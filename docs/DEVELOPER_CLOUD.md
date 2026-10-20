# Vibex Developer Cloud

Status: business direction and phased roadmap; no commercial service or billing is live.

**Recommendation:** Position VibexHQ as a blockchain infrastructure company. Keep the QLU network open and the basic self-custody wallet free apart from network fees. Charge businesses for dependable infrastructure, data access, operational tools, and support. Users and developers must remain able to run their own nodes.

## Build the first service around a narrow customer need

Start with developers who need reliable QLU transaction submission, lookup, and confirmation status without operating nodes. Offer an allowlisted API backed by managed nodes; accept only already-signed transactions for submission. Keep customer signing keys outside VibexHQ.

Do not expose raw node administrator or wallet RPC methods to customers. Separate private node control from the public service. Add scoped API keys, revocation, quotas, rate limits, usage reporting, and spend caps before introducing paid access. Return confirmation depth and chain state rather than promising irreversible settlement. Document reorganization behavior.

Next, add indexed transaction data and authenticated webhooks when real customer needs justify them. Webhooks need retries, deduplication, reorganization notifications, and delivery visibility. Any “exactly once” business outcome must come from application-level idempotency, not a delivery promise.

## Pricing hypotheses, not published commitments

| Proposed tier | Monthly starting hypothesis | Intended customer |
| --- | --- | --- |
| Starter | Free | Learning, prototypes, and small experiments |
| Developer | $49 | Independent developers and early applications |
| Business | $299 | Production applications needing greater capacity and support |
| Enterprise | $2,000+ | Negotiated capacity, support, and service commitments |

Validate demand and unit costs before fixing plan limits, prices, or service guarantees. Meter **weighted work**, since a cached status lookup, historical index query, transaction submission, and webhook delivery have different costs. Measure compute, storage, bandwidth, indexing, operations, and support; publish the charging rules clearly.

Default to hard usage and spending limits. Offer paid overages only with explicit opt-in and a user-set cap, plus alerts before the cap is reached. Show miner fees separately from service charges. The private test laboratory is free and uses coins with no monetary value.

Free access plus paid usage is a reference model illustrated by [Alchemy's pricing](https://www.alchemy.com/pricing), not evidence that these proposed QLU prices will be profitable. Early development requires a separate budget; subscriptions become viable when customers have a useful network and reliable products to build on.

## Expansion order

1. **Developer Cloud:** Managed access, transaction status, measured usage, and developer documentation; indexed data and webhooks follow.
2. **Auto Pay API:** Business payouts, commissions, and creator earnings. Begin with customer-signed batches or a separately reviewed, limited authorization mechanism. Require idempotency, recipient checks, audit trails, and clear fee previews.
3. **AI Payments API:** Reuse those payment controls. Agents need explicit permissions, recipient restrictions, budgets, expiry, revocation, and duplicate-payment protection. Keep model-generated instructions separate from authority to spend. Seek confirmation for spending outside the granted limits.
4. **Verification and Identity APIs:** Separate products requiring privacy and trust design. Store minimal information and avoid placing personal data on a public chain. A blockchain record can attest who issued a claim and whether it changed; it cannot by itself establish that a real-world claim is true, identify a unique human, or prevent every bot.
5. **Blockchain as a Service:** Consider only after operating QLU reliably and finding paying demand. Bespoke chains multiply maintenance, security, and support obligations.

Measure success through active developers, reliable transaction delivery, retention, customer value, and sustainable margins. Coin-price appreciation is not the operating business model.
