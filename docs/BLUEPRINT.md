# QLU v1 blueprint

Status: accepted product direction; implementation is in a private laboratory; current protocol is [QLU private v1](QLU_PRIVATE_V1.md).

**Purpose:** Make everyday payments simple, protect ownership with quantum-resistant authorization, and make mining accessible through ordinary computers. VibexHQ builds infrastructure businesses can choose to pay for.

| Decision | Direction |
| --- | --- |
| Foundation | Begin with a pinned [Bitcoin Core](https://github.com/bitcoin/bitcoin) release. Preserve the original four-node upstream baseline and a separate QLU private development chain. See current protocol and status for implemented scope. |
| First product | Native payments and a simple self-custody wallet. Select a verified contact, enter an amount, review the recipient and fee, then send. Show pending and confirmed states. General-purpose smart contracts are outside v1. |
| Quantum resistance | Integrate [NIST-standardized ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) in an isolated, reviewed stage. Require quantum-resistant authorization for spending and recovery before a QLU launch. Choose parameters after benchmarking; review address commitments and all alternate spending paths. The separate QLU private v1 prototype now requires ML-DSA-65 AND Schnorr for every spend; parameter choice remains provisional until benchmarking and review. The preserved upstream laboratory has no such protection. |
| Recovery | Encrypted wallet backup plus a separately stored offline recovery code, with a guided restore test. Define and test the backup format before release. VibexHQ cannot reset access or spend users' funds. Loss of all usable access and recovery material can permanently lose funds. Guardian recovery comes later, after specialist review. |
| Mining and fair launch | Integrate [RandomX](https://github.com/tevador/RandomX) after the baseline is reproducible. No premine, presale, or reserved company allocation. Announce launch rules, code, and mining tools in advance; the team mines under identical rules. CPU accessibility does not equal equal rewards: hardware, electricity, and scale still matter. |
| Issuance | Model predictable declining rewards with a small permanent mining reward. Supply, reward amounts, timing, fees, and difficulty rules remain explicit design decisions until measured and published. Laboratory coins have no monetary value. |
| Company revenue | An open QLU network and free basic wallet, alongside optional paid **Vibex Developer Cloud** for reliable data access, infrastructure, and support. Network fees pay miners; disclosed service charges pay VibexHQ. No mandatory company gateway. See [the business roadmap](DEVELOPER_CLOUD.md). |

## First milestone and sequence

1. Establish a repeatable four-node local laboratory: generate blocks, send and confirm test payments, reject invalid spending, and check persistence after restart. Keep RPC and peer connections local. A later wallet milestone must separately prove backup restoration; a successful restart does not prove recovery from lost data.
2. Specify QLU's network identity and consensus changes, then implement and test each separately: ML-DSA authorization, RandomX, and economic parameters. Preserve an upstream baseline for comparisons.
3. Build the contact-based wallet experience and a narrow Developer Cloud prototype. Protect recipient mappings against impersonation and address substitution.
4. Require sustained public-testnet testing, independent security review, and reproducible releases before real-value use. Review network participation and mining concentration separately from code quality.

Use one authoritative repository and current specification, small reviewed changes, automated checks, and evidence tied to exact versions. Keep all previous project folders untouched as historical references. No mainnet launch or investment-return promises are part of this milestone.
