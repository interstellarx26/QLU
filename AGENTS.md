# QLU project guidance

- This repository is the new QLU project. The three earlier q-chain folders are reference material only; never modify them as part of this repository's work.
- Current stage: pinned Bitcoin Core regtest laboratory. Do not describe upstream SHA-256/secp256k1 behavior as QLU, RandomX, or quantum-resistant behavior.
- Use `qlu/build.py` and `qlu/devnet.py` for local development. Node data, wallets, RPC cookies, and raw local evidence belong under ignored `.local/`, never in commits.
- Keep private-network defaults restricted to localhost and regtest. Do not connect this laboratory to public networks.
- Preserve upstream attribution and actual Git ancestry. Put QLU-specific tooling in `qlu/` and decisions in `docs/`.
- Prefer one scoped change at a time, with tests that verify its behavior. Record failures honestly; do not weaken assertions to get a pass.
- Consensus, signing, recovery, emission, and mining changes require explicit design documentation and independent review before a public release.
- The open chain must remain usable without VibexHQ services. Developer Cloud is an optional service business and must never require customer spending keys.
- Communicate briefly and plainly. Do not request approval again for work the user already authorized.
