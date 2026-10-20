# QLU

A fresh, payments-first blockchain project by VibexHQ, with an optional developer-infrastructure business.

**Current stage: QLU private v1 prototype.** The separate `qludev` network implements its own identity, mandatory ML-DSA-65 + Schnorr spending, and an encrypted backup/recovery experiment. It runs four local nodes with valueless test coins. The earlier Bitcoin regtest baseline is preserved. This is unaudited development code; RandomX, production economics, contact-wallet UX, and Developer Cloud are later stages.

## Start here

- [Private v1 protocol rules](docs/QLU_PRIVATE_V1.md)
- [Accepted blueprint](docs/BLUEPRINT.md)
- [Vibex Developer Cloud business direction](docs/DEVELOPER_CLOUD.md)
- [Build and private-network guide](docs/FOUNDATION.md)
- [Current verification and next work](docs/STATUS.md)
- [Measured private-network performance](docs/PERFORMANCE.md)
- [Encrypted wallet and guided recovery](docs/SECURE_WALLET.md)
- [MacBook recovery test](docs/MACBOOK_RECOVERY.md)
- [Cross-platform recovery release gate](docs/RECOVERY_RELEASE_GATE.md)
- [Pinned upstream provenance](qlu/upstream.json)

## Local workflow

Run from this repository with Python 3.10+, OpenSSL 3.5+ (tested 3.6.4), and the build dependencies in the foundation guide:

```sh
python3 qlu/build.py doctor
python3 qlu/build.py build --jobs 2
python3 qlu/build.py test --jobs 2
python3 -m venv .local/recovery-venv
.local/recovery-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r qlu/recovery-requirements.txt
.local/recovery-venv/bin/python -m unittest discover -s qlu/tests -v
.local/recovery-venv/bin/python qlu/private_net.py smoke
.local/recovery-venv/bin/python qlu/wallet_smoke.py
python3 qlu/devnet.py smoke
```

The QLU smoke test checks separate identity, both signatures, adversarial transactions and directly submitted blocks, network replay rejection, recovery after deleting the original test wallet, a restored-key payment, restart, and cleanup. The second smoke command separately checks the preserved upstream baseline. Use `setup`, `start`, `status`, and `stop` for manual laboratory operation. No existing wallet folders or previous q-chain projects are used.

Local node data, wallets, credentials, and test evidence are ignored under `.local/`. Do not publish them. The node's privileged RPC must never be exposed as a public cloud API.

For the guided encrypted-wallet flow, run `.local/recovery-venv/bin/python qlu/wallet.py`
yourself in a local terminal. Keep its passphrase and recovery code out of chat and logs.
This interface is private development tooling, not the consumer wallet app.

## Engineering direction

Keep one upstream-derived repository, small reviewable changes, and tests attached to exact revisions. Introduce consensus changes separately. Keep the open network usable without VibexHQ services. Build optional paid infrastructure around developer needs, without taking customer spending keys.

The QLU workflow is `.github/workflows/qlu-foundation.yml`. It has not been run on hosted CI. Upstream's original broad workflow is preserved outside the workflow directory at `.github/upstream-ci.yml` for reference.

## Upstream and license

This is a fresh fork at the official Bitcoin Core v31.1 commit, not a copy of the previous QLU fork. The initial Git fetch is shallow; the commit identity and upstream relationship are preserved.

Bitcoin Core and this repository are distributed under the [MIT license](COPYING), subject to the notices of bundled dependencies. Original developer attribution remains in place. See [the upstream README](doc/bitcoin-core-README.md) and [official source](https://github.com/bitcoin/bitcoin/tree/v31.1).
