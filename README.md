# QLU

A payments-first blockchain experiment by VibexHQ, with an optional developer-infrastructure business.

**Current stage: QLU private v1 prototype.** The separate `qludev` network implements its own identity, mandatory ML-DSA-65 + Schnorr spending, and an encrypted backup/recovery experiment. It runs four local nodes with valueless test coins. The earlier Bitcoin regtest baseline is preserved. This is unaudited development code; RandomX, production economics, contact-wallet UX, and Developer Cloud are later stages.

**Public source is not a public network launch.** This repository has no production
currency, investment offering or mainnet release. The native wallet is a macOS
development app. Windows, Linux and mobile wallet/recovery support remain release
gates, not completed compatibility claims. The laboratory uses temporary SHA-256
proof of work, not RandomX. See the [publication scope](docs/OPEN_SOURCE.md).

## Start here

- [Private v1 protocol rules](docs/QLU_PRIVATE_V1.md)
- [Accepted blueprint](docs/BLUEPRINT.md)
- [Vibex Developer Cloud business direction](docs/DEVELOPER_CLOUD.md)
- [Build and private-network guide](docs/FOUNDATION.md)
- [Current verification and next work](docs/STATUS.md)
- [Measured private-network performance](docs/PERFORMANCE.md)
- [Independent payment-signature checks](docs/INDEPENDENT_CONFORMANCE.md)
- [Native cryptographic input-safety checks](docs/NATIVE_INPUT_SAFETY.md)
- [Private peer-message resilience](docs/P2P_INPUT_RESILIENCE.md)
- [Encrypted wallet and guided recovery](docs/SECURE_WALLET.md)
- [Native Mac wallet app](docs/WALLET_APP.md)
- [Payment conflict and chain recovery rules](docs/NETWORK_RESILIENCE.md)
- [Wallet identity continuity](docs/WALLET_IDENTITY.md)
- [Interrupted payment recovery](docs/INTERRUPTED_PAYMENTS.md)
- [MacBook encrypted-wallet test steps](docs/MACBOOK_WALLET_TEST.md)
- [MacBook encrypted-wallet result](docs/MACBOOK_WALLET_RESULT.md)
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
.local/recovery-venv/bin/python -m pip install --require-hashes --only-binary=:all: --no-deps -r qlu/conformance-requirements.txt
.local/recovery-venv/bin/python -m unittest discover -s qlu/tests -v
.local/recovery-venv/bin/python qlu/conformance_smoke.py
.local/recovery-venv/bin/python qlu/private_net.py smoke
.local/recovery-venv/bin/python qlu/wallet_smoke.py
.local/recovery-venv/bin/python qlu/wallet_app_smoke.py
python3 qlu/devnet.py smoke
```

The QLU smoke test checks separate identity, both signatures, adversarial transactions and directly submitted blocks, network replay rejection, recovery after deleting the original test wallet, a restored-key payment, restart, and cleanup. The second smoke command separately checks the preserved upstream baseline. Use `setup`, `start`, `status`, and `stop` for manual laboratory operation. No existing wallet folders or previous q-chain projects are used.

Local node data, wallets, credentials, and test evidence are ignored under `.local/`. Do not publish them. The node's privileged RPC must never be exposed as a public cloud API.

For the guided encrypted-wallet flow, run `.local/recovery-venv/bin/python qlu/wallet.py`
yourself in a local terminal. Keep its passphrase and recovery code out of chat and logs.
This interface is private development tooling, not the consumer wallet app.

For the native Mac interface, build and open the project-bound development app
with `.local/recovery-venv/bin/python qlu/build_wallet_app.py --open`.
It adds guided screens, QR receiving, balance discovery, and reviewed test
payments through the existing encrypted wallet. See the
[app guide and limits](docs/WALLET_APP.md).

## Engineering direction

Keep one upstream-derived repository, small reviewable changes, and tests attached to exact revisions. Introduce consensus changes separately. Keep the open network usable without VibexHQ services. Build optional paid infrastructure around developer needs, without taking customer spending keys.

The QLU workflow is `.github/workflows/qlu-foundation.yml`. Hosted results must be
checked for the exact published revision; do not infer a passing build from the
workflow's presence. Upstream's original broad workflow is preserved outside the
workflow directory at `.github/upstream-ci.yml` for reference. See
[contribution guidance](CONTRIBUTING.md) and the [security policy](SECURITY.md).

## Upstream and license

This repository is based on the official Bitcoin Core v31.1 commit recorded in
[`qlu/upstream.json`](qlu/upstream.json). Preserve that actual upstream ancestor
when publishing QLU changes. Bitcoin Core's original networks and attribution
remain in the source; QLU-specific experimental rules apply to `qludev`.

Bitcoin Core and this repository are distributed under the [MIT license](COPYING), subject to the notices of bundled dependencies. Original developer attribution remains in place. See [the upstream README](doc/bitcoin-core-README.md) and [official source](https://github.com/bitcoin/bitcoin/tree/v31.1).
