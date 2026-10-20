# QLU

A fresh, payments-first blockchain project by VibexHQ, with an optional developer-infrastructure business.

**Current stage: private-network foundation.** This repository currently builds unmodified Bitcoin Core 31.1 consensus for a four-node, localhost-only regtest laboratory. These are valueless test coins. QLU network identity, ML-DSA quantum-resistant authorization, RandomX mining, wallet recovery, and Developer Cloud are planned stages, not implemented features.

## Start here

- [Accepted blueprint](docs/BLUEPRINT.md)
- [Vibex Developer Cloud business direction](docs/DEVELOPER_CLOUD.md)
- [Build and private-network guide](docs/FOUNDATION.md)
- [Current verification and next work](docs/STATUS.md)
- [Pinned upstream provenance](qlu/upstream.json)

## Local workflow

Run from this repository with Python 3.10+ and the build dependencies in the foundation guide:

```sh
python3 qlu/build.py doctor
python3 qlu/build.py build --jobs 2
python3 qlu/build.py test --jobs 2
python3 -m unittest discover -s qlu/tests -v
python3 qlu/devnet.py smoke
```

The smoke test creates four private nodes, exercises test payments and synchronization, checks invalid-spend rejection and restart persistence, and stops its nodes. Use `setup`, `start`, `status`, and `stop` for manual laboratory operation. No existing wallet folders or previous q-chain projects are used.

Local node data, wallets, credentials, and test evidence are ignored under `.local/`. Do not publish them. The node's privileged RPC must never be exposed as a public cloud API.

## Engineering direction

Keep one upstream-derived repository, small reviewable changes, and tests attached to exact revisions. Introduce consensus changes separately. Keep the open network usable without VibexHQ services. Build optional paid infrastructure around developer needs, without taking customer spending keys.

The QLU workflow is `.github/workflows/qlu-foundation.yml`. It has not been run on hosted CI. Upstream's original broad workflow is preserved outside the workflow directory at `.github/upstream-ci.yml` for reference.

## Upstream and license

This is a fresh fork at the official Bitcoin Core v31.1 commit, not a copy of the previous QLU fork. The initial Git fetch is shallow; the commit identity and upstream relationship are preserved.

Bitcoin Core and this repository are distributed under the [MIT license](COPYING), subject to the notices of bundled dependencies. Original developer attribution remains in place. See [the upstream README](doc/bitcoin-core-README.md) and [official source](https://github.com/bitcoin/bitcoin/tree/v31.1).
