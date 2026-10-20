# Private-network foundation

This is stage 0 of the fresh QLU project. The source is Bitcoin Core **v31.1**, pinned to
`9be056a8a72b624dae9623b2f7bded92c2a21c91`. Source code was fetched directly from the official
Bitcoin repository using its annotated release tag. The official release index, GitHub release
API, and peeled tag agreed. A maintainer PGP signature has not been independently authenticated.
The initial fetch is shallow, retains the upstream commit identity, and can be deepened later.
The `upstream` remote is read-only in this workflow; nothing has been published.

## What this stage proves

- A repeatable local build of an identified upstream release.
- Four local regtest nodes with dedicated storage, cookie authentication, and loopback peers.
- Basic mining, transfers, synchronization, invalid-payment handling, and restart checks.
- A place for separate QLU design decisions and exact-version test evidence.

It **does not** implement QLU network identity, emission, ML-DSA, RandomX, contact payments,
recovery, or paid cloud APIs. The local coins have no value. Upstream Bitcoin rules and names
are intentionally retained while establishing the baseline. No public genesis is being created.

## Build

Prerequisites: Python 3.10+, Git, CMake, C++20 compiler, Boost, libevent, SQLite, and pkg-config.
On macOS, use matching Xcode/Command Line Tools and SDKs. The build helper selects these through
`xcrun`; it does not modify global toolchain settings. System packages are never installed by the helper.
Start with at least 6 GiB free for this release-only build; 15 GiB is preferable for later
sanitizer configurations, additional binaries, and longer network tests.

```sh
python3 qlu/build.py doctor
python3 qlu/build.py build --jobs 2
python3 qlu/build.py test --jobs 2
python3 -m unittest discover -s qlu/tests -v
python3 qlu/devnet.py smoke
```

Local outputs are in `build/qlu-foundation/`. Build transcripts and provenance are in
`.local/evidence/`; CTest also writes `build/qlu-foundation/qlu-ctest.xml`. Raw local artifacts
are ignored, and a concise reviewable result should be kept in `docs/STATUS.md`.

## Operate the laboratory

```sh
python3 qlu/devnet.py setup
python3 qlu/devnet.py start
python3 qlu/devnet.py status
python3 qlu/devnet.py stop
```

The controller owns only its `.local/devnet/` nodes. It must refuse conflicting listeners or
unrecognized processes rather than stopping them. P2P ports are 19440–19443 and RPC ports
19540–19543, all on 127.0.0.1. No default Bitcoin/QLU wallet directory is used. Configurations
disable peer discovery, seeds, Tor listening, NAT mapping, and private broadcast; explicit peers
are local. The controller disables runtime settings files so they cannot override these settings.
Node RPC is privileged and is **not** the future public Developer Cloud API.

Each smoke attempt writes a timestamped evidence file and updates `devnet-smoke.json` with the
latest result, including failures and cleanup. Records include the controller and node-binary
hashes, checkout revision, and tracked-change fingerprint. A passed restart check establishes
on-disk persistence only; backup restoration and the planned QLU recovery system need separate tests.

## Next implementation steps

1. Specify QLU chain identity, post-quantum spending rules, key derivation/backup format, and test vectors.
2. Integrate an identified ML-DSA implementation; test valid and invalid spending, encryption and recovery.
3. Integrate an identified RandomX release and difficulty rules; exercise adversarial header validation.
4. Add wallet/contact UX and tested recovery; then the independent public testnet and security review.

Never transplant the entire old fork. Port useful regression cases with their original bug explanations.

Sources: [Bitcoin Core 31.1](https://bitcoincore.org/en/releases/31.1/),
[official source](https://github.com/bitcoin/bitcoin/tree/v31.1),
[macOS build guide](https://github.com/bitcoin/bitcoin/blob/v31.1/doc/build-osx.md).
