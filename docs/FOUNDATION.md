# Private-network foundation

The original stage 0 baseline is preserved, alongside the [QLU private v1 experiment](QLU_PRIVATE_V1.md). The source is Bitcoin Core **v31.1**, pinned to
`9be056a8a72b624dae9623b2f7bded92c2a21c91`. Source code was fetched directly from the official
Bitcoin repository using its annotated release tag. The official release index, GitHub release
API, and peeled tag agreed. A maintainer PGP signature has not been independently authenticated.
The initial fetch is shallow, retains the upstream commit identity, and can be deepened later.
The `upstream` remote is read-only in this workflow; nothing has been published.

## Preserved upstream baseline

- A repeatable local build of an identified upstream release.
- Four local regtest nodes with dedicated storage, cookie authentication, and loopback peers.
- Basic mining, transfers, synchronization, invalid-payment handling, and restart checks.
- A place for separate QLU design decisions and exact-version test evidence.

The baseline command `qlu/devnet.py` remains Bitcoin regtest. The separate `qlu/private_net.py`
controller runs QLU identity, hybrid authorization, and recovery experiments. See [status](STATUS.md)
for measured results. RandomX, production economics, contacts, and paid cloud APIs are not implemented.
No public genesis is being created; private test coins have no value.

## Build

Prerequisites: Python 3.10+, Git, CMake, C++20 compiler, Boost, libevent, SQLite, pkg-config, and OpenSSL >=3.5 with ML-DSA-65 in its default provider (locally tested 3.6.4).
On macOS, use matching Xcode/Command Line Tools and SDKs. The build helper selects these through
`xcrun`; it does not modify global toolchain settings. System packages are never installed by the helper.
Start with at least 6 GiB free for this release-only build; 15 GiB is preferable for later
sanitizer configurations, additional binaries, and longer network tests. Existing configured builds require at least 2 GiB for incremental work.

```sh
python3 qlu/build.py doctor
python3 qlu/build.py build --jobs 2
python3 qlu/build.py test --jobs 2
python3 -m venv .local/recovery-venv
.local/recovery-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r qlu/recovery-requirements.txt
.local/recovery-venv/bin/python -m unittest discover -s qlu/tests -v
.local/recovery-venv/bin/python qlu/private_net.py smoke
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

## Operate QLU private v1

Use `.local/recovery-venv/bin/python qlu/private_net.py setup|start|status|stop|smoke` (choose one
command). QLU data lives in `.local/qlu-private-v1/`, ports 28440–28443 and 28540–28543; every
listener/peer is loopback in this controller. The Bitcoin wallet RPC is disabled for QLU;
`qlu-keytool` and the prototype Python tools provide its distinct signing path. Raw node RPC
remains privileged local administration, not Developer Cloud.

Recovery CLI:

```sh
.local/recovery-venv/bin/python qlu/recovery.py --help
.local/recovery-venv/bin/python qlu/recovery.py create --help
.local/recovery-venv/bin/python qlu/recovery.py backup --help
.local/recovery-venv/bin/python qlu/recovery.py restore --help
```

Use private directories outside the old projects. Backup and offline-code files must be in
separate directories; for actual offline separation move the code to separate offline storage.
A prototype live wallet is a plaintext seed file protected by filesystem permissions. Never
use these development tools for real funds. The automated drill deletes only its own newly
created original wallet, then restores a new wallet in a separate process and spends normally.
It does not test a second physical device.

## Next implementation steps

1. Harden and benchmark the private hybrid construction: cross-implementation vectors, fuzzing,
   resource pricing, mobile measurements, failure injection and a genuine second-device recovery.
2. Design HD/address rotation and secure live-key storage before a consumer wallet.
3. Integrate identified RandomX code and difficulty/issuance rules as separately reviewed changes.
4. Add contact UX and Developer Cloud; independent public-testnet/security review before release.

Never transplant the entire old fork. Port useful regression cases with their original bug explanations.

Sources: [Bitcoin Core 31.1](https://bitcoincore.org/en/releases/31.1/),
[official source](https://github.com/bitcoin/bitcoin/tree/v31.1),
[macOS build guide](https://github.com/bitcoin/bitcoin/blob/v31.1/doc/build-osx.md).
