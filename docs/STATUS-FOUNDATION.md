> Historical stage-0 report. Current implementation status is in STATUS.md.

# Foundation status

Date: 2026-10-19 (America/Chicago).

**Stage 0 is built and verified: a four-node, localhost-only Bitcoin regtest laboratory.**
The nodes are stopped after verification. Test coins have no value.

## Project and provenance

- Active checkout: `$HOME/Developer/QLU`, branch `qlu/main`.
- `$HOME/Documents/ChatGPT/QLU` links to that checkout.
- Upstream: Bitcoin Core v31.1, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`.
- Verified implementation: `25e60ec4e7952b5c461a5d198db82930476f9b72`. Subsequent status-document edits do not change the tested code.
- The engine, upstream test sources, and upstream build definitions match the pinned release. Upstream Git ancestry and MIT attribution are retained.
- Release identity was checked against official HTTPS sources; the maintainer PGP signature has not been independently authenticated.

## Results

| Check | Observed result |
| --- | --- |
| Fresh release configuration and build in the active folder | Passed, exit status 0 |
| Registered upstream CTest entries | **152 passed, 0 failed, 1 skipped** |
| QLU controller safety tests | **23 passed** |
| Two consecutive real-node smoke runs using the freshly built node | **Both passed**, with complete source and binary fingerprints |
| Final process state | All four owned nodes stopped; private ports available |

Each smoke run verifies four regtest nodes, a complete loopback peer mesh, payment propagation
to all mempools and confirmation, rejection of a transaction spending nonexistent coins,
chain and wallet persistence across restart, and cleanup. Existing laboratory data was reused.

The skipped upstream entry is `script_assets_tests`: its external corpus was not configured
(`DIR_UNIT_TEST_DATA` unset). The full upstream Python functional suite, sanitizers, hosted
Linux/macOS CI, public-network operation, and backup restoration were **not** run. Restart
persistence is not evidence of recovery after losing wallet data.

## Evidence and setup fixes

Machine-readable results are in ignored `.local/evidence/verification-summary.json`. Supporting
records include the `20261020T004954248915Z-build` log/JSON pair, the
`20261020T005443033391Z-ctest` pair, `controller-tests.log` and `.json`, and smoke attempts
`20261020T005332268404Z-3254f227` and `20261020T005339846979Z-1850ef4b`.
CTest also writes `build/qlu-foundation/qlu-ctest.xml`.

Verified node binary SHA-256:
`646c32dec2891a790ece17259de3ce629b89ae2c1edb0b218e6bb94046d7a64d`.

An early repeat run exposed insufficient inbound connection capacity. The controller now
allows enough connections and requires handshakes with all three distinct owned peers before
starting network checks. It also synchronizes existing tips before mining. Regression tests
cover partitions, duplicate peers, incomplete handshakes, and wrong chain tips.

The initial Documents checkout experienced intermittent file-read and directory-move stalls.
The exact OS cause is unconfirmed. A fresh checkout at the same upstream pin in the development
folder, with all QLU changes and stopped-node data preserved, built and verified successfully.
Provenance commands now have bounded timeouts and record failure before starting nodes.
Earlier failed attempts remain in the evidence directory. The initial setup copy and its local
history are preserved at `$HOME/Documents/ChatGPT/QLU-setup-archive-20261019`,
clearly marked as an archive. All three supplied q-chain reference folders remain untouched.

With permission, rebuildable npm, uv, and Homebrew caches were removed, recovering approximately
7.12 GiB before the new builds. Approximately 6.75 GiB remained at final verification.

The verified host is macOS 27.0.1 on ARM64, using Apple Clang 21 and the macOS 26.5 SDK.
The linker reported that installed libevent libraries target macOS 27, plus duplicate-library
warnings. Execution passed on this host; compatibility with older Macs and reproducible release
binaries are not established.

## Next milestone

Specify QLU network identity, ML-DSA spending and recovery rules, key derivation, backup format,
and test vectors before changing consensus. Then integrate and measure those changes separately
from RandomX and issuance parameters.

QLU consensus, quantum-resistant signatures, RandomX, wallet recovery, Developer Cloud, billing,
public testnet, and mainnet remain **unimplemented**. The business direction is documented in
[Developer Cloud](DEVELOPER_CLOUD.md); no commercial service or pricing has been launched.
