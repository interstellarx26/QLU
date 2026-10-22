# Public source, private network

QLU's source can be published for review and collaboration while the software
remains an experimental localhost laboratory. Source publication is not a public
testnet, mainnet, coin sale, investment promise or production release. Valueless
test coins do not establish token economics. Optional VibexHQ infrastructure must
not become a requirement for using the open chain or accessing spending keys.

## Attribution and provenance

QLU is derived from Bitcoin Core v31.1 at the commit recorded in
[`qlu/upstream.json`](../qlu/upstream.json). The actual upstream Git ancestor,
MIT license, copyright notices and bundled dependency notices must be preserved.
The original Bitcoin Core README and security policy remain under `doc/`; its
contributor guide is retained below QLU's guidance in `CONTRIBUTING.md`.

Publish the reviewed QLU branch explicitly. Do not mirror every local ref, push
unrelated branches, or create an unrelated root commit containing copied upstream
files. A shallow development checkout may need upstream history fetched in a
separate publication checkout so the published branch has complete ancestry.

## Publication checks

- Review both current files and the QLU-added commit history for credentials,
  wallet material, private artifacts, personal paths and identifying metadata.
  If history needs sanitizing, use a separate publication copy and rewrite only
  QLU-added commits while retaining their exact upstream ancestor. Preserve the
  original local development history and private data.
- Stage source, tests, design documentation and intentional project metadata
  with an explicit file list. Inspect the staged diff and staged filenames.
  Never stage `.local/`, node data, builds, app bundles, backups, vaults, signed
  payment files, RPC cookies, raw evidence or exported recovery packages.
- Record the published revision and test results. Local success is not hosted
  CI success; hosted results must belong to that exact revision. Keep failed
  tests and unresolved limitations visible in the engineering status.
- Enable private vulnerability reporting and check the repository's security
  policy. Do not publish an unverified reporting address or response promise.
- Publish source without attaching development executables or wallet packages
  as a release. Distribution signing, reproducible packaging, platform support
  and independent security review are separate release work.

Automated pattern scans are useful checks, not proof that a repository contains
no sensitive data. Review findings and dependencies manually. `.gitignore`
prevents ordinary accidental additions; it does not remove files from history
or prevent forced additions.

## Current scope

The implementation combines experimental hybrid spending with local encrypted
wallets, backup verification, reviewed payments and conservative payment history.
The native UI is currently for macOS. Cross-platform recovery, public-network
hardening, economic parameters and RandomX remain separate work. The laboratory
uses SHA-256 proof of work.

Use [STATUS.md](STATUS.md) for measured results and current limitations,
[CONTRIBUTING.md](../CONTRIBUTING.md) for review expectations, and
[SECURITY.md](../SECURITY.md) for reporting guidance. Do not advertise the code as
audited, quantum-proof or ready to hold real funds.
