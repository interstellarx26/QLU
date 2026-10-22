# QLU security status

QLU is pre-release research and development. It implements experimental private-network identity, hybrid ML-DSA-65 and BIP340 Schnorr spending, encrypted wallet storage, and portable recovery, alongside a preserved Bitcoin regtest laboratory. It has not received an independent specialist security audit and is not suitable for real-value funds. Publishing the source does not launch a public network or establish production support.

The native wallet stores its local vault encrypted and keeps unlocked signing material in the local process. Older laboratory harnesses may create disposable plaintext fixture keys under ignored `.local/`. Encryption does not protect a compromised running device, and this Python prototype does not guarantee secret-memory erasure. Recovery needs the encrypted backup and its separate recovery code; VibexHQ has no key-recovery override.

## Reporting a concern

Use this repository's **Security → Report a vulnerability** option for QLU-specific concerns when private vulnerability reporting is available. Include the affected revision, platform, a description of the issue, and a minimal reproduction using disposable fixtures. Do not include genuine wallet material, credentials or personal data.

If private reporting is unavailable, open a public issue asking the repository owner to establish a private reporting channel, without exploit details or sensitive attachments. No dedicated QLU security email, response-time guarantee or bug-bounty program is currently established. Never post spending keys, recovery codes, passphrases, encrypted wallet files, signed payment files or RPC cookies publicly.

For vulnerabilities demonstrably affecting unmodified Bitcoin Core, follow its [upstream security policy](https://github.com/bitcoin/bitcoin/blob/v31.1/SECURITY.md). The preserved [upstream policy](doc/bitcoin-core-SECURITY.md) is reference material, not a QLU reporting contact.

Local tests and source reuse do not constitute an independent audit. The intended release process requires independent review of consensus, cryptographic integration, wallet backup/recovery, and adversarial network behavior.

## Scope

Use only localhost laboratory nodes and valueless `qludev`/regtest coins with the documented tooling. Do not expose privileged node RPC as a public API. The current peer checks and four-node receipts are private laboratory checks, not a claim of Byzantine security, economic finality or independent light-client verification. Only tested behavior may be described as quantum-resistant; do not describe QLU as quantum-proof, audited or production-ready.
