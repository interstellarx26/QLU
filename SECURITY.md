# QLU security status

QLU is pre-release research and development. This checkout implements experimental QLU private-network identity, hybrid post-quantum spending, and encrypted recovery, alongside the original Bitcoin regtest laboratory. It has not received an independent specialist security audit and is not suitable for real-value funds. The live prototype wallet stores its seed in a restricted plaintext file; backup encryption does not protect a compromised running device.

During private development, report QLU-specific concerns directly to the project owner. No dedicated public QLU vulnerability-reporting address or response-time commitment has been established yet. Establish and verify that channel before public release. Do not include private keys, recovery codes, wallet files, or RPC cookies in public issues.

For vulnerabilities demonstrably affecting unmodified Bitcoin Core, follow its [upstream security policy](https://github.com/bitcoin/bitcoin/blob/v31.1/SECURITY.md). The preserved [upstream policy](doc/bitcoin-core-SECURITY.md) is reference material, not a QLU reporting contact.

Local tests and source reuse do not constitute an independent audit. The intended release process requires independent review of consensus, cryptographic integration, wallet backup/recovery, and adversarial network behavior.
