# QLU encrypted wallet foundation

Private development only. Test coins have no value. This adds local wallet
storage and a guided terminal interface; it does not change the chain, keys,
signatures, or portable recovery format. It is not a public wallet release.

## Decisions

- **Daily access:** a separate unlock passphrase encrypts the working wallet.
  Use a long, unique passphrase. The interface requires at least 15 characters,
  with a maximum of 1,024 UTF-8 bytes. It preserves spaces and Unicode exactly;
  it does not normalize or trim a passphrase. Length alone does not establish
  strength. The offline recovery code is not a daily passphrase.
- **Storage:** Argon2id derives a 32-byte key with a fresh 16-byte salt, 65,536
  KiB memory, three passes, and four lanes. AES-256-GCM encrypts the complete
  validated wallet with a fresh 12-byte nonce. A versioned, authenticated header
  binds its algorithm parameters, network, genesis, and signing policy. Unknown
  fields, versions, changed costs, malformed encodings, and oversized files are
  rejected before expensive work. There is no weaker fallback.
- **Files:** the vault is an immutable encrypted file. Creation publishes a
  complete, flushed file atomically without replacing an existing destination.
  Private files use restrictive permissions and reject unsafe paths, symlinks,
  and hard links. Recovery creates a new encrypted vault directly; it never
  writes a plaintext wallet or temporary plaintext seed to disk. To choose a
  new passphrase, recover into a new vault. Existing copies still work with
  their old passphrases; this does not revoke keys or erase old copies.
  An interrupted publication can leave a complete encrypted destination; a crash
  between linking and removing the temporary name can leave two encrypted links,
  which the reader safely refuses. A failure is never reported as successful
  setup. Preserve those files; do not overwrite them. Use a verified backup and
  a new destination if restoration is needed.
- **Lock:** opening an existing vault starts locked. Creation and recovery retain
  the authenticated session until locked or expired. Successful unlock holds keys in process
  memory; explicit lock, normal exit, and five minutes of idle time release the
  session's secret references. Five minutes is the interface's fixed setting and
  the library's default; the library permits an explicit timeout up to one day.
  A timer and operation-time checks enforce the
  idle deadline. An operation already holding the session mutex can finish
  before a waiting lock takes effect; the next operation checks the deadline.
  Signing, backup, and deriving the receiving identity require
  an unlocked session. Python cannot guarantee memory erasure or protection
  from swap, crash dumps, malware, debugging, or another process under the same
  user. This is not a hardware-backed key store.
- **Backup:** the existing encrypted portable backup and independent random
  recovery code stay compatible with the prior MacBook experiment. The guided
  creation flow saves the backup, reads it back, and asks for the code again to
  verify recovery before showing the receiving address. Interrupted setup can
  resume through the existing encrypted vault's backup action. Verification
  proves that those materials match; it cannot prove safe offline storage.
- **Recovery:** choose the encrypted backup, enter the recovery code privately,
  and select a new daily passphrase. No source computer, VibexHQ account, company
  master key, weaker signature, or password-reset service is involved. Restoring
  cannot revoke a stolen wallet. Suspected key theft requires fresh keys and a
  transfer, not merely a new passphrase.

The guided tool uses a real terminal. It refuses redirected or echoing secret
input. Terminal checks cannot prove human control or absence of recording.
Passphrases and recovery codes are never command arguments or log output.
The newly generated recovery code must be shown to the person making the backup;
it is displayed only on the controlling terminal and may remain in terminal
scrollback or screen recordings. Keep it out of chat, screenshots, logs, and
clipboard history. Store it offline, separately from the encrypted backup.

## Use on this private Mac

From the QLU project, run:

```sh
.local/recovery-venv/bin/python qlu/wallet.py
```

Follow the prompts to create, open, back up, lock, unlock, or recover. The default
encrypted wallet is under ignored `.local/wallet/`. Recovery must use a new file,
so it cannot overwrite a working wallet. The default recovery flow suggests a
new destination when the existing wallet is present. The first interface is a guided terminal
tool, not the future consumer app. Signing is provided through the wallet core;
this interface does not broadcast payments or expose a network service.

Older protocol/benchmark fixtures still explicitly use disposable plaintext
wallets. They are not migrated automatically, and the historical device kit is
unchanged. Use the new tool for the new encrypted-wallet flow. Do not reuse the
disclosed recovery code or spent challenge from the earlier physical test.

## Verification and release boundary

Required local checks cover real password derivation, wrong credentials,
authenticated tampering, bounded parsing before derivation, private-file safety,
interrupted/existing/concurrent creation, lock and expiry, guided backup readback,
cancellation, and failure output without secrets. A fresh four-node drill must
fund the encrypted wallet, reject locked signing, close the original session,
restore in a new process directly into an encrypted vault, rediscover its output,
sign with both algorithms, and confirm a payment on every node and after restart.
That drill is on one physical Mac; it does not count as a new second-device test.

Native Windows file protections, physical phone wallets, the full recovery
[platform matrix](RECOVERY_RELEASE_GATE.md), desktop/mobile performance and memory
measurements, hardware-backed custody, and independent specialist review remain
public-release gates. The old MacBook backup test does not establish acceptance
of this newly added encrypted live-wallet implementation. Local automated checks
and agent review are not a specialist security audit.

Implementation references: [cryptography Argon2id](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#argon2id),
[cryptography AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM),
and [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html). Parameters above are a
fixed private-format decision; target hardware must be measured before release.
