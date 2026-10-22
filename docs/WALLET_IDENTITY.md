# Wallet identity continuity on the private network

An open wallet must never combine one wallet's signing keys with another
wallet's payment history, backup-verification receipt or cached balance.
This milestone closes a file-replacement gap in the local wallet bridge.

## Selection and authentication

Open reads the encrypted file through the existing bounded private-file reader
and pins the SHA-256 digest of those exact bytes. This pin identifies the
selection; it does not authenticate or unlock anything. Create and Restore pin
the exact encrypted bytes produced by the authenticated session. A known public
key commitment is also retained for the lifetime of that selection.

Manual and idle locks preserve the public selection pin. Unlock first drops
the previous session's authority and cached availability. The vault reads once,
compares that blob against the pin, and decrypts those same bytes. The bridge
checks the authenticated digest and previously known commitment before
publishing keys, acquiring history, or trusting a saved verification receipt.
The digest is never taken from a second file read after authentication.

Changed ciphertext requires explicit Open again, including a re-encrypted file
with the same seed. A byte-identical, otherwise safe private copy is allowed.
On a detected change QLU closes the selection, locks the session, releases its
journal, and clears public keys, balance, network health, backup confirmation,
payment review and recent-payment state. Neither wallet file nor journal is
deleted or repaired. The user can explicitly select the replacement, authenticate
it and load that wallet's own existing history.

A wrong passphrase for unchanged bytes leaves the selection locked so it can be
retried, but drops cached authentication, availability and history association.
Failures during creation/restoration adoption also discard the session without
overwriting any existing wallet or history file.

## Journal ownership

Reused history must independently match the selected, authenticated public
commitment. This check runs before state publication, reconciliation, operation
replay and payment authorization. A mismatch closes access before any history
reconciliation or signing. The existing exclusive journal lock remains in use;
another instance must wait for its owner to close or exit. Lock files and pending
records are never removed to bypass ownership or uncertain-payment guards.

## Verification and limits

Tests use fresh private fixtures for A-to-B replacement, replacement between
selection and first unlock, same-seed re-encryption, byte-identical copies,
wrong-passphrase cleanup, independent history ownership, stale review rejection,
normal release and abrupt death of an actual journal-owning child process.
Native model tests cover clearing the selected wallet and its review after a
changed-file error. Live drills use four loopback nodes with valueless QLU.

This is session identity continuity, not continuous filesystem monitoring or
protection against a compromised same-user process or operating system. A file
changed after its authenticated bytes were read cannot replace the keys already
in memory; a subsequent unlock checks the selection again. Whole-directory
rollback, lost history and a pre-broadcast crash without a saved signed
transaction remain separate problems. Consensus, signatures, encryption formats,
portable recovery and mining economics are unchanged. See [STATUS.md](STATUS.md)
for measured results, including failures preserved before the fix.
