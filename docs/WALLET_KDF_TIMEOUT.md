# Bounded wallet password derivation

Private `qludev` milestone. A native encryption-library stall must fail wallet
creation, unlock or recovery within a bounded operation instead of trapping the
wallet process. This is availability hardening, not a new cryptographic scheme.

## Rules

1. Keep the v1 vault and backup formats, passphrase encoding, Argon2id costs and
   derived key unchanged: 16-byte salt, 32-byte key, 65,536 KiB, three iterations,
   four lanes. Existing vaults need no migration. There is no weaker fallback.
2. Execute one fresh helper through the current pinned Python interpreter in
   isolated mode. Its request is the 16-byte salt followed by at most 1,024
   passphrase bytes over anonymous stdin. The worker reads at most 1,041 bytes
   to detect excess input. Neither secret is a command argument, environment
   variable, file, diagnostic or test-report field.
3. Accept only exactly 32 result bytes, EOF and successful process exit. Read
   at most 33 bytes to detect oversized output; discard stderr. A short result,
   excess result, error exit, closed pipe or missed deadline fails the operation.
   Do not return partial keys or preserve child diagnostics in exceptions.
4. Use a single monotonic 15-second budget, including shared-gate waiting and
   helper communication/exit. Both import styles share the same gate, limiting
   this interpreter to one native derivation at a time. Queue expiry must not
   launch another helper. Independent wallet processes have independent gates.
5. Close pipes and kill/reap the owned helper on failure or cancellation, with a
   separate one-second cleanup budget. If the OS cannot reap it, retain its
   identity and refuse new helpers until it exits. Do not accumulate replacements.
6. Failed unlock leaves the session locked, and a failed derivation during
   creation or restoration publishes no destination vault. Existing files and
   payment journals remain unchanged. A subsequent deliberate retry uses the
   same normal checks; a failed password operation never submits a payment.

## Verification requirements

Test real child processes that stall, refuse input, emit too much output, return
short output, fail after writing a key, or stay alive after writing a key. Verify
deadline enforcement, child reaping, descriptor cleanup, queue expiry, shared
import gating and follow-up success. Cover cleanup failure with a controlled
process double and prove that new launches are refused while it remains alive.

Compare the helper with an independently generated fixed Argon2id result and
decrypt an existing-format vault fixture. Retain the concurrent creation test
requiring exactly one destination winner. Check create/restore publication and
failed re-unlock authority without weakening the encryption or file rules.

A disposable four-node drill injects helper faults into test wallets, verifies
that signing/broadcast and history changes do not occur on failed unlock, then
retries with the real helper. Remembered backup verification, wallet identity,
history and duplicate guards must survive. An explicitly reviewed payment must
confirm once on all four nodes, with the expected balance after restart.

## Limits

The deadline is enforced by the parent under normal OS scheduling. Process
creation, OS failure or an unkillable process can exceed a wall-clock target;
quarantine prevents further native helpers in that interpreter in that case.
This is not an OS watchdog or a global memory quota. Other wallet operations have
their own limits, and a waiting explicit lock can still wait for an operation
already holding the session mutex. The helper does not access the blockchain.
The controlling wallet process must remain alive to enforce its deadline and
cleanup. Abrupt parent termination (such as SIGKILL) or OS failure can orphan a
stalled helper; this implementation does not claim portable parent-death cleanup.

Python cannot guarantee erasure of passphrases, derived keys or wallet material.
Anonymous pipes and isolated imports do not protect a compromised OS, executable
or same-user debugger. The worker requires the installed pinned dependencies.
This milestone does not establish Windows or phone support, second-device
acceptance, audited security, public-network readiness or real-fund safety.
