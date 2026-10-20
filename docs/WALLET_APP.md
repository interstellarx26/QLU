# QLU private Mac wallet app

The first native Mac interface uses the existing encrypted wallet and the four
local QLU development nodes. Coins have no monetary value. This is a local
development app tied to this source checkout, not a public wallet release or
a portable installer.

## Scope and decisions

- Use native SwiftUI screens for creating, opening, backing up, restoring,
  receiving and reviewing payments. The receiving screen shows the exact QLU
  address and a QR code; contact names are a later feature.
- Keep the existing Argon2id/AES-GCM working vault, portable backup format and
  mandatory ML-DSA-65 plus Schnorr authorization unchanged.
- The Mac process launches the pinned Python wallet through private process
  pipes. There is no browser, HTTP wallet server, cloud account or public API.
  Only a bounded set of named operations is accepted. Errors must not repeat
  passwords, recovery codes, raw requests or private keys.
- Passphrases and recovery codes enter native secure fields. A newly created
  recovery code is displayed for the person to record separately from the
  encrypted backup. It is not automatically copied or saved by the app.
  No app can prove that a screen, keyboard, clipboard or computer is private.
  Swift and Python do not guarantee secret-memory erasure.
- Creation saves a new encrypted wallet and requires a saved-backup readback
  check before receiving or sending. Restoration creates another encrypted
  file directly and verifies the supplied backup. Existing wallets and backups
  are never overwritten. Reopening a wallet requires checking its backup again
  in this first interface; no persistent backup-safety claim is inferred.
- Locking, expiration, switching wallets and quitting invalidate an outstanding
  payment review. Status polling must not extend the five-minute key deadline.
  The native interface requests a lock on focus loss, hiding, minimizing and
  system sleep; an unlock response arriving while inactive is relocked.
- Sending first validates a QLU development address and exact decimal amount,
  then selects confirmed mature inputs and presents the recipient, amount,
  fee and total. A review expires after two minutes and can be used only once.
  Confirmation rechecks the inputs and requires an unlocked wallet.
- The fixed fee of 0.001 test QLU and a button to obtain 1 test QLU are laboratory
  conveniences, not production fee or issuance rules. The app owns a separate,
  persistent four-node data directory and the existing laboratory port lock.
  Starting it must never take over nodes belonging to another test.
- A successful send requires the exact payment to confirm on all four nodes.
  A failure after a possible broadcast must retain the transaction identifier
  and report uncertainty rather than encourage another payment.
  The interface blocks further sends for that uncertain session. Recent activity
  is currently held in memory, and automatic reconciliation is not implemented.
  Keep a reported transaction ID for engineering verification before retrying,
  including after restarting the app. A transport failure may occur before the
  interface receives the transaction ID; it must still warn of an unknown outcome.
- Node startup is an explicit app action. Normal shutdown locks the wallet and
  stops owned nodes. A forced process kill, system crash or failed cleanup may
  require investigation; startup must fail safely instead of adopting or
  force-killing an unknown process.

## Local build

With the foundation binaries and pinned Python environment already built:

```sh
.local/recovery-venv/bin/python qlu/build_wallet_app.py --open
```

The output is `build/qlu-wallet/QLU Wallet.app`. Its local ad-hoc signature is not
Apple notarization or a developer distribution signature. Its embedded project
path points to this checkout, including Python and native dependencies; moving
the app to another Mac does not install those dependencies. A UI deployment
target does not establish minimum-OS compatibility for the whole wallet.

Managed encrypted wallets live under `.local/wallet-app/wallets/`. The person
chooses where to save an encrypted portable backup. Keep the recovery code on
separate offline storage. Existing disclosed test codes and passwords must
never be reused for this app.

## First use

1. Choose **Create a wallet** and enter a new private passphrase twice.
2. Choose **Save new backup**, save the encrypted file, and write down the
   displayed recovery code separately offline.
3. Choose **I saved my code**, enter that code, and choose **Verify backup**.
4. From **Wallet**, choose **Start network**, then **Add 1 test QLU**.
5. Use **Receive** to share the address or QR with another wallet on this same
   local network. **Send** requires the full address and an amount, followed by
   **Review payment** and **Confirm and send**.

Quit normally to lock the wallet and stop its nodes. The current interface asks
you to open and unlock your wallet and verify its backup again after relaunch.
The faucet has no persisted signing key: after restarting it may mine additional
temporary development blocks. Eventually those temporary halving rules can
exhaust its ability to provide another whole test coin; the app will report that
without deleting or resetting the chain.

## Required checks

Verify malformed and oversized requests, error redaction, backup gating,
wrong passphrases, locked signing, idle behavior without polling extending it,
exact amount/address parsing, stale inputs, review expiration and replay,
wallet switching, cleanup, and uncertain-broadcast reporting. Exercise the
bridge against actual four-node payments and a restored encrypted wallet,
and inspect the native screens.

Local result: 256 Python tests and ten actual four-node bridge checks passed.
The native bundle compiled, its ad-hoc signature verified, and UI inspection
exercised opening/unlocking an isolated fixture, backup file selection and
verification, QR display, test funding, payment review, a confirmed self-payment
and shutdown. Creation and restoration were exercised through the real bridge;
their complete human native-screen flows remain follow-up acceptance. The
final hide/minimize handlers typechecked; background unlock relocking was
observed, while a foreground human hide/minimize trial remains pending.

MacBook transfer, secret-custody acceptance, other operating systems,
hardware-backed storage, independent cryptography/operational review and the
full [recovery matrix](RECOVERY_RELEASE_GATE.md) remain separate gates. See
[current status](STATUS.md) for evidence actually collected.

Native interface references: [Apple SecureField](https://developer.apple.com/documentation/swiftui/securefield)
and [Foundation process output](https://developer.apple.com/documentation/foundation/process/standardoutput).
