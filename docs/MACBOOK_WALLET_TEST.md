# MacBook encrypted-wallet test

This is a fresh test of the encrypted working wallet on the MacBook Air M4,
macOS 26.4. It does not reuse the earlier spent recovery challenge or its
disclosed code. Coins have no monetary value. Preparation and a same-Mac
rehearsal are not a completed physical-device test.

## Simple steps for Manny

1. AirDrop the newly supplied wallet-test `.tar.gz` file to your MacBook.
2. Extract it into a new folder. Open that extracted folder in a new local Codex
   chat. Use the archive fingerprint supplied by the original Mac to verify it.
3. Have Codex finish the setup below and stop before asking for any secret.
4. In your own Terminal, run the test command Codex gives you. Enter the fresh
   recovery code from its separate offline copy, then choose a new wallet
   passphrase of at least 15 characters. Keep both out of chat and screenshots.
5. Follow the prompts. The automatic-lock check deliberately waits five minutes.
   Leave the MacBook awake. Enter the wallet passphrase again when asked, then
   approve the displayed **0.999 test QLU payment with a 0.001 QLU fee**.
6. Return only `wallet-response.json` and its SHA-256 to the original Mac.
   The test remains pending until that Mac verifies and confirms the payment.

The recovery code and daily passphrase are different secrets. The code restores
the backup; the passphrase opens the new encrypted file on the MacBook. The
archive contains neither. The original Mac retains the disposable code in a
private file outside the transfer package; the human must move it to separate
offline storage. Separate folders alone are not offline separation. Neither
Codex chat should read or display the code or the chosen passphrase.

## Setup instructions for the MacBook Codex chat

The user supplies the expected archive SHA-256 outside the archive. Verify that
original archive before executing its contents. Extract into a fresh private
folder and run the manifest verifier before builds/imports add files. A matching
internal manifest alone does not establish archive authenticity. Preserve old
projects and use only the files from this new kit.

Use a native arm64 Python, the MacBook's SDK, CMake, and OpenSSL 3.5 or newer.
Reuse working local dependencies; install only missing requirements. Build the
minimal helper locally, not a full node and not a binary copied from the origin.
Use the pinned Python dependencies and do not bypass hash or test failures.

From the freshly extracted kit root:

```sh
python3 qlu/package_device_kit.py verify --directory .
umask 077
mkdir -p .local
python3 -m venv .local/recovery-venv
.local/recovery-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r qlu/recovery-requirements.txt
cmake -S qlu/keytool-build -B build/qlu-foundation -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=26.4 "-DCMAKE_OSX_SYSROOT=$(xcrun --sdk macosx --show-sdk-path)" "-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)"
cmake --build build/qlu-foundation --parallel 2
ctest --test-dir build/qlu-foundation --output-on-failure --no-tests=error
.local/recovery-venv/bin/python -m unittest qlu.tests.test_recovery qlu.tests.test_device_recovery qlu.tests.test_vault qlu.tests.test_wallet qlu.tests.test_wallet_device -v
```

Report the setup results and prepare the next command for the human to run in
Terminal. Do not launch the secret-entry flow through a recorded automation
terminal, read a code file, or ask for secrets in chat. Do not modify the frozen
sources to force a pass. If setup fails, report the failure before proceeding.

## Human-run recovery and wallet checks

Run from the extracted kit root in your own Terminal, after setup passes:

```sh
.local/recovery-venv/bin/python qlu/wallet_device.py --mode physical-device
```

The target runner restores directly into a new encrypted vault, checks the
expected key commitment, verifies the backup again, tests explicit locking and
wrong-passphrase rejection, and reopens the encrypted file in a fresh session.
It then waits the full five minutes without a key operation, checks automatic
locking and rejected signing, and asks for the passphrase again. You review the
exact challenge and approve signing. It does not broadcast or require node RPC.
The session locks on exit. The encrypted vault stays local to the MacBook.

After the program reports a saved response:

```sh
shasum -a 256 wallet-response.json
```

Return only that response and its fingerprint. It contains a public signed
payment and test results; do not transfer the encrypted working vault, passphrase,
or recovery code back with it. If interrupted, preserve the created files and
report where it stopped. Existing vaults and responses are never overwritten;
a new run can use fresh destination paths.

## Origin verification and scope

The origin coordinator uses a new disposable `device_lab` session, funds its
fresh wallet, stores that authority in an encrypted origin vault, reopens it,
and verifies its portable backup. The daily origin passphrase is random and
not retained. Its independent recovery code is retained privately for the
human handoff. No plaintext seed file or source vault enters the archive.

The `encrypted-wallet-v1` source-kit profile adds the encrypted-wallet tools,
tests, this guide, and public `transfer/wallet-origin.json` provenance. It keeps
the original portable backup, challenge, and nested signing-response formats.
The origin wrapper freezes and compares wallet source fingerprints, rejects
shortened idle tests in physical mode, and confirms the nested payment with
the existing four-node coordinator. The original recovery modules and native
consensus rules are unchanged.

Origin commands for the engineer:

```sh
.local/recovery-venv/bin/python qlu/wallet_device_lab.py rehearse
.local/recovery-venv/bin/python qlu/wallet_device_lab.py prepare
.local/recovery-venv/bin/python qlu/package_device_kit.py create --session SESSION --profile encrypted-wallet-v1
.local/recovery-venv/bin/python qlu/wallet_device_lab.py check --session SESSION --response RETURNED_FILE --physical-device
```

Only the human can attest that a different physical computer was used. Platform,
timing, test flags, and source hashes in the returned report are self-reported;
they are not hardware attestation. Node verification establishes a valid exact
payment by the recovered authority. The shortened same-host rehearsal is labeled
as such and cannot satisfy the physical-device acceptance gate. This test is not
a specialist audit, a consumer app, or acceptance for Windows, Linux, or phones.

The nested response retains the legacy timing field names for compatibility.
Here `backup_decryption` includes recovery into encrypted vault storage, including
its password derivation; `key_derivation_and_signing` measures the relevant key
and signing operations. The idle wait is recorded separately. These values are
not directly comparable to the earlier in-memory recovery microbenchmark.
