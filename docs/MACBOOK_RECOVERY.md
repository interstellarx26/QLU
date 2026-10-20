# First MacBook recovery trial

Target: MacBook Air 15-inch, M4 (2025), 16 GB, macOS Tahoe 26.4, with Codex.
Use only the disposable QLU private-network test coins. A successful local
rehearsal does not complete this physical-device test.

**First trial completed:** [origin verification and four-node confirmation passed](MACBOOK_RECOVERY_RESULT.md)
on 2026-10-19. The instructions below are retained for future freshly prepared
trials. Session `ed5cb43b67794073a0a5aaa9bf051f76` is complete; its challenge is
spent and its disclosed disposable code/keys must not be reused for real value.

## What to transfer

Copy the prepared `qlu-recovery-<session>-<revision>.tar.gz` source kit to the MacBook.
It contains the encrypted test backup, public payment challenge, exact source
files, license notices, and file fingerprints. Compare the archive's SHA-256
with the value supplied separately by the original Mac before extracting or
executing it. A checksum supplied only inside the archive is insufficient.
The kit verifier requires a pristine extraction: run it before builds or tests
create additional files. It rejects unlisted files that could replace imports.

Bring the recovery code separately on offline storage or enter it from its
offline copy. **Do not place the code in the kit, paste it into Codex/chat,
put it in a command, or return it with the response.** No source wallet is
needed on the MacBook.

Extract into a new local folder under `~/Developer`, with `umask 077` so files
remain private. Use the actual session filename supplied in the handoff; do not
overwrite an existing project. The unpacked root is `qlu-recovery-<session>`.

## Codex prompt for the MacBook

Copy this prompt into a new Codex chat on the MacBook after opening the extracted
kit folder. Replace the archive checksum placeholder with the separate value
from the original Mac. Do not include the recovery code in the prompt.

> This MacBook Air M4 is the second physical computer for QLU's disposable
> recovery test. The source kit archive SHA-256 from the original Mac is
> `<ORIGIN_ARCHIVE_SHA256>`. Verify the original archive against that checksum
> and run the kit file verification before executing the recovery code. Read
> `docs/MACBOOK_RECOVERY.md`, `docs/QLU_PRIVATE_V1.md`, and
> `docs/RECOVERY_RELEASE_GATE.md`. Build only the minimal native recovery helper
> here, using this Mac's SDK and OpenSSL 3.5 or newer; do not copy or use the
> original Mac's prebuilt binary. Install missing development dependencies as
> needed, then use the pinned Python requirements and run the native self-test
> and recovery tests. Preserve all existing projects and files. Prepare the
> interactive terminal command for me to enter the separately stored recovery
> code without displaying or recording it. Never ask me to paste that code into
> this chat or read it through a tool. Produce only the public `response.json`
> and tell me its path, test results, OS/architecture, and SHA-256. No public
> network or node RPC connection is needed. This is pending until the original
> Mac verifies the returned payment and confirms it on the private network.

## Setup commands for the target Mac

Run from the extracted kit root. These commands are for Codex or an experienced
operator; the recovery-code prompt at the end is for the human in a terminal.
Use an up-to-date Xcode Command Line Tools installation compatible with macOS
26.4. If Homebrew is not installed, set that up from its official instructions
before running its commands. Install only missing dependencies.

```sh
python3 qlu/package_device_kit.py verify --directory .
brew install cmake openssl@3 python@3.13
umask 077
mkdir -p .local
"$(brew --prefix python@3.13)/bin/python3.13" -m venv .local/recovery-venv
.local/recovery-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r qlu/recovery-requirements.txt
cmake -S qlu/keytool-build -B build/qlu-foundation -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=26.4 "-DCMAKE_OSX_SYSROOT=$(xcrun --sdk macosx --show-sdk-path)" "-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)"
cmake --build build/qlu-foundation --parallel 2
ctest --test-dir build/qlu-foundation --output-on-failure --no-tests=error
.local/recovery-venv/bin/python -m unittest qlu.tests.test_recovery qlu.tests.test_device_recovery -v
```

Stop if verification, installation, build, or a test fails. Do not bypass pinned
dependency hashes or choose weaker signing algorithms to make it work. The
minimal helper uses the same QLU cryptography and pinned upstream sources; it
does not build or launch a node. Its generic SHA-256 implementation preserves
the exact hashes and is not a network-performance benchmark.

Once setup passes, **the human** runs this command in a terminal on the MacBook
and enters the recovery code at the hidden prompt. If desired, disconnect from
the network after dependency setup; the signing step is fully offline.

```sh
.local/recovery-venv/bin/python qlu/device_recovery.py respond --backup transfer/backup.json --challenge transfer/challenge.json --response response.json --mode physical-device
shasum -a 256 response.json
```

Return only `response.json` and the MacBook test results to the original Mac.
The response contains the signed test payment and public device/tool details,
not the seed or recovery code. The original Mac validates the challenge,
both signatures, amount, recipient, and fee, then confirms the payment on four
private nodes. Only that completed check supports a successful second-device
claim. This MacBook result does not establish Windows, Linux, iPhone, or Android
compatibility; those remain separate release gates.
