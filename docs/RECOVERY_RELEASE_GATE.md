# Recovery portability release gate

QLU must support recovering the same signing authority across Mac, Windows,
Linux, iPhone, and Android before a public wallet release. This is a release
requirement, **not a statement of current support**. Minimum operating-system
versions and supported architectures must be named and tested before release.
All trials use disposable private-network coins with no monetary value.

## Current matrix

| Target | Required execution environment | Current status |
| --- | --- | --- |
| Mac, Apple silicon | Native application/tool on physical hardware | First Mac-to-Mac recovery/payment trial passed; full platform acceptance still pending |
| Mac, Intel | Native application/tool on physical hardware | Not run |
| Windows | Native Windows application/tool on physical hardware | Not implemented or run; WSL does not satisfy this row |
| Linux | Native application/tool on physical hardware; name distribution and architecture | Not run |
| iPhone | Native iOS wallet on a physical phone | No phone wallet yet; not run |
| Android | Native Android wallet on a physical phone | No phone wallet yet; not run |

The backup format in [QLU private v1](QLU_PRIVATE_V1.md) is platform-independent.
The current recovery CLI is not: it depends on Python, the pinned cryptography
environment, POSIX private-file protections, and a locally built `qlu-keytool`.
macOS/Linux are tooling targets, not a completed compatibility claim. Windows
requires native private-file handling; phones require wallet implementations and
appropriate device storage. A WSL, virtual-machine, emulator, simulator, or new
process result must remain labeled as such. None substitutes for physical-device
acceptance on its claimed platform.

## Acceptance matrix

1. Create a fresh disposable wallet and encrypted backup on **each** supported
   source platform. Keep recovery codes on separate offline storage. Preserve
   only the public key commitment and required public evidence alongside the
   encrypted backups; never publish seeds or codes.
2. Restore each source platform's backup on **every** supported target platform.
   This is an ordered source-to-target matrix, including same-platform recovery
   on another physical device with a fresh wallet installation. With the six
   rows above, there are 36 cells. Extra supported architectures add cells.
   A shared reference backup alone tests reading, not whether every platform
   creates interoperable backups.
3. Start without the original wallet, source-device account, local key files,
   cloud account, or VibexHQ service. The encrypted backup and separate recovery
   code must suffice. Confirm the exact same public keys, address, network,
   discovery metadata, and signing policy. Rediscover funded outputs.
4. Give every matrix cell its own unspent test output and challenge. The restored
   wallet must authorize an exact amount and recipient, with the declared fee,
   using **both ML-DSA-65 and Schnorr**. Verify and confirm that payment on the
   private network. Distinct outputs avoid treating conflicting spends of the
   same output as portability failures.
5. On every target, reject a wrong code, altered/truncated backup, wrong network,
   unsupported format/policy, and altered challenge. Check storage permissions,
   app logs, crash reporting, clipboard behavior, and exports for secret leaks.
   No password reset, platform account, or weaker signature may bypass recovery.
6. Record restore/signing duration and peak memory on named hardware, including
   phones. Report failures and unsupported combinations. Do not infer mobile
   performance from a desktop measurement.

## First MacBook trial

The first physical trial uses an encrypted test backup, a public spend challenge,
and a separately transferred recovery code. `qlu/device_recovery.py` restores in
memory and returns a signed response. It neither exports a seed nor requires
exposing node RPC to the MacBook. The origin computer checks the response against
its saved challenge and confirms the exact payment on the private chain.

Record the source and target OS/version, architecture, application/source and
native-tool versions, challenge fingerprint, key commitment, transaction ID,
confirmation result, and the operator's statement that a different physical
device was used. No serial number, hostname, account name, MAC address, or stable
device identifier is necessary. Platform metadata and signatures alone do not
prove different hardware; the physical-device claim relies on operator evidence.

The first trial [passed on 2026-10-19](MACBOOK_RECOVERY_RESULT.md): the original
Mac matched the transferred file fingerprint, checked both signatures and
confirmed the exact payment on all four nodes. Separate-device use was attested
by the user. The code was disclosed in chat at the user's request, so this trial
does not satisfy secret-custody/offline-code handling acceptance. Target discovery,
peak memory and the rest of the platform matrix also remain outstanding.
A same-computer rehearsal remains a rehearsal even if its operator-mode field
says `physical-device`. This first trial does not complete the release gate or
establish production security.
