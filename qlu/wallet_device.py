#!/usr/bin/env python3
"""Human-terminal encrypted-wallet trial for disposable private QLU coins.

Physical mode waits a full five minutes. Platform, checks, and elapsed times are
local reports, not remote attestation. The origin node must verify the returned
payment. No payment is broadcast here. Python cannot guarantee secret erasure.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import secrets
import subprocess
import sys
import termios
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from . import device_recovery as device, wallet, vault
else:
    import device_recovery as device
    import wallet
    import vault

recovery = device.recovery
protocol = device.protocol
ROOT = protocol.ROOT
DEFAULT_VAULT = ROOT / ".local/wallet/restored.vault.json"
PHYSICAL_IDLE_SECONDS = 300
REHEARSAL_IDLE_SECONDS = 0.05
CHECKS = {"restored_encrypted", "identity_matches", "explicit_lock_blocks_signing",
          "wrong_passphrase_rejected", "fresh_session_starts_locked", "backup_readback_matches",
          "idle_lock_observed", "idle_lock_blocks_signing", "hybrid_payment_signed",
          "session_locked_on_exit"}
TOOLING_FIELDS = {"vault_sha256", "wallet_sha256", "wallet_device_sha256"}


class WalletDeviceError(device.DeviceRecoveryError):
    """A fixed-shape test or its public evidence failed validation."""


def wallet_tooling(root: Path = ROOT) -> dict:
    return {name + "_sha256": hashlib.sha256((Path(root) / "qlu" / (name + ".py")).read_bytes()).hexdigest()
            for name in ("vault", "wallet", "wallet_device")}


def _duration(value, *, maximum=3600):
    if type(value) not in (int, float) or not 0 < value <= maximum or not math.isfinite(value):
        raise WalletDeviceError("Invalid idle duration")
    return value


def _mode_idle(mode, idle_seconds):
    if mode not in device.MODES:
        raise WalletDeviceError("Unsupported test mode")
    _duration(idle_seconds, maximum=PHYSICAL_IDLE_SECONDS)
    if mode == "physical-device" and idle_seconds != PHYSICAL_IDLE_SECONDS:
        raise WalletDeviceError("Physical-device trials require the full five-minute idle interval")


def validate_result(envelope: dict, challenge: dict):
    """Validate public report structure; actual signatures require node consensus."""
    device._fields(envelope, {"format", "version", "response", "wallet_test"})
    if envelope["format"] != "qlu-wallet-device-response" or type(envelope["version"]) is not int or envelope["version"] != 1:
        raise WalletDeviceError("Unsupported wallet response format")
    test = envelope["wallet_test"]
    device._fields(test, {"checks", "idle_seconds", "observed_idle_seconds", "tooling"})
    device._fields(test["checks"], CHECKS)
    if any(value is not True for value in test["checks"].values()):
        raise WalletDeviceError("Wallet trial is incomplete")
    device._fields(test["tooling"], TOOLING_FIELDS)
    for value in test["tooling"].values():
        device._hex(value, 32)
    signed = device.validate_response(envelope["response"], challenge)
    _mode_idle(envelope["response"]["mode"], test["idle_seconds"])
    if _duration(test["observed_idle_seconds"]) < test["idle_seconds"]:
        raise WalletDeviceError("Idle interval was too short")
    if len(recovery._canonical(envelope)) > device.MAX_DOCUMENT_BYTES:
        raise WalletDeviceError("Wallet response is too large")
    return signed


def _fresh_destination(path):
    parent, name = recovery._open_parent(path)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise WalletDeviceError("A fresh output path is required")
    finally:
        os.close(parent)


class _Trial:
    """Keeps session authority and public state; never retains a password or code."""
    def __init__(self, challenge, path, mode, idle_seconds):
        self.tx, self.previous = device.validate_challenge(challenge)
        _mode_idle(mode, idle_seconds)
        self.challenge, self.path, self.mode, self.idle_seconds = challenge, Path(path), mode, idle_seconds
        self.session = None
        self.checks = {}
        self.keys = None
        self.crypto_seconds = 0.0
        self.restore_seconds = 0.0
        self.observed_idle_seconds = 0.0

    def close(self):
        if self.session is not None:
            self.session.lock()

    def _keys(self):
        started = time.monotonic()
        keys = self.session.public_keys()
        self.crypto_seconds += time.monotonic() - started
        return keys

    def _blocked_sign(self):
        try:
            self.session.sign(self.tx, [self.previous])
        except vault.VaultError:
            if self.session.locked:
                return
        raise WalletDeviceError("Locked signing was not refused")

    def restore(self, backup, code, passphrase):
        _fresh_destination(self.path)
        started = time.monotonic()
        self.session = vault.WalletSession.restore(self.path, backup, code, passphrase,
                                                  idle_seconds=self.idle_seconds)
        self.restore_seconds = time.monotonic() - started
        stored = recovery._parse(recovery.read_private(self.path), vault.MAX_VAULT_BYTES)
        if stored.get("format") != "qlu-local-vault":
            raise WalletDeviceError("Encrypted local wallet was not saved")
        self.checks["restored_encrypted"] = True
        self.keys = self._keys()
        if self.keys["key_commitment"] != self.challenge["wallet_commitment"]:
            raise WalletDeviceError("Restored identity does not match the challenge")
        self.checks["identity_matches"] = True
        self.session.lock()
        self._blocked_sign()
        self.checks["explicit_lock_blocks_signing"] = True
        wrong = "deliberately-wrong-" + secrets.token_hex(32)
        while wrong == passphrase:
            wrong = "deliberately-wrong-" + secrets.token_hex(32)
        try:
            self.session.unlock(wrong)
        except vault.VaultError:
            if not self.session.locked:
                raise WalletDeviceError("Rejected unlock retained authority") from None
        else:
            raise WalletDeviceError("Incorrect passphrase was accepted")
        finally:
            del wrong
        self.checks["wrong_passphrase_rejected"] = True
        self.session.lock()
        self.session = vault.WalletSession(self.path, idle_seconds=self.idle_seconds)
        if not self.session.locked:
            raise WalletDeviceError("Fresh session did not start locked")
        self.checks["fresh_session_starts_locked"] = True

    def verify(self, backup, code):
        if self._keys() != self.keys or self.session.verify_backup(backup, code) is not True:
            raise WalletDeviceError("Saved recovery materials do not match")
        self.checks["backup_readback_matches"] = True

    def observe_idle(self, wait_for_idle):
        # No session operations (including status polling) happen during this
        # interval. Measuring monotonic time rejects an accidentally short wait.
        started = time.monotonic()
        wait_for_idle(self.idle_seconds)
        self.observed_idle_seconds = time.monotonic() - started
        if self.observed_idle_seconds < self.idle_seconds or not self.session.locked:
            raise WalletDeviceError("The complete idle lock was not observed")
        self.checks["idle_lock_observed"] = True
        self._blocked_sign()
        self.checks["idle_lock_blocks_signing"] = True

    def finish(self):
        started = time.monotonic()
        signed = self.session.sign(self.tx, [self.previous])
        self.crypto_seconds += time.monotonic() - started
        self.checks["hybrid_payment_signed"] = True
        self.session.lock()
        if not self.session.locked:
            raise WalletDeviceError("Final wallet lock failed")
        self.checks["session_locked_on_exit"] = True
        response = {
            "format": "qlu-device-recovery-response", "version": 1,
            "challenge_id": self.challenge["challenge_id"],
            "challenge_sha256": device.challenge_hash(self.challenge),
            "network_id": protocol.NETWORK, "genesis_hash": protocol.GENESIS,
            "wallet_commitment": self.keys["key_commitment"],
            "signed_tx": signed.serialize_with_witness().hex(), "txid": signed.txid_hex,
            "mode": self.mode, "device": device._device(), "tooling": device._tooling(),
            # This legacy field includes direct encrypted-vault restoration and
            # is not a standalone portable-backup decryption microbenchmark.
            "timing_seconds": {"backup_decryption": self.restore_seconds,
                               "key_derivation_and_signing": self.crypto_seconds},
        }
        result = {"format": "qlu-wallet-device-response", "version": 1, "response": response,
                  "wallet_test": {"checks": dict(self.checks), "idle_seconds": self.idle_seconds,
                                  "observed_idle_seconds": self.observed_idle_seconds,
                                  "tooling": wallet_tooling()}}
        validate_result(result, self.challenge)
        return result


def recover_sign(backup: bytes, code: str, passphrase: str, challenge: dict, vault_path: Path,
                 *, mode="rehearsal", idle_seconds=REHEARSAL_IDLE_SECONDS, wait_for_idle=None) -> dict:
    """Automated disposable rehearsal only; the caller retains its test credentials.

    Physical trials must use the human-terminal runner, with re-entry instead of
    retaining the passphrase during the five-minute interval.
    """
    if mode != "rehearsal":
        raise WalletDeviceError("Automated recovery is only a same-host rehearsal")
    trial = _Trial(challenge, vault_path, mode, idle_seconds)
    try:
        trial.restore(backup, code, passphrase)
        trial.session.unlock(passphrase)
        trial.verify(backup, code)
        trial.observe_idle(time.sleep if wait_for_idle is None else wait_for_idle)
        trial.session.unlock(passphrase)
        return trial.finish()
    finally:
        trial.close()


def _wait_human(io, seconds):
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(60, remaining))
        remaining = deadline - time.monotonic()
        if remaining > 0:
            io.message(f"Idle test running: about {math.ceil(remaining)} seconds remaining. No wallet key operation is running.")


def _coins(value):
    return f"{value // 100000000}.{value % 100000000:08d}"


def run(io, backup_path: Path, challenge_path: Path, vault_path: Path, response_path: Path,
        *, mode="physical-device", idle_seconds=None, wait_for_idle=None) -> int:
    """Interactive IO seam; production callers use TerminalIO only."""
    trial = None
    try:
        idle_seconds = (PHYSICAL_IDLE_SECONDS if mode == "physical-device" else REHEARSAL_IDLE_SECONDS) if idle_seconds is None else idle_seconds
        _mode_idle(mode, idle_seconds)
        challenge = device.read_document(challenge_path)
        device.validate_challenge(challenge)
        # Fail before asking for secrets or waiting when output paths conflict.
        if Path(vault_path) == DEFAULT_VAULT:
            wallet._ensure_private_directory(ROOT / ".local")
            wallet._ensure_private_directory(DEFAULT_VAULT.parent)
        _fresh_destination(vault_path)
        _fresh_destination(response_path)
        if Path(vault_path).absolute() == Path(response_path).absolute():
            raise WalletDeviceError("Wallet and response need distinct destinations")
        backup = recovery.read_private(backup_path)
        io.message("QLU encrypted-wallet trial. Private qludev coins have no value; nothing is broadcast here.")
        io.message("Use a private terminal without recording. This program cannot verify terminal privacy or erase Python secret memory.")
        if mode == "physical-device":
            if io.prompt("Are you on a different physical computer from the origin? Type yes to attest: ").strip().casefold() != "yes":
                raise WalletDeviceError("Physical-computer statement was not confirmed")
        else:
            io.message("REHEARSAL ONLY: shortened idle interval on this host; this does not pass the physical-device gate.")
        io.message("New encrypted wallet file: " + str(vault_path))
        code = io.secret("Separate offline recovery code (hidden): ")
        passphrase = wallet._new_passphrase(io)
        trial = _Trial(challenge, vault_path, mode, idle_seconds)
        trial.restore(backup, code, passphrase)
        del backup, passphrase
        io.message("Encrypted wallet saved. Explicit lock and incorrect-passphrase checks passed. A fresh session starts locked.")
        trial.session.unlock(io.secret("Re-enter your new wallet passphrase (hidden): "))
        trial.verify(recovery.read_private(backup_path), code)
        del code
        io.message("Identity and saved backup checked. Leave this terminal open while the automatic idle lock is tested.")
        trial.observe_idle((lambda seconds: _wait_human(io, seconds)) if wait_for_idle is None else wait_for_idle)
        io.message("Full idle interval observed; the wallet is locked and refuses signing.")
        trial.session.unlock(io.secret("Unlock again with your new wallet passphrase (hidden): "))
        recipient = protocol.address_for({"key_commitment": challenge["recipient"]["script_pubkey"][4:]})
        io.message("Private test recipient: " + recipient)
        io.message("Amount: " + _coins(challenge["recipient"]["value_sat"]) + " QLU; fee: " + _coins(challenge["fee_sat"]) + " QLU.")
        if io.prompt("Authorize this exact private test payment? Type yes to sign: ").strip().casefold() != "yes":
            raise WalletDeviceError("Signing was not authorized")
        if trial.session.locked:
            io.message("The wallet locked while you reviewed the payment. Unlock to sign the same approved challenge.")
            trial.session.unlock(io.secret("Wallet passphrase (hidden): "))
        result = trial.finish()
        device.write_document(response_path, result)
        io.message("Public response saved: " + str(response_path))
        io.message("Wallet locked. Return only that response for origin-node verification. This device has not broadcast a payment.")
        return 0
    except (KeyboardInterrupt, EOFError):
        io.message("Cancelled. Any saved encrypted wallet is retained and locked. No completed response is claimed.")
        return 1
    except (ValueError, OSError, UnicodeError, RuntimeError, KeyError, subprocess.SubprocessError, termios.error):
        io.message("Wallet trial incomplete. Check the recovery materials, passphrase, native build, and fresh private paths. Any saved encrypted wallet is retained and locked; existing files are never replaced.")
        return 1
    finally:
        if trial is not None:
            trial.close()


def main(argv=None, *, io_factory=wallet.TerminalIO):
    parser = wallet.SafeArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, default=ROOT / "transfer/backup.json")
    parser.add_argument("--challenge", type=Path, default=ROOT / "transfer/challenge.json")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    parser.add_argument("--response", type=Path, default=ROOT / "wallet-response.json")
    parser.add_argument("--mode", choices=device.MODES, default="physical-device")
    args = parser.parse_args(argv)
    try:
        with io_factory() as io:
            return run(io, args.backup.expanduser(), args.challenge.expanduser(),
                       args.vault.expanduser(), args.response.expanduser(), mode=args.mode)
    except (wallet.WalletUIError, OSError, UnicodeError, termios.error):
        print("QLU wallet trial requires a private interactive human terminal. No secrets may be supplied as command arguments or redirected input.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
