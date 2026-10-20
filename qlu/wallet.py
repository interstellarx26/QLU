#!/usr/bin/env python3
"""Guided private QLU wallet. Human terminal only; no payment broadcast UI.

Passphrases and recovery codes are never command arguments, environment values,
or redirected output. The portable recovery code is displayed only on the
controlling terminal, where terminal scrollback/recording can still retain it.
Python cannot guarantee secret-memory erasure. Use disposable qludev coins only.
"""
from __future__ import annotations

import argparse
import getpass
import hmac
import io
import os
from pathlib import Path
import secrets
import stat
import sys
import termios
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parent))
if __package__:
    from . import recovery, vault
else:
    import recovery
    import vault

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WALLET = ROOT / ".local/wallet/wallet.vault.json"
IDLE_SECONDS = 300


class WalletUIError(ValueError):
    """A wizard operation failed without revealing entered material."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        # Users may accidentally try a secret-bearing option. Never echo its
        # value through argparse's usual unknown-argument diagnostic.
        self.exit(2, "QLU wallet command is invalid. Use --help; enter secrets only at the hidden terminal prompts.\n")


class TerminalIO:
    """All interactive input/output goes to an opened controlling terminal."""
    def __init__(self):
        self._tty = None

    def __enter__(self):
        if not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)):
            raise WalletUIError("An interactive human terminal is required")
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        raw = None
        try:
            if not os.isatty(fd):
                raise WalletUIError("A controlling terminal is required")
            termios.tcgetattr(fd)  # Fail before collecting secrets if echo control is unavailable.
            # A terminal is not seekable: buffered r+ would require a seekable
            # BufferedRandom stream. Wrap its raw descriptor as getpass does.
            raw = io.FileIO(fd, "r+", closefd=True)
            self._tty = io.TextIOWrapper(raw, encoding="utf-8", line_buffering=True, write_through=True)
        except BaseException:
            raw.close() if raw is not None else os.close(fd)
            raise
        return self

    def __exit__(self, *_):
        if self._tty is not None:
            self._tty.close()
            self._tty = None

    def message(self, text: str):
        self._tty.write(text + "\n")
        self._tty.flush()

    def prompt(self, text: str) -> str:
        self._tty.write(text)
        self._tty.flush()
        answer = self._tty.readline(4097)
        if not answer:
            raise EOFError
        if len(answer) > 4096 or not answer.endswith("\n"):
            raise WalletUIError("Input is too long")
        return answer[:-1]

    def secret(self, text: str) -> str:
        # getpass normally controls /dev/tty itself. Its warning is raised before
        # any echoing fallback reads input; turn that fallback into a hard error.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                value = getpass.getpass(text, stream=self._tty)
            except getpass.GetPassWarning:
                raise WalletUIError("Hidden input is unavailable") from None
        if len(value.encode("utf-8")) > 1024:
            raise WalletUIError("Hidden input is too long")
        return value

    def show_recovery_code(self, code: str):
        # Never use print/stdout/stderr for this deliberately visible secret.
        self._tty.write("\n" + code + "\n\n")
        self._tty.flush()


def _ensure_private_directory(path: Path):
    """Create one private directory, refusing links and unsafe existing paths."""
    directory_fd, name = recovery._open_parent(path)
    try:
        try:
            os.mkdir(name, mode=0o700, dir_fd=directory_fd)
        except FileExistsError:
            pass
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            info = os.fstat(child_fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise WalletUIError("Wallet directory must be private to its owner")
        finally:
            os.close(child_fd)
    finally:
        os.close(directory_fd)


def _prepare_default_parent(path: Path):
    if path == DEFAULT_WALLET:
        _ensure_private_directory(ROOT / ".local")
        _ensure_private_directory(DEFAULT_WALLET.parent)


def _new_passphrase(io) -> str:
    io.message("Choose a new wallet passphrase: at least 15 characters. Preserve spaces exactly.")
    first = io.secret("New passphrase (hidden): ")
    second = io.secret("Repeat new passphrase (hidden): ")
    if not hmac.compare_digest(first.encode("utf-8"), second.encode("utf-8")):
        raise WalletUIError("Passphrases do not match")
    return first


def _backup(io, session, wallet_path: Path):
    default = wallet_path.parent / "backups" / ("backup-" + secrets.token_hex(8) + ".json")
    destination = io.prompt(f"Encrypted backup file [Enter for {default}]: ").strip()
    if not destination:
        _ensure_private_directory(default.parent)
        path = default
    else:
        path = Path(destination).expanduser()
    blob, code = session.backup()
    recovery.write_private(path, blob)
    del blob
    io.message("Encrypted backup saved. Keep copies safe; keep its recovery code separately offline.")
    io.message("The code is about to be visible in this terminal. Scrollback or recording may retain it; this app cannot erase that.")
    io.show_recovery_code(code)
    del code
    if io.prompt("Have you stored the code separately offline? Type yes to continue: ").strip().casefold() != "yes":
        raise WalletUIError("Backup confirmation was cancelled")
    entered = io.secret("Re-enter the stored recovery code (hidden): ")
    if session.locked:
        io.message("The wallet locked while you stored the code. Unlock it to finish checking the same saved backup.")
        session.unlock(io.secret("Wallet passphrase (hidden): "))
    # Verify the actual bytes on disk, not only the earlier in-memory backup.
    if session.verify_backup(recovery.read_private(path), entered) is not True:
        raise WalletUIError("Backup verification failed")
    io.message("Backup checked: the saved file and your re-entered code recover this wallet.")


def _session_menu(io, session, wallet_path: Path, *, backup_checked: bool):
    while True:
        state = "locked" if session.locked else "unlocked"
        io.message(f"Wallet {state}. Automatic lock follows five minutes without a key operation.")
        choice = io.prompt("1 Status | 2 Receive address | 3 Backup | 4 Lock | 5 Unlock | 0 Exit: ").strip()
        if choice == "0":
            return
        if choice == "1":
            io.message("Locked." if session.locked else "Unlocked. Private qludev test network only.")
            io.message("Backup checked during this session." if backup_checked else "Backup has not been checked during this session. Check it before relying on the wallet.")
        elif choice == "4":
            session.lock()
            io.message("Wallet locked.")
        elif choice == "5":
            if session.locked:
                session.unlock(io.secret("Wallet passphrase (hidden): "))
                io.message("Wallet unlocked.")
            else:
                io.message("Wallet is already unlocked.")
        elif choice in ("2", "3"):
            if session.locked:
                io.message("Unlock the wallet first.")
                continue
            if choice == "2":
                if not backup_checked:
                    io.message("Check a portable backup before relying on this wallet.")
                io.message("Receiving address: " + session.address())
            else:
                _backup(io, session, wallet_path)
                backup_checked = True
        else:
            io.message("Choose one of the listed options.")


def _run(io, path: Path, session_type, *, offer_recovery_destination: bool = False) -> int:
    session = None
    saved_new_wallet = False
    setup_complete = False
    try:
        io.message("QLU private wallet. Test coins have no monetary value.")
        io.message("Your wallet passphrase unlocks this device. The separate offline code restores a portable backup.")
        choice = io.prompt("1 Create wallet | 2 Open wallet | 3 Recover backup | 0 Exit: ").strip()
        if choice == "0":
            return 0
        if choice not in ("1", "2", "3"):
            raise WalletUIError("Choose a listed action")
        _prepare_default_parent(path)
        if choice == "3" and offer_recovery_destination:
            suggested = path if not path.exists() else path.parent / ("recovered-" + secrets.token_hex(8) + ".vault.json")
            destination = io.prompt(f"New encrypted wallet file [Enter for {suggested}]: ").strip()
            path = Path(destination).expanduser() if destination else suggested
        io.message("Wallet file: " + str(path))
        backup_checked = False
        if choice == "1":
            session = session_type.create(path, _new_passphrase(io), idle_seconds=IDLE_SECONDS)
            saved_new_wallet = True
            io.message("Encrypted wallet saved. Complete the portable backup check before using it.")
            _backup(io, session, path)
            backup_checked = True
            io.message("Wallet ready for private testing. Receiving address: " + session.address())
        elif choice == "2":
            session = session_type(path, idle_seconds=IDLE_SECONDS)
            session.unlock(io.secret("Wallet passphrase (hidden): "))
            io.message("Wallet opened. Check a portable backup before relying on it.")
        else:
            backup_path = Path(io.prompt("Encrypted portable backup file: ")).expanduser()
            backup = recovery.read_private(backup_path)
            code = io.secret("Separate offline recovery code (hidden): ")
            passphrase = _new_passphrase(io)
            session = session_type.restore(path, backup, code, passphrase, idle_seconds=IDLE_SECONDS)
            del backup, code, passphrase
            saved_new_wallet = True
            session.lock()
            io.message("Recovered encrypted wallet saved. Unlock it with the new passphrase to continue.")
            session.unlock(io.secret("New wallet passphrase (hidden): "))
            backup_checked = True
            io.message("Recovery checked. Keep your portable backup and its separate offline code.")
            io.message("Other copies of the old keys remain valid. Recovery does not revoke them.")
            io.message("Receiving address: " + session.address())
        setup_complete = True
        _session_menu(io, session, path, backup_checked=backup_checked)
        return 0
    except (KeyboardInterrupt, EOFError):
        if saved_new_wallet and not setup_complete:
            io.message("Cancelled. The encrypted wallet is saved and will be locked; setup is incomplete. Reopen it and complete Backup before relying on it.")
        else:
            io.message("Cancelled. Any opened wallet will be locked.")
        return 1
    except (WalletUIError, vault.VaultError, recovery.RecoveryError, OSError, UnicodeError, termios.error):
        if saved_new_wallet and not setup_complete:
            io.message("Setup incomplete. The encrypted wallet is saved and will be locked. Reopen it and complete Backup; existing files were not replaced.")
        else:
            io.message("Wallet action failed. Check the passphrase, recovery materials, and private file paths. Existing files were not replaced; any opened wallet will be locked.")
        return 1
    finally:
        if session is not None:
            session.lock()


def main(argv: list[str] | None = None, *, io_factory=TerminalIO, session_type=None) -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--wallet", type=Path,
                        help="Private encrypted wallet file; create/recover never overwrite it")
    args = parser.parse_args(argv)
    try:
        with io_factory() as io:
            path = DEFAULT_WALLET if args.wallet is None else args.wallet.expanduser()
            return _run(io, path, vault.WalletSession if session_type is None else session_type,
                        offer_recovery_destination=args.wallet is None)
    except (WalletUIError, OSError, UnicodeError, termios.error):
        # This fixed message contains no entered data or exception details.
        print("QLU wallet stopped because a secure interactive terminal is unavailable. Reopen it in a private human-controlled terminal.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
