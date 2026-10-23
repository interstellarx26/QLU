"""Bounded private-pipe transport for the isolated local-vault KDF.

The wallet imports this module by its direct name from both entry points. Native
work is serialized across those callers; the same deadline covers queueing and
the child exchange. POSIX pipes are used on the currently tested Mac/Linux hosts.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

import vault_kdf_lock as shared


DERIVATION_TIMEOUT_SECONDS = 15.0
CLEANUP_TIMEOUT_SECONDS = 1.0


class DerivationError(ValueError):
    """Fixed, secret-free failure at the password-derivation boundary."""


def _worker_command():
    # Keep the venv executable path: resolving its symlink would lose its site
    # packages. Isolated mode ignores PYTHON* settings and the working directory.
    return [sys.executable, "-I", str(Path(__file__).with_name("vault_kdf_worker.py").resolve())]


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DerivationError("Password derivation failed")
    return remaining


def _cleanup(process):
    """Close our pipes and reap only our child, with a bounded final wait."""
    # Preserve ownership even if cancellation interrupts closing, killing, or
    # waiting. Only observed reaping permits a later helper to be launched.
    shared.QUARANTINED_CHILD = process
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=CLEANUP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        # An uninterruptible OS child must not permit unlimited replacements.
        return False
    shared.QUARANTINED_CHILD = None
    return True


def _run_worker(passphrase, salt, deadline):
    _remaining(deadline)
    process = subprocess.Popen(_worker_command(), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               bufsize=0, close_fds=True)
    try:
        _remaining(deadline)
        request = salt + passphrase
        offset = 0
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "input")
            selector.register(process.stdout, selectors.EVENT_READ, "output")
            while selector.get_map():
                ready = selector.select(_remaining(deadline))
                for key, _ in ready:
                    _remaining(deadline)
                    if key.data == "input":
                        try:
                            offset += os.write(key.fd, request[offset:])
                        except BlockingIOError:
                            continue
                        if offset == len(request):
                            selector.unregister(process.stdin)
                            process.stdin.close()  # EOF is part of the protocol.
                    else:
                        try:
                            chunk = os.read(key.fd, 33 - len(output))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(process.stdout)
                            process.stdout.close()
                        else:
                            output.extend(chunk)
                            if len(output) > 32:
                                raise DerivationError("Password derivation failed")
            status = process.wait(timeout=_remaining(deadline))
            _remaining(deadline)
        if status != 0 or len(output) != 32:
            raise DerivationError("Password derivation failed")
        return bytes(output)
    finally:
        if not _cleanup(process):
            raise DerivationError("Password derivation failed") from None


def derive(passphrase: bytes, salt: bytes) -> bytes:
    """Derive with the fixed v1 costs, or fail without a partial key or retry."""
    timeout = DERIVATION_TIMEOUT_SECONDS
    if (type(passphrase) is not bytes or not 1 <= len(passphrase) <= 1024
            or type(salt) is not bytes or len(salt) != 16
            or type(timeout) not in (float, int) or not math.isfinite(timeout) or timeout <= 0):
        raise DerivationError("Password derivation failed")
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        acquired = shared.ARGON2_LOCK.acquire(timeout=_remaining(deadline))
        if not acquired:
            raise DerivationError("Password derivation failed")
        if shared.QUARANTINED_CHILD is not None:
            if shared.QUARANTINED_CHILD.poll() is None:
                raise DerivationError("Password derivation failed")
            # poll() reaps a terminated child; no unbounded wait is needed here.
            shared.QUARANTINED_CHILD = None
        return _run_worker(passphrase, salt, deadline)
    except Exception:
        raise DerivationError("Password derivation failed") from None
    finally:
        if acquired:
            shared.ARGON2_LOCK.release()
