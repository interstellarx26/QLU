"""Shared native-KDF gate for the vault's package and command-line imports.

Vault deliberately imports this helper by its direct name in both entry paths,
so qlu.vault and vault do not create separate gates in the same interpreter.
Workers launch fresh interpreters; continuing wallet work after fork without
exec is unsupported.
"""
import threading


ARGON2_LOCK = threading.Lock()
# A child that could not be reaped within bounded cleanup prevents another
# native operation until its exit is observed while holding ARGON2_LOCK.
QUARANTINED_CHILD = None
