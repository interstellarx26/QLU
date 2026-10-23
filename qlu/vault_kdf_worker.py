"""One isolated Argon2id operation; the binary pipes are private to its parent.

No passphrase, derived key, or backend error is placed in argv, logs, or files.
The fixed parameters deliberately match the existing local-vault v1 format.
"""
import sys


def main():
    try:
        # One extra byte detects oversized requests without unbounded input.
        request = sys.stdin.buffer.read(1041)
        if not 17 <= len(request) <= 1040:
            return 1
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        key = Argon2id(salt=request[:16], length=32, iterations=3,
                      lanes=4, memory_cost=65536).derive(request[16:])
        if len(key) != 32:
            return 1
        sys.stdout.buffer.write(key)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Never expose provider exceptions or a traceback through this protocol.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
