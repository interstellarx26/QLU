#!/usr/bin/env python3
"""Compile and run deterministic Mac wallet-model tests without opening a wallet."""
from __future__ import annotations

import argparse
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run() -> None:
    if platform.system() != "Darwin" or platform.machine() not in ("arm64", "x86_64"):
        raise RuntimeError("Native wallet-model tests require a supported Mac.")
    compiler = subprocess.check_output(
        ["xcrun", "--find", "swiftc"], text=True, timeout=30).strip()
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True, timeout=30).strip()
    output = ROOT / "build/qlu-wallet-tests"
    cache = ROOT / ".local/swift-wallet-cache"
    for directory in (output, cache):
        if directory.is_symlink():
            raise RuntimeError("Native test output and cache must not be symbolic links.")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    sources = [ROOT / "qlu/macos/WalletApp.swift",
               ROOT / "qlu/macos/tests/WalletBackupFlowTests.swift"]
    with tempfile.TemporaryDirectory(prefix="backup-flow-", dir=output) as staging:
        executable = Path(staging) / "WalletBackupFlowTests"
        subprocess.run(
            [compiler, "-D", "QLU_WALLET_TESTS", "-parse-as-library", "-sdk", sdk,
             "-target", f"{platform.machine()}-apple-macosx14.0",
             "-module-cache-path", str(cache), *map(str, sources), "-o", str(executable)],
            cwd=ROOT, check=True, timeout=600,
        )
        subprocess.run([str(executable)], cwd=ROOT, check=True, timeout=60)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        run()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        # Test inputs are synthetic; neither actual credentials nor wallet files are read.
        parser.exit(1, f"QLU native wallet-model tests failed: {error}\n")


if __name__ == "__main__":
    main()
