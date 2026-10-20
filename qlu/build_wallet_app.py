#!/usr/bin/env python3
"""Build the local Mac wallet interface; this is not a distributable release."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "build/qlu-wallet/QLU Wallet.app"
IDENTIFIER = "com.vibexhq.qlu.privatewallet"


def command_output(*args: str) -> str:
    return subprocess.check_output(args, text=True, timeout=30).strip()


def build() -> dict:
    if platform.system() != "Darwin" or platform.machine() not in ("arm64", "x86_64"):
        raise RuntimeError("This interface must be built on a supported Mac.")
    python = ROOT / ".local/recovery-venv/bin/python"
    for dependency in (python, ROOT / "build/qlu-foundation/bin/qlu-keytool",
                       ROOT / "build/qlu-foundation/bin/bitcoind",
                       ROOT / "build/qlu-foundation/bin/bitcoin-cli"):
        if not dependency.is_file() or not os.access(dependency, os.X_OK):
            raise RuntimeError("Build the private QLU foundation and pinned Python environment first.")
    subprocess.run([str(python), "-c", "import cryptography; import cffi"], check=True, timeout=30)
    sources = sorted((ROOT / "qlu/macos").glob("*.swift"))
    if not sources:
        raise RuntimeError("The native wallet sources are missing.")
    if shutil.disk_usage(ROOT).free < 1024 ** 3:
        raise RuntimeError("At least 1 GiB of free space is required for the app build.")
    compiler = command_output("xcrun", "--find", "swiftc")
    sdk = command_output("xcrun", "--sdk", "macosx", "--show-sdk-path")
    sdk_version = command_output("xcrun", "--sdk", "macosx", "--show-sdk-version")
    output = APP.parent
    if output.is_symlink():
        raise RuntimeError("The app build directory must not be a symbolic link.")
    output.mkdir(parents=True, exist_ok=True)
    if APP.exists():
        if APP.is_symlink():
            raise RuntimeError("Refusing to replace a linked application.")
        with (APP / "Contents/Info.plist").open("rb") as stream:
            previous = plistlib.load(stream)
        if previous.get("CFBundleIdentifier") != IDENTIFIER or previous.get("QLUProjectRoot") != str(ROOT):
            raise RuntimeError("An unrelated application occupies the build destination.")
    cache = ROOT / ".local/swift-wallet-cache"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".qlu-wallet-build-", dir=output) as staging:
        bundle = Path(staging) / APP.name
        contents = bundle / "Contents"
        executable = contents / "MacOS/QLUWallet"
        executable.parent.mkdir(parents=True)
        subprocess.run(
            [compiler, "-parse-as-library", "-O", "-sdk", sdk,
             "-target", f"{platform.machine()}-apple-macosx14.0",
             "-module-cache-path", str(cache),
             *map(str, sources), "-o", str(executable)],
            cwd=ROOT, check=True, timeout=600,
        )
        info = {
            "CFBundleName": "QLU Wallet",
            "CFBundleDisplayName": "QLU Wallet",
            "CFBundleIdentifier": IDENTIFIER,
            "CFBundleExecutable": "QLUWallet",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "0.1.0",
            "CFBundleVersion": "1",
            "LSMinimumSystemVersion": "14.0",
            "NSHighResolutionCapable": True,
            "NSPrincipalClass": "NSApplication",
            "QLUProjectRoot": str(ROOT),
            "QLUPrivateNetwork": "qludev",
        }
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump(info, stream)
        (contents / "PkgInfo").write_bytes(b"APPL????")
        subprocess.run(["codesign", "--force", "--sign", "-", str(bundle)],
                       check=True, timeout=30, capture_output=True)
        subprocess.run(["codesign", "--verify", "--strict", str(bundle)],
                       check=True, timeout=30, capture_output=True)
        # Retain the existing bundle until the replacement has compiled and verified.
        previous_bundle = Path(staging) / "previous.app"
        if APP.exists():
            APP.rename(previous_bundle)
        try:
            bundle.rename(APP)
        except BaseException:
            if previous_bundle.exists():
                previous_bundle.rename(APP)
            raise
    result = {
        "app": str(APP), "project": str(ROOT), "architecture": platform.machine(),
        "sdk": sdk_version, "host_macos": platform.mac_ver()[0],
        "executable_sha256": hashlib.sha256((APP / "Contents/MacOS/QLUWallet").read_bytes()).hexdigest(),
        "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "signing": "Local ad-hoc signature; not notarized or a distribution identity",
        "scope": "Project-bound private development app; backend dependencies remain in this checkout",
    }
    evidence = ROOT / ".local/evidence"
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    (evidence / "wallet-app-build.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open", action="store_true", help="Open the app after a successful build")
    args = parser.parse_args()
    try:
        result = build()
        print(json.dumps(result, indent=2))
        if args.open:
            subprocess.run(["open", str(APP)], check=True, timeout=30)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        # Build inputs contain no credentials; no wallet is opened during a build.
        parser.exit(1, f"QLU wallet build failed: {error}\n")


if __name__ == "__main__":
    main()
