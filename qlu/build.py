#!/usr/bin/env python3
"""Build the pinned upstream laboratory without installing system packages."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build" / "qlu-foundation"
EVIDENCE = ROOT / ".local" / "evidence"
PIN = json.loads((ROOT / "qlu" / "upstream.json").read_text())


def capture(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True, timeout=30).strip()


def doctor(min_free_gib=0):
    for name in ("git", "cmake", "python3"):
        if shutil.which(name) is None:
            raise RuntimeError(f"Missing {name}; see docs/FOUNDATION.md")
    if subprocess.run(["git", "merge-base", "--is-ancestor", PIN["commit"], "HEAD"], cwd=ROOT, timeout=30).returncode:
        raise RuntimeError("Source is not descended from the pinned Bitcoin Core release")
    free = shutil.disk_usage(ROOT).free / 2**30
    print(f"Source: {capture('git', 'rev-parse', '--short', 'HEAD')}; free space: {free:.2f} GiB")
    if free < min_free_gib:
        raise RuntimeError(f"Need at least {min_free_gib} GiB free for this operation")
    if platform.system() == "Darwin":
        sdk = capture("xcrun", "--sdk", "macosx", "--show-sdk-path")
        print(f"macOS SDK: {sdk}")


def execute(label, command):
    EVIDENCE.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log = EVIDENCE / f"{stamp}-{label}.log"
    result = {
        "operation": label, "command": [str(x) for x in command],
        "started_utc": stamp, "upstream": PIN["commit"],
        "head": capture("git", "rev-parse", "HEAD"),
        "tracked_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT, timeout=30)).hexdigest(),
        "build_driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "platform": platform.platform(), "log": str(log.relative_to(ROOT)),
    }
    with log.open("w") as output:
        process = subprocess.Popen([str(x) for x in command], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            for line in process.stdout:
                output.write(line)
                output.flush()
                print(line, end="", flush=True)
            result["exit_code"] = process.wait()
        except BaseException:
            # Stop this invocation's build group, including compiler children.
            # Never target a process group read from a saved state file.
            os.killpg(process.pid, signal.SIGTERM)
            process.wait()
            raise
    result["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    log.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    if result["exit_code"]:
        raise RuntimeError(f"{label} failed; see {log}")


def configure():
    doctor(2 if (BUILD / "CMakeCache.txt").exists() else 6)
    command = ["cmake", "-S", ROOT, "-B", BUILD,
               "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_GUI=OFF", "-DENABLE_IPC=OFF",
               "-DBUILD_TESTS=ON", "-DBUILD_BENCH=OFF", "-DBUILD_FUZZ_BINARY=OFF",
               "-DWITH_ZMQ=OFF", "-DWITH_USDT=OFF"]
    if platform.system() == "Darwin":
        command += [f"-DCMAKE_C_COMPILER={capture('xcrun', '--sdk', 'macosx', '--find', 'clang')}",
                    f"-DCMAKE_CXX_COMPILER={capture('xcrun', '--sdk', 'macosx', '--find', 'clang++')}",
                    f"-DCMAKE_OSX_SYSROOT={capture('xcrun', '--sdk', 'macosx', '--show-sdk-path')}"]
        if Path("/opt/homebrew").is_dir():
            command.append("-DCMAKE_PREFIX_PATH=/opt/homebrew")
    execute("configure", command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["doctor", "configure", "build", "test"])
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be between 1 and 32")
    if args.action == "doctor":
        doctor()
    elif args.action == "configure":
        configure()
    elif args.action == "build":
        configure()
        execute("build", ["cmake", "--build", BUILD, "--parallel", str(args.jobs)])
    else:
        doctor(1)
        execute("ctest", ["ctest", "--test-dir", BUILD, "--parallel", str(args.jobs), "--output-on-failure", "--no-tests=error", "--timeout", "600", "--output-junit", "qlu-ctest.xml"])


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        sys.exit(str(exc))
