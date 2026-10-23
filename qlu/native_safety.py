#!/usr/bin/env python3
"""Bounded ASan/UBSan checks of QLU's offline native crypto/input helper.

Only fixed, explicitly PUBLIC SYNTHETIC inputs are used. No node is started and
no wallet, backup, recovery code, RPC cookie or user data is read. This is a fixed
regression corpus, not coverage-guided fuzzing or full-node instrumentation.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conformance_reference as reference
from devnet import secure_directory, write_private

ROOT = Path(__file__).resolve().parents[1]
MAX_TOTAL_SECONDS = 540
MAX_FIXTURE_BYTES = 384 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
PUBLIC_SEED_LABEL = b"QLU PUBLIC SYNTHETIC native sanitizer regression v1 - NEVER USE FOR FUNDS"
PUBLIC_SEED = hashlib.sha256(PUBLIC_SEED_LABEL).digest()
PUBLIC_DIGEST = hashlib.sha256(b"QLU PUBLIC SYNTHETIC native sanitizer message v1").digest()
KEY_FIELDS = {"policy_version", "mldsa_public", "schnorr_public", "key_commitment"}
SIGNATURE_FIELDS = KEY_FIELDS | {"mldsa_signature", "schnorr_signature"}
ERROR_MESSAGE = b"QLU key operation failed\n"
EXPECTED_NATIVE_CATEGORIES = {"length_boundaries": 5361, "bit_mutations": 5389,
                              "adversarial_patterns": 8, "key_digest_mismatch": 3}


class SafetyError(RuntimeError):
    """Messages are fixed labels; CLI output never echoes backend diagnostics."""


def require(condition, message):
    if not condition:
        raise SafetyError(message)


def canonical(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def public_request(*, signing=False):
    value = {"action": "sign" if signing else "public", "seed": PUBLIC_SEED.hex()}
    if signing:
        value["digest"] = PUBLIC_DIGEST.hex()
    return canonical(value)


def malformed_corpus():
    """Named fixed cases; raw input bytes are never included in public reports."""
    public = {"action": "public", "seed": PUBLIC_SEED.hex()}
    sign = {"action": "sign", "seed": PUBLIC_SEED.hex(), "digest": PUBLIC_DIGEST.hex()}
    groups = {}
    groups["fields"] = [("empty-object", b"{}"), ("missing-action", canonical({"seed": PUBLIC_SEED.hex()})),
                        ("missing-seed", b'{"action":"public"}'), ("missing-digest", canonical({"action": "sign", "seed": PUBLIC_SEED.hex()})),
                        ("extra-field", canonical({**public, "extra": 0})), ("public-digest", canonical({**public, "digest": PUBLIC_DIGEST.hex()})),
                        ("unknown-action", canonical({**public, "action": "unknown"}))]
    groups["duplicates"] = []
    for name in ("action", "seed", "digest"):
        base = sign if name == "digest" else public
        raw = canonical(base)[:-1] + b"," + canonical({name: base[name]})[1:]
        groups["duplicates"].append(("duplicate-" + name, raw))
    groups["duplicates"].append(("escaped-duplicate-seed", canonical(public)[:-1] + b',"\\u0073eed":"' + PUBLIC_SEED.hex().encode() + b'"}'))
    groups["types"] = []
    for field in ("action", "seed", "digest"):
        for number, value in enumerate((None, True, 1, [], {})):
            base = sign if field == "digest" else public
            groups["types"].append((f"{field}-type-{number}", canonical({**base, field: value})))
    groups["hex"] = []
    for field in ("seed", "digest"):
        for name, value in (("short", "0" * 63), ("long", "0" * 65), ("nonhex", "g" * 64),
                            ("escaped-nul", "0" * 63 + "\0"), ("unicode", "0" * 63 + "\u00e9")):
            base = sign if field == "digest" else public
            groups["hex"].append((field + "-" + name, canonical({**base, field: value})))
    raw = public_request()
    groups["framing"] = [(f"truncated-{end}", raw[:end]) for end in (0, 1, len(raw) // 2, len(raw) - 1)]
    groups["framing"] += [("trailing-garbage", raw + b"x"), ("second-object", raw + raw),
                           ("literal-nul", raw + b"\0"), ("invalid-utf8", raw[:-2] + b"\xff\"}"),
                           ("array-root", b"[]"), ("string-root", b'"public"'), ("scalar-root", b"null")]
    groups["nested-cleanup"] = []
    for depth in (64, 512, 1024):
        nested = b"[" * depth + b"0" + b"]" * depth
        groups["nested-cleanup"].append((f"array-depth-{depth}", nested))
        groups["nested-cleanup"].append((f"partial-depth-{depth}", nested[:depth + 1]))
    for depth in (64, 513):
        nested = b'{"":' * depth + b"0" + b"}" * depth
        groups["nested-cleanup"].append((f"object-depth-{depth}", nested))
        groups["nested-cleanup"].append((f"partial-object-depth-{depth}", nested[:-depth]))
    groups["size-boundary"] = [("4097-byte-request", raw + b" " * (4097 - len(raw)))]
    groups["argv"] = [("extra-argument", raw)]
    cases = [case for rows in groups.values() for case in rows]
    require(len({name for name, _ in cases}) == len(cases), "Duplicate native corpus label")
    require(all(type(payload) is bytes and len(payload) <= 4097 for _, payload in cases), "Native corpus input limit exceeded")
    return groups


def sanitizer_environment():
    environment = dict(os.environ)
    for name in ("CFLAGS", "CXXFLAGS", "LDFLAGS", "CPPFLAGS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
                 "ASAN_OPTIONS", "UBSAN_OPTIONS", "LSAN_OPTIONS", "MSAN_OPTIONS", "TSAN_OPTIONS"):
        environment.pop(name, None)
    for name in list(environment):
        if name.startswith(("LD_", "DYLD_", "OPENSSL_")):
            environment.pop(name)
    # The default provider is built into the selected libcrypto. Ignore any
    # host configuration that could load external engines/provider modules.
    environment["OPENSSL_CONF"] = os.devnull
    environment["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:abort_on_error=0:exitcode=86:symbolize=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:exitcode=87:print_stacktrace=1:symbolize=0"
    return environment


def sanitizer_diagnostic(data):
    return any(marker in data for marker in (b"AddressSanitizer", b"UndefinedBehaviorSanitizer", b"runtime error:",
                                            b"Sanitizer:DEADLYSIGNAL", b"LeakSanitizer"))


def disable_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


@dataclass(frozen=True)
class Result:
    code: int
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float


class Runner:
    """Own each child process group; bound time and streamed output before disk growth."""
    def __init__(self, root, directory, deadline):
        self.root, self.directory, self.deadline = Path(root), Path(directory), deadline
        self.environment = sanitizer_environment()
        self.sequence = 0
        self.active = None

    @staticmethod
    def stop(process):
        # Only the Popen instance created with start_new_session=True is used.
        # No persisted PID or another task's process is ever targeted.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)

    def run(self, label, command, *, payload=b"", timeout=15, output_limit=65536):
        require(re.fullmatch(r"[a-z0-9-]+", label) is not None, "Invalid native log label")
        require(type(payload) is bytes and len(payload) <= 4097, "Native process input limit exceeded")
        require(0 < output_limit <= MAX_OUTPUT_BYTES, "Native output limit exceeded")
        remaining = min(float(timeout), self.deadline - time.monotonic())
        require(remaining > 0, "Native safety deadline exceeded")
        started, self.sequence = time.monotonic(), self.sequence + 1
        logs, collected, selector, process = [], [bytearray(), bytearray()], selectors.DefaultSelector(), None
        try:
            for stream in ("stdout", "stderr"):
                path = self.directory / f"{self.sequence:03d}-{label}.{stream}.log"
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                logs.append(os.fdopen(fd, "wb"))
            process = subprocess.Popen([str(value) for value in command], cwd=self.root, env=self.environment,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, preexec_fn=disable_core_dumps)
            self.active = process
            offset = 0
            if payload:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "input")
            else:
                process.stdin.close()
            for index, stream in enumerate((process.stdout, process.stderr)):
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                require(time.monotonic() < started + remaining, "Native process deadline exceeded")
                for key, _ in selector.select(min(.1, max(.001, started + remaining - time.monotonic()))):
                    if key.data == "input":
                        try:
                            offset += os.write(key.fileobj.fileno(), payload[offset:offset + 4096])
                        except BrokenPipeError:
                            offset = len(payload)
                        if offset == len(payload):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    require(sum(map(len, collected)) + len(chunk) <= output_limit, "Native process output budget exceeded")
                    collected[key.data].extend(chunk)
                    logs[key.data].write(chunk)
            code = process.wait(timeout=max(.001, started + remaining - time.monotonic()))
            self.stop(process)
            self.active = None
            return Result(code, bytes(collected[0]), bytes(collected[1]), time.monotonic() - started)
        except BaseException:
            if process is not None:
                self.stop(process)
                self.active = None
            raise
        finally:
            selector.close()
            for log in logs:
                log.close()
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()


def require_clean(result):
    require(not sanitizer_diagnostic(result.stdout + result.stderr), "Unexpected sanitizer diagnostic")
    require(result.code == 0, "Native process failed")


def validate_rejection(result):
    require(not sanitizer_diagnostic(result.stdout + result.stderr), "Sanitizer failure is not a normal rejection")
    require(result.code == 1 and result.stdout == b"" and result.stderr == ERROR_MESSAGE,
            "Malformed helper request did not fail with its exact safe error")


def validate_probe(kind, result):
    require(kind in ("address", "undefined"), "Unknown sanitizer probe")
    require(result.code != 0, "Sanitizer probe unexpectedly succeeded")
    if kind == "address":
        require(b"AddressSanitizer" in result.stderr and b"heap-buffer-overflow" in result.stderr,
                "Address sanitizer probe did not report the intended fault")
    else:
        require(b"UndefinedBehaviorSanitizer" in result.stderr and b"runtime error: signed integer overflow" in result.stderr,
                "Undefined behavior probe did not report the intended fault")
    require(result.stdout == b"", "Sanitizer probe emitted unexpected output")
    return {"fault": kind, "exit_code": result.code, "expected_diagnostic_seen": True}


def validate_key_result(result, keys, *, signing):
    require_clean(result)
    require(result.stderr == b"", "Successful helper emitted diagnostics")
    value = json.loads(result.stdout)
    require(type(value) is dict and set(value) == (SIGNATURE_FIELDS if signing else KEY_FIELDS), "Unexpected helper output schema")
    require(type(value["policy_version"]) is int and value["policy_version"] == 1, "Unexpected native key policy")
    require(all(value[name] == keys[name] for name in KEY_FIELDS - {"policy_version"}), "Independent native key disagreement")
    if signing:
        require(reference.verify(keys, PUBLIC_DIGEST, bytes.fromhex(value["mldsa_signature"]),
                                 bytes.fromhex(value["schnorr_signature"])), "Independent native signature verification failed")


def valid_controls(runner, keytool, keys, label):
    for signing in (False, True):
        result = runner.run(label + ("-sign" if signing else "-public"), [keytool], payload=public_request(signing=signing))
        validate_key_result(result, keys, signing=signing)
    return 2


def validate_native_report(result):
    require_clean(result)
    require(result.stderr == b"", "Native safety harness emitted diagnostics")
    value = json.loads(result.stdout)
    expected = {"schema_version", "passed", "negative_cases", "positive_controls", "categories",
                "openssl_runtime", "compiler", "sanitizers", "instrumented_openssl_provider",
                "crypto_selftest", "deterministic_mutation_schedule", "production_signing_randomness"}
    require(type(value) is dict and set(value) == expected, "Unexpected native safety report schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["passed"] is True,
            "Native safety harness did not pass")
    require(type(value["categories"]) is dict and value["categories"] == EXPECTED_NATIVE_CATEGORIES
            and all(type(count) is int for count in value["categories"].values())
            and type(value["negative_cases"]) is int and value["negative_cases"] == sum(EXPECTED_NATIVE_CATEGORIES.values()),
            "Native safety corpus counts changed")
    require(type(value["positive_controls"]) is int and value["positive_controls"] == 8, "Native safety positive control count changed")
    require(type(value["sanitizers"]) is dict and set(value["sanitizers"]) == {"address", "undefined"}
            and all(enabled is True for enabled in value["sanitizers"].values())
            and value["instrumented_openssl_provider"] is False, "Native safety instrumentation scope changed")
    require(all(value[name] is True for name in ("crypto_selftest", "deterministic_mutation_schedule", "production_signing_randomness")),
            "Native safety provenance changed")
    require(type(value["compiler"]) is str and 0 < len(value["compiler"]) <= 512, "Missing native compiler identity")
    require(type(value["openssl_runtime"]) is str and value["openssl_runtime"].startswith("OpenSSL 3."), "Unexpected OpenSSL runtime")
    return value


def openssl_runtime_version(text):
    """Normalize the CLI's explicit library annotation without accepting drift."""
    require(type(text) is str, "Invalid OpenSSL version report")
    match = re.fullmatch(r"(OpenSSL [^()\r\n]+)(?: \(Library: (OpenSSL [^()\r\n]+)\))?", text)
    require(match is not None, "Malformed OpenSSL version report")
    intended, loaded = match.group(1), match.group(2) or match.group(1)
    require(intended == loaded, "OpenSSL executable and library versions disagree")
    require(re.fullmatch(r"OpenSSL \d+\.\d+\.\d+(?:[-a-z0-9]+)? \d{1,2} [A-Z][a-z]{2} \d{4}", loaded) is not None,
            "Unsupported OpenSSL release version format")
    return loaded


def sources(root):
    names = subprocess.check_output(["git", "ls-files", "--", "src/qlu", "src/crypto", "src/support",
        "src/univalue", "src/secp256k1", "src/compat", "src/util", "src/span.h", "src/hash.h", "src/uint256.h",
        "src/serialize.h", "src/streams.h"], cwd=root, text=True, timeout=10).splitlines()
    names += ["qlu/native_safety.py", "qlu/tests/test_native_safety.py", "qlu/conformance_reference.py",
              "qlu/conformance-requirements.txt", "qlu/devnet.py"]
    names += [str(path.relative_to(root)) for path in (root / "qlu/native-safety").rglob("*") if path.is_file()]
    names += [str(path.relative_to(root)) for path in (root / "qlu/conformance_vendor").iterdir() if path.is_file()]
    require(0 < len(names) <= 2000, "Native source inventory limit exceeded")
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(set(names))}


def binary_hashes(build):
    return {name: hashlib.sha256((build / "bin" / name).read_bytes()).hexdigest()
            for name in ("qlu-native-safety", "qlu-keytool", "qlu-sanitizer-probe")}


def build_provenance(root, build, openssl):
    """Require instrumentation on every actual C/C++ compilation unit."""
    root, build, openssl = Path(root).resolve(), Path(build).resolve(), Path(openssl).resolve()
    path = build / "compile_commands.json"
    require(path.stat().st_size <= 2097152, "Native compile inventory is oversized")
    commands = json.loads(path.read_text())
    require(type(commands) is list and 0 < len(commands) <= 64, "Invalid native compile inventory")
    files = []
    for row in commands:
        source = Path(row["file"]).resolve()
        require(source.is_relative_to(root) and source.suffix in (".c", ".cpp"), "Unexpected native compilation source")
        arguments = row.get("arguments") or shlex.split(row["command"])
        require(all(flag in arguments for flag in ("-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer")),
                "Native compilation unit is missing instrumentation")
        optimization = [arg for arg in arguments if re.fullmatch(r"-O(?:[0-3sgz]|fast)", arg)]
        require(optimization and optimization[-1] == "-O1", "Unexpected native optimization mode")
        if source.name in ("crypto.cpp", "sha256.cpp", "hmac_sha256.cpp", "cleanse.cpp"):
            require("-DDISABLE_OPTIMIZED_SHA256" in arguments, "Native SHA256 must use the portable source")
        files.append(str(source.relative_to(root)))
    required = {"src/qlu/crypto.cpp", "src/qlu/keytool.cpp", "src/secp256k1/src/secp256k1.c",
                "src/univalue/lib/univalue_read.cpp", "src/univalue/lib/univalue.cpp",
                "qlu/native-safety/native_harness.cpp", "qlu/native-safety/sanitizer_probe.cpp"}
    require(required <= set(files), "Native build omitted a required implementation")
    cache = {}
    for line in (build / "CMakeCache.txt").read_text().splitlines():
        match = re.match(r"([^:#][^:]*):[^=]+=(.*)$", line)
        if match:
            cache[match.group(1)] = match.group(2)
    require(cache.get("SECP256K1_ASM") == "OFF", "Native secp256k1 assembly must be disabled")
    header = Path(cache["OPENSSL_INCLUDE_DIR"]).resolve() / "openssl/opensslv.h"
    library = Path(cache["OPENSSL_CRYPTO_LIBRARY"]).resolve()
    require(header.is_relative_to(openssl) and library.is_relative_to(openssl), "CMake selected a different OpenSSL installation")
    executable = openssl / "bin/openssl"
    openssl_files = {str(item.relative_to(openssl)): hashlib.sha256(item.read_bytes()).hexdigest() for item in (header, library, executable)}
    return {"compile_commands_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "instrumented_sources": sorted(files), "openssl_selected_files": openssl_files}


def size_checkpoint(directory):
    total, count = 0, 0
    for base, directories, names in os.walk(directory, followlinks=False):
        for name in directories + names:
            path = Path(base) / name
            require(not path.is_symlink(), "Linked native build fixture")
            if path.is_file():
                metadata = path.stat()
                require(metadata.st_nlink == 1, "Hard-linked native fixture")
                total += metadata.st_blocks * 512
                count += 1
                require(count <= 4096 and total <= MAX_FIXTURE_BYTES, "Native fixture budget exceeded")
    return {"allocated_bytes": total, "files": count}


def discover_tools(runner):
    commands = {name: shutil.which(name) for name in ("cmake", "clang", "clang++")}
    require(all(commands.values()), "Native safety requires CMake and Clang")
    sdk = None
    if platform.system() == "Darwin":
        xcrun = shutil.which("xcrun")
        require(xcrun is not None, "Native safety requires the selected Apple toolchain")
        for name in ("clang", "clang++"):
            result = runner.run("apple-" + ("clang-cxx" if name == "clang++" else name),
                                [xcrun, "--sdk", "macosx", "--find", name])
            require_clean(result)
            path = Path(result.stdout.decode("utf-8").strip())
            require(path.is_absolute() and path.is_file(), "Selected Apple compiler unavailable")
            commands[name] = str(path)
        result = runner.run("apple-sdk", [xcrun, "--sdk", "macosx", "--show-sdk-path"])
        require_clean(result)
        path = Path(result.stdout.decode("utf-8").strip())
        require(path.is_absolute() and path.is_dir(), "Selected Apple SDK unavailable")
        sdk = str(path)
    prefix = os.environ.get("OPENSSL_ROOT_DIR")
    if prefix is None and platform.system() == "Darwin":
        prefix = "/opt/homebrew/opt/openssl@3"
    require(type(prefix) is str and Path(prefix).is_absolute(), "Explicit OpenSSL installation required")
    openssl = Path(prefix).resolve()
    require((openssl / "include/openssl/opensslv.h").is_file() and (openssl / "bin/openssl").is_file(),
            "OpenSSL development installation unavailable")
    versions = {}
    for name, command in (*commands.items(), ("openssl", openssl / "bin/openssl")):
        label = "clang-cxx" if name == "clang++" else name
        result = runner.run(label + "-version", [command, "version" if name == "openssl" else "--version"])
        require_clean(result)
        text = result.stdout.decode("utf-8", "replace").strip()
        require(0 < len(text) <= 4096, "Unexpected native tool version output")
        versions[name] = text
    require(all("clang" in versions[name].lower() for name in ("clang", "clang++")), "Native safety requires Clang")
    match = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", versions["openssl"])
    require(match is not None and tuple(map(int, match.groups())) >= (3, 5, 0), "OpenSSL 3.5 or newer required")
    openssl_runtime_version(versions["openssl"])
    if sdk is not None:
        versions["macos_sdk"] = sdk
    return commands, openssl, versions


def public_failure(report):
    allowed = ("format", "attempt", "passed", "phase", "error_type", "error_location", "cleanup", "cleanup_error_type",
               "source_unchanged", "binaries_unchanged", "evidence_error_type")
    return {key: report[key] for key in allowed if key in report}


def run(*, jobs=2):
    require(type(jobs) is int and 1 <= jobs <= 2, "Native safety permits one or two build jobs")
    require(shutil.disk_usage(ROOT).free >= 1024 ** 3, "Native safety requires one GiB free disk space")
    secure_directory(ROOT / ".local")
    identifier = uuid.uuid4().hex
    directory = ROOT / ".local" / ("native-safety-" + identifier)
    require(not directory.exists() and not directory.is_symlink(), "Native safety requires a fresh fixture")
    secure_directory(directory)
    logs, build = directory / "logs", directory / "build"
    secure_directory(logs)
    runner = Runner(ROOT, logs, time.monotonic() + MAX_TOTAL_SECONDS)
    report = {"format": "qlu-native-input-safety-v1", "attempt": identifier, "passed": False, "phase": "preflight",
              "started_at": datetime.now(timezone.utc).isoformat(), "network": "offline-no-nodes",
              "scope": "Fixed public synthetic ASan/UBSan crypto/input-helper regression corpus. Not coverage-guided fuzzing, full-node sanitization, leak checking, instrumented OpenSSL provider, or production audit.",
              "public_seed_label": PUBLIC_SEED_LABEL.decode("ascii"), "cleanup": "not-started",
              "host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
              "limits": {"total_work_seconds": MAX_TOTAL_SECONDS, "max_process_output_bytes": MAX_OUTPUT_BYTES,
                         "max_input_bytes": 4097, "sampled_fixture_bytes": MAX_FIXTURE_BYTES}, "checks": {}}
    failure = None
    try:
        report["sources_start"] = sources(ROOT)
        report["reference_self_test"] = reference.self_test()
        tools, openssl, report["tool_versions"] = discover_tools(runner)
        report["head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10).strip()
        report["phase"] = "configure"
        configure = [tools["cmake"], "-S", ROOT / "qlu/native-safety", "-B", build,
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            f"-DCMAKE_C_COMPILER={tools['clang']}", f"-DCMAKE_CXX_COMPILER={tools['clang++']}",
            f"-DOPENSSL_ROOT_DIR={openssl}"]
        if "macos_sdk" in report["tool_versions"]:
            configure.append(f"-DCMAKE_OSX_SYSROOT={report['tool_versions']['macos_sdk']}")
        configured = runner.run("configure", configure, timeout=60, output_limit=MAX_OUTPUT_BYTES)
        require_clean(configured)
        report["phase"] = "build"
        built = runner.run("build", [tools["cmake"], "--build", build, "--parallel", str(jobs)], timeout=240, output_limit=MAX_OUTPUT_BYTES)
        require_clean(built)
        report["build_provenance"] = build_provenance(ROOT, build, openssl)
        report["binaries_start"] = binary_hashes(build)
        report["fixture_after_build"] = size_checkpoint(directory)
        report["phase"] = "sanitizer-probes"
        report["probes"] = [validate_probe(kind, runner.run("probe-" + kind, [build / "bin/qlu-sanitizer-probe", kind]))
                            for kind in ("address", "undefined")]
        report["checks"]["both_sanitizer_runtimes_report_intentional_faults"] = True
        report["phase"] = "native-crypto-corpus"
        native = runner.run("native-corpus", [build / "bin/qlu-native-safety"], timeout=90, output_limit=1048576)
        report["native"] = validate_native_report(native)
        require(report["native"]["openssl_runtime"] == openssl_runtime_version(report["tool_versions"]["openssl"]),
                "Linked OpenSSL runtime disagrees with selected tools")
        report["checks"]["instrumented_native_crypto_corpus"] = True
        report["phase"] = "helper-input-corpus"
        keys, keytool = reference.derive_keys(PUBLIC_SEED), build / "bin/qlu-keytool"
        positives, negatives, groups = 0, 0, []
        corpus = malformed_corpus()
        schedule = {"valid_before_and_after_each_group": [public_request(signing=signing).hex() for signing in (False, True)],
                    "valid_padded_public_request_lengths": [4095, 4096],
                    "groups": [{"group": group, "cases": [{"label": label, "payload_hex": payload.hex(),
                        "argv": ["PUBLIC-SYNTHETIC-EXTRA-ARGUMENT"] if group == "argv" else []} for label, payload in cases]}
                               for group, cases in corpus.items()]}
        report["helper_corpus_sha256"] = hashlib.sha256(canonical(schedule)).hexdigest()
        for group, cases in corpus.items():
            positives += valid_controls(runner, keytool, keys, "before-" + group)
            for label, payload in cases:
                command = [keytool] + (["PUBLIC-SYNTHETIC-EXTRA-ARGUMENT"] if group == "argv" else [])
                validate_rejection(runner.run(label, command, payload=payload))
                negatives += 1
            positives += valid_controls(runner, keytool, keys, "after-" + group)
            groups.append({"category": group, "rejected_cases": len(cases), "positive_controls": 4})
        for length in (4095, 4096):
            payload = public_request()
            payload += b" " * (length - len(payload))
            validate_key_result(runner.run(f"valid-{length}-bytes", [keytool], payload=payload), keys, signing=False)
            positives += 1
        report["helper"] = {"negative_cases": negatives, "positive_controls": positives, "groups": groups,
                            "valid_input_bytes": [4095, 4096], "rejected_input_bytes": 4097}
        report["checks"]["malformed_inputs_reject_safely_without_sanitizer_findings"] = True
        report["checks"]["independent_key_and_signature_controls_before_after_every_batch"] = True
        report["fixture_final"] = size_checkpoint(directory)
        report["passed"], report["phase"] = True, "complete"
    except BaseException as error:
        failure = error
        report["error_type"] = type(error).__name__
        report["error_location"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                    for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        try:
            if runner.active is not None:
                runner.stop(runner.active)
                runner.active = None
            report["cleanup"] = "owned-build-and-test-processes-stopped"
        except BaseException as error:
            failure = failure or error
            report["cleanup"], report["cleanup_error_type"] = "needs-attention", type(error).__name__
        try:
            report["sources_end"] = sources(ROOT)
            report["source_unchanged"] = report.get("sources_start") == report["sources_end"]
            require(report["source_unchanged"], "Native safety sources changed during execution")
            if "binaries_start" in report:
                report["binaries_end"] = binary_hashes(build)
                report["binaries_unchanged"] = report["binaries_start"] == report["binaries_end"]
                require(report["binaries_unchanged"], "Native safety binaries changed during execution")
                require(report["build_provenance"] == build_provenance(ROOT, build, openssl), "Native build inputs or selected OpenSSL changed")
            if "reference_self_test" in report:
                require(report["reference_self_test"] == reference.self_test(), "Independent reference dependency changed")
        except BaseException as error:
            failure = failure or error
            report["integrity_error_type"] = type(error).__name__
        report["passed"] = report["passed"] and failure is None
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            evidence = ROOT / ".local/evidence"
            secure_directory(evidence)
            text = json.dumps(report, indent=2) + "\n"
            write_private(directory / "result.json", text)
            write_private(evidence / f"native-safety-{identifier}.json", text)
            write_private(evidence / "native-safety-latest.json", text)
        except BaseException as error:
            failure = failure or error
            report["passed"], report["evidence_error_type"] = False, type(error).__name__
        if not report["passed"]:
            print(json.dumps(public_failure(report), indent=2), flush=True)
    if failure is not None:
        raise SafetyError("Native safety checks failed; inspect retained local evidence") from None
    public = {key: report[key] for key in ("format", "attempt", "passed", "phase", "network", "scope", "checks", "probes",
              "native", "helper", "helper_corpus_sha256", "tool_versions", "build_provenance",
              "source_unchanged", "binaries_unchanged", "binaries_end", "cleanup")}
    public["source_inventory_sha256"] = hashlib.sha256(canonical(report["sources_end"])).hexdigest()
    print(json.dumps(public, indent=2), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    try:
        run(jobs=args.jobs)
    except Exception:
        print("Native safety checks failed; inspect retained local evidence.", file=sys.stderr)
        raise SystemExit(1)
