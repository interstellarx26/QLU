"""The sanitizer gate must distinguish detected faults from ordinary rejection."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from qlu import native_safety as safety


def result(code=0, stdout=b"", stderr=b""):
    return safety.Result(code, stdout, stderr, .01)


def native_report():
    return {"schema_version": 1, "passed": True, "negative_cases": 10761, "positive_controls": 8,
            "categories": dict(safety.EXPECTED_NATIVE_CATEGORIES), "openssl_runtime": "OpenSSL 3.6.4 7 Apr 2026",
            "compiler": "18.1.3 (Ubuntu)", "sanitizers": {"address": True, "undefined": True},
            "instrumented_openssl_provider": False, "crypto_selftest": True,
            "deterministic_mutation_schedule": True, "production_signing_randomness": True}


class NativeGateTests(unittest.TestCase):
    def test_normal_rejection_requires_exact_exit_stdout_and_generic_error(self):
        safety.validate_rejection(result(1, stderr=safety.ERROR_MESSAGE))
        failures = [result(0, stderr=safety.ERROR_MESSAGE), result(-11, stderr=safety.ERROR_MESSAGE),
                    result(86, stderr=safety.ERROR_MESSAGE), result(1, stdout=b"partial", stderr=safety.ERROR_MESSAGE),
                    result(1, stderr=b"different failure\n"), result(1, stderr=safety.ERROR_MESSAGE + b"details"),
                    result(1, stderr=b"ERROR: AddressSanitizer: heap-buffer-overflow"),
                    result(1, stderr=b"runtime error: signed integer overflow")]
        for item in failures:
            with self.subTest(code=item.code, stderr=item.stderr[:30]), self.assertRaises(safety.SafetyError):
                safety.validate_rejection(item)

    def test_deliberate_probes_require_specific_sanitizer_faults(self):
        address = result(86, stderr=b"ERROR: AddressSanitizer: heap-buffer-overflow\n")
        undefined = result(87, stderr=b"runtime error: signed integer overflow\nSUMMARY: UndefinedBehaviorSanitizer\n")
        self.assertTrue(safety.validate_probe("address", address)["expected_diagnostic_seen"])
        self.assertTrue(safety.validate_probe("undefined", undefined)["expected_diagnostic_seen"])
        for kind, item in (("address", undefined), ("undefined", address),
                           ("address", result(0, stderr=address.stderr)), ("undefined", result(0, stderr=undefined.stderr)),
                           ("address", result(1, stderr=safety.ERROR_MESSAGE)),
                           ("undefined", result(-11, stderr=b"segmentation fault")),
                           ("address", result(86, stdout=b"unexpected", stderr=address.stderr))):
            with self.subTest(kind=kind, code=item.code), self.assertRaises(safety.SafetyError):
                safety.validate_probe(kind, item)

    def test_native_success_requires_exact_counts_scope_and_provenance(self):
        original = native_report()
        self.assertEqual(safety.validate_native_report(result(stdout=safety.canonical(original))), original)
        for name in ("passed", "negative_cases", "positive_controls", "categories", "sanitizers",
                     "instrumented_openssl_provider", "crypto_selftest", "deterministic_mutation_schedule",
                     "production_signing_randomness", "extra", "compiler"):
            changed = copy.deepcopy(original)
            if name == "categories": changed[name]["length_boundaries"] += 1
            elif name == "sanitizers": changed[name]["undefined"] = 1
            elif name == "compiler": changed[name] = ""
            elif name == "extra": changed[name] = "untrusted"
            elif type(changed[name]) is bool: changed[name] = not changed[name]
            else: changed[name] -= 1
            with self.subTest(field=name), self.assertRaises(safety.SafetyError):
                safety.validate_native_report(result(stdout=safety.canonical(changed)))

    def test_sanitizer_diagnostic_prevents_apparent_success(self):
        for output in (b"AddressSanitizer", b"UndefinedBehaviorSanitizer", b"runtime error:"):
            with self.assertRaises(safety.SafetyError):
                safety.require_clean(result(stderr=output))

    def test_openssl_library_annotation_is_normalized_but_mismatch_is_rejected(self):
        version = "OpenSSL 3.6.4 25 Aug 2026"
        self.assertEqual(safety.openssl_runtime_version(version), version)
        self.assertEqual(safety.openssl_runtime_version(version + " (Library: " + version + ")"), version)
        for text in (version + " (Library: OpenSSL 3.6.5 26 Aug 2026)", version + " (Library: unknown)",
                     version + " (Library: " + version, version + " (Library: " + version + ") extra",
                     version + "\n", "LibreSSL 3.6.4", "OpenSSL 3.6.4 custom", None):
            with self.subTest(text=text), self.assertRaises(safety.SafetyError):
                safety.openssl_runtime_version(text)

    def test_fixed_public_corpus_has_boundaries_duplicates_and_nested_cleanup(self):
        corpus = safety.malformed_corpus()
        cases = {name: payload for rows in corpus.values() for name, payload in rows}
        self.assertEqual(len(cases), sum(map(len, corpus.values())))
        self.assertLessEqual(max(map(len, cases.values())), 4097)
        self.assertEqual(len(cases["4097-byte-request"]), 4097)
        self.assertIn(b"\\u0073eed", cases["escaped-duplicate-seed"])
        self.assertIn(b"\0", cases["literal-nul"])
        for depth in (64, 512, 1024):
            self.assertIn(f"array-depth-{depth}", cases)
            self.assertIn(f"partial-depth-{depth}", cases)
        self.assertEqual(hashlib.sha256(safety.PUBLIC_SEED_LABEL).digest(), safety.PUBLIC_SEED)
        self.assertIn(b"PUBLIC SYNTHETIC", safety.PUBLIC_SEED_LABEL)
        self.assertEqual(json.loads(safety.public_request())["seed"], safety.PUBLIC_SEED.hex())

    def test_environment_cannot_override_sanitizer_failures_or_inject_libraries(self):
        with patch.dict(os.environ, {"ASAN_OPTIONS": "halt_on_error=0", "UBSAN_OPTIONS": "halt_on_error=0",
                                     "LD_PRELOAD": "untrusted", "DYLD_INSERT_LIBRARIES": "untrusted", "CFLAGS": "-O3",
                                     "LD_LIBRARY_PATH": "untrusted", "DYLD_LIBRARY_PATH": "untrusted",
                                     "OPENSSL_MODULES": "untrusted", "OPENSSL_CONF": "untrusted"}):
            environment = safety.sanitizer_environment()
        for name in ("LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "CFLAGS", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "OPENSSL_MODULES"):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["OPENSSL_CONF"], os.devnull)
        self.assertIn("halt_on_error=1", environment["ASAN_OPTIONS"])
        self.assertIn("halt_on_error=1", environment["UBSAN_OPTIONS"])

    def test_safe_failure_report_excludes_raw_diagnostics_and_input(self):
        original = {"passed": False, "phase": "build", "error_type": "SafetyError", "cleanup": "stopped"}
        self.assertEqual(safety.public_failure({**original, "stderr": "private", "payload": "private", "master_seed": "private"}), original)


class RunnerTests(unittest.TestCase):
    def test_bounded_child_transfers_full_input_and_retains_private_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = safety.Runner(root, root, time.monotonic() + 5)
            payload = b"x" * 4097
            item = runner.run("echo", [sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"], payload=payload)
            self.assertEqual(item.stdout, payload)
            self.assertEqual(item.stderr, b"")
            self.assertEqual(item.code, 0)
            self.assertIsNone(runner.active)
            paths = list(root.iterdir())
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in paths))

    def test_child_core_dump_limit_is_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = safety.Runner(directory, directory, time.monotonic() + 5)
            item = runner.run("core-limit", [sys.executable, "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_CORE))"])
            self.assertEqual(item.stdout.strip(), b"(0, 0)")

    def test_output_limit_and_timeout_fail_without_leaving_owned_child(self):
        for label, code, timeout, limit in (("oversize", "import sys;sys.stdout.write('x'*10000)", 2, 100),
                                             ("timeout", "import time;time.sleep(10)", .1, 100)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                runner = safety.Runner(directory, directory, time.monotonic() + 5)
                began = time.monotonic()
                with self.assertRaises(safety.SafetyError):
                    runner.run(label, [sys.executable, "-c", code], timeout=timeout, output_limit=limit)
                self.assertLess(time.monotonic() - began, 4)
                self.assertIsNone(runner.active)
                self.assertLessEqual(sum(path.stat().st_size for path in Path(directory).iterdir()), limit)

    def test_timeout_also_stops_owned_compiler_like_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "should-not-exist"
            child = "import time,pathlib;time.sleep(1);pathlib.Path(" + repr(str(marker)) + ").write_text('still running')"
            code = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);time.sleep(10)"
            runner = safety.Runner(directory, directory, time.monotonic() + 5)
            with self.assertRaises(safety.SafetyError):
                runner.run("descendant", [sys.executable, "-c", code], timeout=.2)
            time.sleep(1.1)
            self.assertFalse(marker.exists())

    def test_success_stops_descendant_that_closed_inherited_output(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "should-not-exist"
            child = "import time,pathlib;time.sleep(1);pathlib.Path(" + repr(str(marker)) + ").write_text('still running')"
            code = ("import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child)
                    + "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)")
            runner = safety.Runner(directory, directory, time.monotonic() + 5)
            self.assertEqual(runner.run("descendant-exit", [sys.executable, "-c", code], timeout=2).code, 0)
            time.sleep(1.1)
            self.assertFalse(marker.exists())

    def test_nonreading_child_still_obeys_input_and_time_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = safety.Runner(directory, directory, time.monotonic() + 5)
            began = time.monotonic()
            with self.assertRaises(safety.SafetyError):
                runner.run("nonreading", [sys.executable, "-c", "import time;time.sleep(10)"], payload=b"x" * 4097, timeout=.1)
            self.assertLess(time.monotonic() - began, 4)
            self.assertIsNone(runner.active)

    def test_invalid_request_or_expired_deadline_starts_no_process(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = safety.Runner(directory, directory, 0)
            with patch.object(safety.subprocess, "Popen") as popen:
                for label, payload in (("bad/label", b""), ("large", b"x" * 4098), ("expired", b"")):
                    with self.assertRaises(safety.SafetyError):
                        runner.run(label, [sys.executable], payload=payload)
                popen.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])


class BuildProvenanceTests(unittest.TestCase):
    def test_mac_compilers_and_sdk_are_selected_together_through_xcrun(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler, compiler_cxx, sdk = root / "selected-clang", root / "selected-clang-cxx", root / "SelectedSDK"
            compiler.touch(); compiler_cxx.touch(); sdk.mkdir()
            (root / "include/openssl").mkdir(parents=True)
            (root / "include/openssl/opensslv.h").touch()
            (root / "bin").mkdir(); (root / "bin/openssl").touch()
            calls = []
            class FakeRunner:
                def run(inner, label, command):
                    self.assertRegex(label, r"^[a-z0-9-]+$")
                    calls.append(command)
                    if command[-2:] == ["--find", "clang"]: text = str(compiler)
                    elif command[-2:] == ["--find", "clang++"]: text = str(compiler_cxx)
                    elif command[-1] == "--show-sdk-path": text = str(sdk)
                    elif command[-1] == "version": text = "OpenSSL 3.6.4 7 Apr 2026"
                    elif command[0] == "/fake/cmake": text = "cmake version 4.0"
                    else: text = "Apple clang version 17.0.0"
                    return result(stdout=(text + "\n").encode())
            with patch.object(safety.platform, "system", return_value="Darwin"), \
                    patch.object(safety.shutil, "which", side_effect=lambda name: "/fake/" + name), \
                    patch.dict(os.environ, {"OPENSSL_ROOT_DIR": str(root)}):
                commands, _, versions = safety.discover_tools(FakeRunner())
            self.assertEqual(commands["clang"], str(compiler))
            self.assertEqual(commands["clang++"], str(compiler_cxx))
            self.assertEqual(versions["macos_sdk"], str(sdk))
            for command in calls[:3]:
                self.assertEqual(command[:3], ["/fake/xcrun", "--sdk", "macosx"])
            self.assertFalse(any(command[0] == "/fake/clang" for command in calls))

    def fixture(self, root):
        build, openssl = root / "build", root / "openssl"
        build.mkdir(); openssl.mkdir()
        (openssl / "include/openssl").mkdir(parents=True)
        (openssl / "lib").mkdir()
        (openssl / "bin").mkdir()
        (openssl / "include/openssl/opensslv.h").write_bytes(b"public header")
        (openssl / "lib/libcrypto.a").write_bytes(b"public library")
        (openssl / "bin/openssl").write_bytes(b"public executable")
        files = ["src/qlu/crypto.cpp", "src/qlu/keytool.cpp", "src/secp256k1/src/secp256k1.c",
                 "src/univalue/lib/univalue_read.cpp", "src/univalue/lib/univalue.cpp",
                 "qlu/native-safety/native_harness.cpp", "qlu/native-safety/sanitizer_probe.cpp"]
        commands = [{"file": str(root / name), "arguments": ["clang", "-O2", "-O1", "-fsanitize=address,undefined",
                    "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", "-DDISABLE_OPTIMIZED_SHA256"]} for name in files]
        (build / "compile_commands.json").write_text(json.dumps(commands))
        (build / "CMakeCache.txt").write_text("SECP256K1_ASM:STRING=OFF\nOPENSSL_INCLUDE_DIR:PATH=" + str(openssl / "include")
                                              + "\nOPENSSL_CRYPTO_LIBRARY:FILEPATH=" + str(openssl / "lib/libcrypto.a") + "\n")
        return build, openssl, commands

    def test_every_compilation_unit_and_selected_openssl_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build, openssl, _ = self.fixture(root)
            value = safety.build_provenance(root, build, openssl)
            self.assertEqual(len(value["instrumented_sources"]), 7)
            self.assertEqual(value["openssl_selected_files"]["lib/libcrypto.a"], hashlib.sha256(b"public library").hexdigest())

    def test_missing_instrumentation_wrong_optimization_and_missing_source_fail(self):
        for mode in ("missing-asan", "missing-recover", "wrong-optimization", "missing-secp", "asm", "wrong-openssl"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                build, openssl, commands = self.fixture(root)
                if mode == "missing-asan": commands[2]["arguments"].remove("-fsanitize=address,undefined")
                elif mode == "missing-recover": commands[2]["arguments"].remove("-fno-sanitize-recover=all")
                elif mode == "wrong-optimization": commands[2]["arguments"].append("-O3")
                elif mode == "missing-secp": commands.pop(2)
                elif mode == "asm":
                    path = build / "CMakeCache.txt"; path.write_text(path.read_text().replace("ASM:STRING=OFF", "ASM:STRING=ON"))
                elif mode == "wrong-openssl": openssl = root / "other"
                (build / "compile_commands.json").write_text(json.dumps(commands))
                with self.assertRaises(safety.SafetyError):
                    safety.build_provenance(root, build, openssl)


if __name__ == "__main__":
    unittest.main()
