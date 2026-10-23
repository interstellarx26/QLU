# Native cryptographic input safety

Status: implemented and verified on local Mac plus hosted Mac and Linux.
Exact-revision results are recorded in [STATUS.md](STATUS.md).
This gate exercises QLU's existing native hybrid verification and signing-helper
input boundary. It changes no consensus rules, keys, recovery format, mining or
public-network access. All fixtures are explicitly public synthetic test data.

## Why this milestone

Independent conformance checks agreement between implementations. This gate adds
instrumented execution of the actual native QLU code to detect memory errors and
undefined behavior on a bounded, repeatable set of malformed inputs. It must
also prove that valid operations still succeed after the negative cases.

## Acceptance rules

1. Build a separate, disposable native test installation under ignored `.local/`
   using Clang or Apple Clang, AddressSanitizer and UndefinedBehaviorSanitizer.
   Compile the actual QLU crypto and keytool sources, upstream hash helpers,
   UniValue parser and vendored libsecp256k1. Use generic hash implementations
   and disable optional assembly so the compiled C/C++ test paths are instrumented.
   Keep the ordinary application and node binaries unchanged.
2. Run separate deliberate-fault probes and require each sanitizer to detect
   its corresponding fault. A missing runtime, unsupported instrumentation or
   successful fault probe is a failed gate, never a skip. The probes are test-only
   executables; they are not distributed with the wallet.
3. Check valid hybrid signatures, all four key/signature length boundaries,
   systematic single-bit mutations across every byte of both keys and both
   signatures, digest mutations, and fixed adversarial encodings. Keep a valid
   Schnorr signature while mutating ML-DSA inputs so those cases reach the ML-DSA
   verification path. Repeat valid controls after negative cases. Unexpected
   acceptance, crash, sanitizer diagnostic or exception fails the gate.
4. Exercise the actual signing helper through its bounded standard-input JSON
   interface. Cover malformed syntax, duplicate/missing/extra fields, incorrect
   types and hex, embedded nulls, nesting, truncation and its 4,096-byte boundary.
   Rejected input must produce the exact generic error and no standard output.
   A sanitizer failure must never count as an expected application rejection.
5. Independently verify successful helper output and compare its public keys with
   the already pinned reference implementation. No real wallet keys, recovery
   codes, RPC cookies or user wallet files are used as test inputs.
6. Bound build and execution time and captured output. Preserve diagnostics in
   ignored local evidence; print only a safe summary. Record source, compiler,
   dependency and executable fingerprints and require unchanged inputs across
   the run. Stop and reap only processes started by this invocation.
7. Run this gate on both hosted Mac and Linux, along with the existing Python,
   native-wallet, core and localhost private-network regression checks. Record
   the exact tested revision and any failures before reporting completion.

## Running the gate

Use the isolated, pinned recovery and conformance environment described in
[the foundation guide](FOUNDATION.md), with CMake, Clang/Apple Clang and an
OpenSSL 3.5+ development installation:

```sh
.local/recovery-venv/bin/python qlu/native_safety.py --jobs 2
```

The driver builds only its small native test targets in a new ignored directory;
it does not rebuild or replace the normal node or wallet helper. It does not
install packages, open wallets or start network services. Linux can select its
OpenSSL installation through `OPENSSL_ROOT_DIR`; the hosted workflow records
and verifies that dependency before this step. Preserve failed run logs alongside
successful evidence. Do not treat a passing deliberate-fault probe as a successful
test: those isolated processes must fail with their expected sanitizer report.

## Scope limits

This is a deterministic mutation and boundary test, not coverage-guided fuzzing
or proof of complete input coverage. ASan and UBSan do not prove constant-time
execution, secret erasure, resistance to compromised devices or cryptographic
security. The separately linked OpenSSL library/provider and system libraries
are not rebuilt with sanitizers by this gate; their internal coverage is not
claimed. This is not a sanitized full-node, transaction-parser, P2P, consensus,
thread-race, leak or denial-of-service audit. Runtime and memory observations
must not be presented as performance guarantees.

Public launch, physical-device recovery acceptance and independent specialist
security review remain separate release gates. The reference implementation and
deliberate-fault executables are never wallet custody components.

Instrumentation references:
[Clang AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) and
[Clang UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
