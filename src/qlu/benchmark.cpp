// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see the accompanying file COPYING.

// Laboratory-only microbenchmark. All seeds below are PUBLIC fixtures and must
// never receive funds. This executable does not read wallets or contact nodes.
#include <qlu/crypto.h>
#include <univalue.h>

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
static_assert(Clock::is_steady);
constexpr size_t CASE_COUNT{5};
constexpr size_t KEY_COUNT{32};
constexpr std::array<std::string_view, CASE_COUNT> NAMES{
    "derive_keys", "sign_with_key_reconstruction", "verify_valid",
    "verify_bad_schnorr", "verify_good_schnorr_bad_mldsa"};

struct Options {
    size_t samples{1000};
    size_t batches{5};
    size_t warmup{50};
};

size_t ParseSize(std::string_view text, size_t minimum, size_t maximum)
{
    size_t value{0};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
        value < minimum || value > maximum) throw std::runtime_error("invalid benchmark option");
    return value;
}

Options ParseOptions(int argc, char** argv)
{
    Options result;
    for (int i{1}; i < argc; i += 2) {
        if (i + 1 >= argc) throw std::runtime_error("each option needs a value");
        const std::string_view option{argv[i]};
        if (option == "--samples") result.samples = ParseSize(argv[i + 1], 500, 10000);
        else if (option == "--batches") result.batches = ParseSize(argv[i + 1], 3, 20);
        else if (option == "--warmup") result.warmup = ParseSize(argv[i + 1], 10, 1000);
        else throw std::runtime_error("unknown benchmark option");
    }
    return result;
}

struct KeyFixture {
    qlu::Bytes32 master;
    qlu::PublicKeys keys;
};

struct Fixture {
    size_t key_index;
    qlu::Bytes32 digest{};
    qlu::HybridSignature signature;
    std::array<unsigned char, 64> bad_schnorr;
    std::array<unsigned char, qlu::MLDSA_SIGNATURE_SIZE> bad_mldsa;
};

bool Verify(const KeyFixture& key, const Fixture& fixture,
            std::span<const unsigned char> mldsa, std::span<const unsigned char> schnorr)
{
    return qlu::Verify(key.keys.mldsa, key.keys.schnorr, mldsa, schnorr, fixture.digest);
}

int64_t Measure(size_t which, const KeyFixture& key, const Fixture& fixture)
{
    // Correctness checks occur AFTER the timed operation, but on every call,
    // including warm-ups. Their consumption also prevents dead-code removal.
    const auto start = Clock::now();
    if (which == 0) {
        const auto actual = qlu::DeriveKeys(key.master);
        const auto end = Clock::now();
        if (actual != key.keys) throw std::runtime_error("derived key mismatch");
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    }
    if (which == 1) {
        const auto actual = qlu::Sign(key.master, fixture.digest);
        const auto end = Clock::now();
        if (!Verify(key, fixture, actual.mldsa, actual.schnorr)) throw std::runtime_error("new signature rejected");
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    }
    bool valid{false};
    if (which == 2) valid = Verify(key, fixture, fixture.signature.mldsa, fixture.signature.schnorr);
    else if (which == 3) valid = Verify(key, fixture, fixture.signature.mldsa, fixture.bad_schnorr);
    else if (which == 4) valid = Verify(key, fixture, fixture.bad_mldsa, fixture.signature.schnorr);
    else throw std::runtime_error("unknown benchmark case");
    const auto end = Clock::now();
    if (valid != (which == 2)) throw std::runtime_error("unexpected signature verification result");
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}

UniValue Statistics(std::vector<int64_t> values)
{
    if (values.empty()) throw std::runtime_error("empty benchmark sample");
    std::sort(values.begin(), values.end());
    // Nearest-rank quantiles, including the median (not a mean of middle ranks).
    const auto percentile = [&](size_t percent) {
        return values[(percent * values.size() + 99) / 100 - 1];
    };
    UniValue result{UniValue::VOBJ};
    result.pushKV("count", static_cast<int64_t>(values.size()));
    result.pushKV("min", values.front());
    result.pushKV("median", percentile(50));
    result.pushKV("p95", percentile(95));
    result.pushKV("p99", percentile(99));
    result.pushKV("max", values.back());
    return result;
}
} // namespace

int main(int argc, char** argv)
{
    try {
        const auto options = ParseOptions(argc, argv);
        const auto run_start = Clock::now();
        if (!qlu::SelfTest()) throw std::runtime_error("QLU cryptographic self-test failed");
        std::array<KeyFixture, KEY_COUNT> keys;
        for (size_t k{0}; k < keys.size(); ++k) {
            for (size_t b{0}; b < keys[k].master.size(); ++b) {
                keys[k].master[b] = static_cast<unsigned char>((k * 17 + b) & 255);
            }
            keys[k].keys = qlu::DeriveKeys(keys[k].master);
        }
        std::vector<Fixture> fixtures(options.samples);
        for (size_t i{0}; i < fixtures.size(); ++i) {
            auto& fixture = fixtures[i];
            fixture.key_index = i % keys.size();
            constexpr std::string_view label{"QLU/public-benchmark/v1"};
            std::copy(label.begin(), label.end(), fixture.digest.begin());
            for (size_t b{0}; b < 8; ++b) fixture.digest[24 + b] = static_cast<unsigned char>(static_cast<uint64_t>(i) >> (8 * b));
            fixture.signature = qlu::Sign(keys[fixture.key_index].master, fixture.digest);
            fixture.bad_schnorr = fixture.signature.schnorr;
            fixture.bad_schnorr.back() ^= 1; // Damage s; retain the original R encoding.
            fixture.bad_mldsa = fixture.signature.mldsa;
            fixture.bad_mldsa.front() ^= 1; // Damage the challenge; keep the exact length.
            if (!Verify(keys[fixture.key_index], fixture, fixture.signature.mldsa, fixture.signature.schnorr) ||
                Verify(keys[fixture.key_index], fixture, fixture.signature.mldsa, fixture.bad_schnorr) ||
                Verify(keys[fixture.key_index], fixture, fixture.bad_mldsa, fixture.signature.schnorr)) {
                throw std::runtime_error("benchmark fixture verification failed");
            }
        }

        std::array<std::vector<std::vector<int64_t>>, CASE_COUNT> timings;
        UniValue batch_order{UniValue::VARR};
        for (size_t batch{0}; batch < options.batches; ++batch) {
            UniValue order{UniValue::VARR};
            for (size_t slot{0}; slot < CASE_COUNT; ++slot) {
                const size_t which = (slot + batch) % CASE_COUNT;
                order.push_back(std::string{NAMES[which]});
                for (size_t w{0}; w < options.warmup; ++w) {
                    const auto& fixture = fixtures[w % fixtures.size()];
                    (void)Measure(which, keys[fixture.key_index], fixture);
                }
                std::vector<int64_t> samples;
                samples.reserve(options.samples);
                for (const auto& fixture : fixtures) samples.push_back(Measure(which, keys[fixture.key_index], fixture));
                timings[which].push_back(std::move(samples));
            }
            batch_order.push_back(std::move(order));
        }
        const auto run_end = Clock::now();

        UniValue report{UniValue::VOBJ};
        report.pushKV("schema", "qlu-native-crypto-benchmark-v1");
        report.pushKV("timing_unit", "nanoseconds");
        report.pushKV("clock", "std::chrono::steady_clock");
        report.pushKV("clock_period_numerator", static_cast<int64_t>(Clock::period::num));
        report.pushKV("clock_period_denominator", static_cast<int64_t>(Clock::period::den));
        report.pushKV("quantile_method", "nearest_rank");
        report.pushKV("samples_per_case_per_batch", static_cast<int64_t>(options.samples));
        report.pushKV("batches", static_cast<int64_t>(options.batches));
        report.pushKV("warmup_calls_per_case_per_batch", static_cast<int64_t>(options.warmup));
        report.pushKV("batch_case_order", std::move(batch_order));
        report.pushKV("openssl_runtime", OpenSSL_version(OPENSSL_VERSION));
        report.pushKV("openssl_headers", OPENSSL_VERSION_TEXT);
#if defined(__clang__)
        report.pushKV("compiler", std::string{"clang "} + __clang_version__);
#elif defined(__GNUC__)
        report.pushKV("compiler", std::string{"gcc "} + __VERSION__);
#else
        report.pushKV("compiler", "unreported");
#endif
#ifdef NDEBUG
        report.pushKV("ndebug", true);
#else
        report.pushKV("ndebug", false);
#endif
        report.pushKV("single_threaded", true);
        report.pushKV("all_correctness_checks_passed", true);
        report.pushKV("elapsed_including_setup_and_checks_ns",
                      std::chrono::duration_cast<std::chrono::nanoseconds>(run_end - run_start).count());
        report.pushKV("fixture_description", "32 PUBLIC seeds: seed[k][b]=(17*k+b) mod 256; digest is ASCII QLU/public-benchmark/v1, zero padded, with uint64LE(sample_index) in bytes 24..31. Fixtures and verification signatures generated outside timers; same fixtures reused across batches. Never fund these keys.");
        report.pushKV("methodology", "In-process calls to unchanged qlu::DeriveKeys, Sign, and Verify. Sign includes key reconstruction, provider/context setup, and fresh signing randomness. All results checked outside each timed interval. Clock overhead is included, not subtracted. Warm-ups and fixture setup are excluded from samples. Case order rotates by batch. Failures emit no partial JSON.");
        report.pushKV("limits", "Warm-process microbenchmark of this build and host, not transactions per second, full-node validation, block propagation, mobile performance, or security review. No CPU pinning or frequency control. A fixed public fixture pool does not characterize all possible inputs or adversarial worst cases. Transaction digest construction and key commitment construction are excluded; per-call provider/key setup is measured. Schnorr rejection intentionally short-circuits before ML-DSA verification; the damaged ML-DSA case has a valid Schnorr signature and reaches ML-DSA.");

        UniValue sizes{UniValue::VOBJ};
        sizes.pushKV("mldsa_public_key", static_cast<int64_t>(qlu::MLDSA_PUBLIC_KEY_SIZE));
        sizes.pushKV("schnorr_public_key", 32);
        sizes.pushKV("mldsa_signature", static_cast<int64_t>(qlu::MLDSA_SIGNATURE_SIZE));
        sizes.pushKV("schnorr_signature", 64);
        sizes.pushKV("authorization_digest", 32);
        sizes.pushKV("public_keys_plus_signatures", static_cast<int64_t>(qlu::MLDSA_PUBLIC_KEY_SIZE + 32 + qlu::MLDSA_SIGNATURE_SIZE + 64));
        sizes.pushKV("serialization_overhead_included", false);
        report.pushKV("sizes_bytes", std::move(sizes));

        UniValue cases{UniValue::VOBJ};
        for (size_t which{0}; which < CASE_COUNT; ++which) {
            UniValue entry{UniValue::VOBJ};
            UniValue batches{UniValue::VARR};
            std::vector<int64_t> aggregate;
            aggregate.reserve(options.samples * options.batches);
            for (size_t batch{0}; batch < timings[which].size(); ++batch) {
                UniValue item{UniValue::VOBJ};
                item.pushKV("batch_index", static_cast<int64_t>(batch));
                item.pushKV("statistics_ns", Statistics(timings[which][batch]));
                UniValue raw{UniValue::VARR};
                for (const auto sample : timings[which][batch]) raw.push_back(sample);
                item.pushKV("samples_ns", std::move(raw));
                aggregate.insert(aggregate.end(), timings[which][batch].begin(), timings[which][batch].end());
                batches.push_back(std::move(item));
            }
            entry.pushKV("statistics_ns", Statistics(aggregate));
            entry.pushKV("batches", std::move(batches));
            cases.pushKV(std::string{NAMES[which]}, std::move(entry));
        }
        report.pushKV("cases", std::move(cases));
        std::cout << report.write() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "QLU benchmark failed: " << error.what() << '\n';
        return 1;
    }
}
