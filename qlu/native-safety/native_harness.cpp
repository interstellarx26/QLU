// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see COPYING.
// Public synthetic fixtures only. Never supply wallet data to this executable.
#include <qlu/crypto.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef __clang__
#error "Clang instrumentation is required"
#endif
#if !__has_feature(address_sanitizer)
#error "AddressSanitizer instrumentation is required"
#endif

namespace {
struct Case {
    std::array<std::vector<unsigned char>, 4> fields;
    qlu::Bytes32 digest{};
};

struct Counts {
    std::size_t length_boundaries{0};
    std::size_t bit_mutations{0};
    std::size_t adversarial_patterns{0};
    std::size_t key_digest_mismatch{0};
    std::size_t positive_controls{0};
};

bool Verify(const Case& test)
{
    return qlu::Verify(test.fields[0], test.fields[1], test.fields[2], test.fields[3], test.digest);
}

[[noreturn]] void Failure(const char* category, std::size_t index)
{
    // Only a bounded category/index is reported, never key/signature material.
    throw std::runtime_error(std::string{category} + ":" + std::to_string(index));
}

void Positive(const Case& baseline, Counts& counts)
{
    if (!Verify(baseline)) Failure("positive_control", counts.positive_controls);
    ++counts.positive_controls;
}

void Negative(const Case& test, const char* category, std::size_t& count)
{
    if (Verify(test)) Failure(category, count);
    ++count;
}

template <std::size_t N>
std::vector<unsigned char> Vector(const std::array<unsigned char, N>& value)
{
    return {value.begin(), value.end()};
}

std::string JsonString(const char* value)
{
    std::string result{"\""};
    for (const unsigned char c : std::string{value}) {
        if (c == '\\' || c == '"') result += '\\';
        if (c < 0x20) result += '?';
        else result += static_cast<char>(c);
    }
    return result + '"';
}
} // namespace

int main(int argc, char**)
{
    if (argc != 1) {
        std::cerr << "native_safety_failed:unsupported_arguments\n";
        return 2;
    }
    try {
        // These are public deterministic test seeds, not wallet data. Sign uses
        // its unchanged production randomness; the mutation schedule is fixed.
        qlu::Bytes32 seed{}, other_seed{}, digest{};
        for (std::size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<unsigned char>(i);
            other_seed[i] = static_cast<unsigned char>(255 - i);
            digest[i] = static_cast<unsigned char>(i + 42);
        }
        if (!qlu::SelfTest()) Failure("crypto_selftest", 0);
        const auto keys = qlu::DeriveKeys(seed);
        const auto signature = qlu::Sign(seed, digest);
        const auto other = qlu::DeriveKeys(other_seed);
        const Case baseline{{Vector(keys.mldsa), Vector(keys.schnorr),
                             Vector(signature.mldsa), Vector(signature.schnorr)}, digest};
        Counts counts;

        Positive(baseline, counts);
        for (std::size_t field = 0; field < baseline.fields.size(); ++field) {
            // Real vector allocations, never a fabricated span extending beyond
            // live storage. Every shorter length, empty, and one longer length.
            const auto expected = baseline.fields[field].size();
            for (std::size_t size = 0; size <= expected + 1; ++size) {
                if (size == expected) continue;
                Case test = baseline;
                test.fields[field].resize(size, 0);
                Negative(test, "length_boundaries", counts.length_boundaries);
            }
        }
        Positive(baseline, counts);

        Positive(baseline, counts);
        for (std::size_t field = 0; field < baseline.fields.size(); ++field) {
            for (std::size_t position = 0; position < baseline.fields[field].size(); ++position) {
                Case test = baseline;
                test.fields[field][position] ^= 1;
                // ML-DSA mutations retain the VALID original Schnorr signature
                // and digest so the cheap Schnorr check cannot mask ML errors.
                Negative(test, "bit_mutations", counts.bit_mutations);
            }
        }
        for (std::size_t position = 0; position < digest.size(); ++position) {
            Case test = baseline;
            test.digest[position] ^= 1;
            Negative(test, "bit_mutations", counts.bit_mutations);
        }
        Positive(baseline, counts);

        Positive(baseline, counts);
        for (std::size_t field = 0; field < baseline.fields.size(); ++field) {
            for (const auto byte : {0x00, 0xff}) {
                Case test = baseline;
                std::fill(test.fields[field].begin(), test.fields[field].end(), static_cast<unsigned char>(byte));
                Negative(test, "adversarial_patterns", counts.adversarial_patterns);
            }
        }
        Positive(baseline, counts);

        Positive(baseline, counts);
        Case mismatch = baseline;
        mismatch.fields[0] = Vector(other.mldsa);
        Negative(mismatch, "key_digest_mismatch", counts.key_digest_mismatch);
        mismatch = baseline;
        mismatch.fields[1] = Vector(other.schnorr);
        Negative(mismatch, "key_digest_mismatch", counts.key_digest_mismatch);
        mismatch = baseline;
        mismatch.digest.fill(0);
        Negative(mismatch, "key_digest_mismatch", counts.key_digest_mismatch);
        Positive(baseline, counts);

        if (counts.length_boundaries != 5361 || counts.bit_mutations != 5389
            || counts.adversarial_patterns != 8 || counts.key_digest_mismatch != 3
            || counts.positive_controls != 8) Failure("case_count", 0);
        const auto total = counts.length_boundaries + counts.bit_mutations
                           + counts.adversarial_patterns + counts.key_digest_mismatch;
        std::cout << "{\"schema_version\":1,\"passed\":true,\"negative_cases\":" << total
                  << ",\"positive_controls\":" << counts.positive_controls
                  << ",\"categories\":{\"length_boundaries\":" << counts.length_boundaries
                  << ",\"bit_mutations\":" << counts.bit_mutations
                  << ",\"adversarial_patterns\":" << counts.adversarial_patterns
                  << ",\"key_digest_mismatch\":" << counts.key_digest_mismatch
                  << "},\"crypto_selftest\":true,\"openssl_runtime\":" << JsonString(OpenSSL_version(OPENSSL_VERSION))
                  << ",\"compiler\":" << JsonString(__clang_version__)
                  << ",\"sanitizers\":{\"address\":true,\"undefined\":true}"
                  << ",\"instrumented_openssl_provider\":false"
                  << ",\"deterministic_mutation_schedule\":true,\"production_signing_randomness\":true}\n";
        return 0;
    } catch (const std::runtime_error& error) {
        // Only Failure above supplies these category labels. Production crypto
        // errors are replaced rather than propagating arbitrary exception text.
        const std::string message{error.what()};
        for (const std::string category : {"positive_control:", "length_boundaries:", "bit_mutations:",
                "adversarial_patterns:", "key_digest_mismatch:", "crypto_selftest:", "case_count:"}) {
            if (message.starts_with(category) && message.size() <= category.size() + 8
                && std::all_of(message.begin() + category.size(), message.end(), [](char c) { return c >= '0' && c <= '9'; })) {
                std::cerr << "native_safety_failed:" << message << '\n';
                return 1;
            }
        }
        std::cerr << "native_safety_failed:crypto_backend\n";
        return 1;
    } catch (...) {
        std::cerr << "native_safety_failed:unexpected_error\n";
        return 1;
    }
}
