// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see the accompanying file COPYING.

#ifndef QLU_CRYPTO_H
#define QLU_CRYPTO_H

#include <array>
#include <cstddef>
#include <span>

namespace qlu {
inline constexpr unsigned char POLICY_VERSION{1};
inline constexpr std::size_t MLDSA_PUBLIC_KEY_SIZE{1952};
inline constexpr std::size_t MLDSA_SIGNATURE_SIZE{3309};
using Bytes32 = std::array<unsigned char, 32>;

struct PublicKeys {
    std::array<unsigned char, MLDSA_PUBLIC_KEY_SIZE> mldsa{};
    Bytes32 schnorr{};
    bool operator==(const PublicKeys&) const = default;
};

struct HybridSignature {
    std::array<unsigned char, MLDSA_SIGNATURE_SIZE> mldsa{};
    std::array<unsigned char, 64> schnorr{};
};

// The caller must supply a uniformly random, secret 32-byte master seed.
// Errors throw without including key material. The caller owns/cleanses master.
PublicKeys DeriveKeys(std::span<const unsigned char, 32> master);
HybridSignature Sign(std::span<const unsigned char, 32> master,
                     std::span<const unsigned char, 32> digest);

// Both signatures are mandatory. Malformed lengths and backend errors fail closed.
bool Verify(std::span<const unsigned char> mldsa_public,
            std::span<const unsigned char> schnorr_public,
            std::span<const unsigned char> mldsa_signature,
            std::span<const unsigned char> schnorr_signature,
            std::span<const unsigned char, 32> digest);

// taggedSHA256("QLU/key-commitment/v1", policy_byte || mldsa_pub || schnorr_pub).
Bytes32 KeyCommitment(const PublicKeys& keys);

// Startup guard: fixed nonsecret derivation vector plus positive/negative hybrid
// authorization checks. False means this process must not validate a QLU chain.
bool SelfTest() noexcept;
} // namespace qlu

#endif // QLU_CRYPTO_H
