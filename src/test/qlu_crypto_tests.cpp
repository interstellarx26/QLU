// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see the accompanying file COPYING.

#include <qlu/crypto.h>
#include <crypto/hex_base.h>
#include <crypto/sha256.h>
#include <boost/test/unit_test.hpp>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>
#include <memory>
#include <span>

BOOST_AUTO_TEST_SUITE(qlu_crypto_tests)

BOOST_AUTO_TEST_CASE(startup_self_test)
{
    BOOST_CHECK(qlu::SelfTest());
}

BOOST_AUTO_TEST_CASE(deterministic_keys_and_commitment)
{
    qlu::Bytes32 master{};
    for (size_t i = 0; i < master.size(); ++i) master[i] = i;
    const auto original = qlu::DeriveKeys(master);
    BOOST_CHECK(original == qlu::DeriveKeys(master));
    // QLU protocol regression vector, generated with OpenSSL 3.6.4. Unlike the
    // external NIST KAT below, this locks our domain labels and serialization.
    qlu::Bytes32 public_hash;
    CSHA256().Write(original.mldsa.data(), original.mldsa.size()).Finalize(public_hash.data());
    BOOST_CHECK_EQUAL(HexStr(public_hash), "a47743740f26c83344a8d06d0399a49043dbfd15a14c744bf7d1e618924d8e53");
    BOOST_CHECK_EQUAL(HexStr(original.schnorr), "ff5fada046056eeea028455da07220ea27c9a723fa37542a694922519d99cebb");
    BOOST_CHECK_EQUAL(HexStr(qlu::KeyCommitment(original)), "e5c462b39feaa32ea38c2267339eeca777f9ff6926b177f2583fd9a8bd3dcb12");
    master[0] ^= 1;
    const auto changed = qlu::DeriveKeys(master);
    BOOST_CHECK(original != changed);
    BOOST_CHECK(qlu::KeyCommitment(original) != qlu::KeyCommitment(changed));
    auto swapped = original;
    swapped.schnorr = changed.schnorr;
    BOOST_CHECK(qlu::KeyCommitment(original) != qlu::KeyCommitment(swapped));
    swapped = original;
    swapped.mldsa = changed.mldsa;
    BOOST_CHECK(qlu::KeyCommitment(original) != qlu::KeyCommitment(swapped));
}

BOOST_AUTO_TEST_CASE(both_signatures_required)
{
    qlu::Bytes32 master{}, digest{};
    master.fill(71);
    digest.fill(23);
    const auto keys = qlu::DeriveKeys(master);
    const auto signature = qlu::Sign(master, digest);
    BOOST_CHECK(qlu::Verify(keys.mldsa, keys.schnorr, signature.mldsa, signature.schnorr, digest));
    auto other_digest = digest;
    other_digest[31] ^= 1;
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, signature.mldsa, signature.schnorr, other_digest));
    auto corrupt = signature;
    corrupt.mldsa[91] ^= 1;
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, corrupt.mldsa, corrupt.schnorr, digest));
    corrupt = signature;
    corrupt.schnorr[42] ^= 1;
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, corrupt.mldsa, corrupt.schnorr, digest));
    // An absent component must never select a classical-only/PQ-only fallback.
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, {}, signature.schnorr, digest));
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, signature.mldsa, {}, digest));
    corrupt = signature;
    corrupt.mldsa.fill(0);
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, corrupt.mldsa, corrupt.schnorr, digest));
    corrupt = signature;
    corrupt.schnorr.fill(0);
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, corrupt.mldsa, corrupt.schnorr, digest));
}

BOOST_AUTO_TEST_CASE(noncanonical_lengths_and_keys_rejected)
{
    qlu::Bytes32 master{}, digest{};
    master.fill(81);
    const auto keys = qlu::DeriveKeys(master);
    const auto signature = qlu::Sign(master, digest);
    BOOST_CHECK(!qlu::Verify(std::span{keys.mldsa}.first(1951), keys.schnorr, signature.mldsa, signature.schnorr, digest));
    BOOST_CHECK(!qlu::Verify(keys.mldsa, std::span{keys.schnorr}.first(31), signature.mldsa, signature.schnorr, digest));
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, std::span{signature.mldsa}.first(3308), signature.schnorr, digest));
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, signature.mldsa, std::span{signature.schnorr}.first(63), digest));
    std::array<unsigned char, 3310> oversized{};
    std::copy(signature.mldsa.begin(), signature.mldsa.end(), oversized.begin());
    BOOST_CHECK(!qlu::Verify(keys.mldsa, keys.schnorr, oversized, signature.schnorr, digest));
    qlu::Bytes32 invalid_secp;
    invalid_secp.fill(255);
    BOOST_CHECK(!qlu::Verify(keys.mldsa, invalid_secp, signature.mldsa, signature.schnorr, digest));
    master[0] ^= 1;
    const auto another = qlu::DeriveKeys(master);
    BOOST_CHECK(!qlu::Verify(another.mldsa, keys.schnorr, signature.mldsa, signature.schnorr, digest));
    BOOST_CHECK(!qlu::Verify(keys.mldsa, another.schnorr, signature.mldsa, signature.schnorr, digest));
}

BOOST_AUTO_TEST_CASE(nist_acvp_mldsa65_keygen_known_answer)
{
    // ACVP ML-DSA keyGen FIPS204 version42 tcId26, as published in OpenSSL
    // openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_dsa_keygen.txt.
    // Source file SHA256: 4ce166548af99bd678c26be58c65ed580b238aa35ba03f3913f743e331e943ce.
    // Compare SHA256 of the complete external 1952-byte expected public key.
    // This checks the installed provider independently of our self-sign/verify tests.
    std::array<unsigned char, 32> seed{
        0x8a,0xb6,0x44,0x8b,0xf5,0x8f,0x89,0x7d,0x52,0x8a,0x8d,0xe9,0xf8,0xe5,0x93,0x29,
        0xac,0x92,0x9a,0x9c,0xde,0x7e,0xdf,0x3e,0x27,0xe0,0x1b,0xc9,0xef,0x12,0x8a,0x67};
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx{
        EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", "provider=default"), EVP_PKEY_CTX_free};
    BOOST_REQUIRE(ctx);
    BOOST_REQUIRE_EQUAL(EVP_PKEY_keygen_init(ctx.get()), 1);
    OSSL_PARAM params[]{OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, seed.data(), seed.size()),
                        OSSL_PARAM_construct_end()};
    BOOST_REQUIRE_EQUAL(EVP_PKEY_CTX_set_params(ctx.get(), params), 1);
    EVP_PKEY* raw_key{nullptr};
    const int generated = EVP_PKEY_generate(ctx.get(), &raw_key);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key{raw_key, EVP_PKEY_free};
    BOOST_REQUIRE_EQUAL(generated, 1);
    std::array<unsigned char, qlu::MLDSA_PUBLIC_KEY_SIZE> public_key;
    size_t length{0};
    BOOST_REQUIRE_EQUAL(EVP_PKEY_get_octet_string_param(key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                        public_key.data(), public_key.size(), &length), 1);
    BOOST_REQUIRE_EQUAL(length, public_key.size());
    qlu::Bytes32 public_hash;
    CSHA256().Write(public_key.data(), public_key.size()).Finalize(public_hash.data());
    BOOST_CHECK_EQUAL(HexStr(public_hash), "b0cc1d6464e1528a478108d4be94be4aca4c7ae69d9595b1e6b752713442022a");
}

BOOST_AUTO_TEST_SUITE_END()
