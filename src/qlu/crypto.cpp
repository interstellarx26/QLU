// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see the accompanying file COPYING.

#include <qlu/crypto.h>

#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <memory>
#include <stdexcept>
#include <string_view>

namespace qlu {
namespace {
constexpr std::string_view MLDSA_CONTEXT{"QLU/hybrid/v1"};
using PKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PKeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using SignatureAlgorithm = std::unique_ptr<EVP_SIGNATURE, decltype(&EVP_SIGNATURE_free)>;
using SecpContext = std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>;

template <typename T> struct Cleansed {
    T value{};
    Cleansed() = default;
    Cleansed(const Cleansed&) = delete;
    Cleansed& operator=(const Cleansed&) = delete;
    ~Cleansed() { memory_cleanse(&value, sizeof(value)); }
};

[[noreturn]] void BackendError()
{
    throw std::runtime_error("QLU cryptographic operation failed");
}

void DeriveSecret(std::span<const unsigned char, 32> master,
                  std::string_view label, Bytes32& output,
                  std::span<const unsigned char> suffix = {})
{
    // HMAC-SHA256 with a uniform secret master, not a password KDF.
    CHMAC_SHA256 hmac{master.data(), master.size()};
    hmac.Write(reinterpret_cast<const unsigned char*>(label.data()), label.size());
    if (!suffix.empty()) hmac.Write(suffix.data(), suffix.size());
    hmac.Finalize(output.data());
    memory_cleanse(&hmac, sizeof(hmac));
}

PKey MLDSAPrivate(std::span<const unsigned char, 32> master)
{
    Cleansed<Bytes32> seed;
    DeriveSecret(master, "QLU/ML-DSA-65/seed/v1", seed.value);
    PKeyContext ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", "provider=default"), EVP_PKEY_CTX_free};
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1) BackendError();
    OSSL_PARAM params[]{
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, seed.value.data(), seed.value.size()),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_CTX_set_params(ctx.get(), params) != 1) BackendError();
    EVP_PKEY* raw_key{nullptr};
    if (EVP_PKEY_generate(ctx.get(), &raw_key) != 1) {
        EVP_PKEY_free(raw_key);
        BackendError();
    }
    return PKey{raw_key, EVP_PKEY_free};
}

PKey MLDSAPublic(std::span<const unsigned char> public_key)
{
    PKeyContext ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", "provider=default"), EVP_PKEY_CTX_free};
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) return PKey{nullptr, EVP_PKEY_free};
    OSSL_PARAM params[]{
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                         const_cast<unsigned char*>(public_key.data()), public_key.size()),
        OSSL_PARAM_construct_end(),
    };
    EVP_PKEY* raw_key{nullptr};
    if (EVP_PKEY_fromdata(ctx.get(), &raw_key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_free(raw_key);
        raw_key = nullptr;
    }
    return PKey{raw_key, EVP_PKEY_free};
}

SecpContext SigningContext()
{
    SecpContext ctx{secp256k1_context_create(SECP256K1_CONTEXT_NONE), secp256k1_context_destroy};
    Cleansed<Bytes32> random;
    if (!ctx || RAND_priv_bytes(random.value.data(), random.value.size()) != 1 ||
        secp256k1_context_randomize(ctx.get(), random.value.data()) != 1) BackendError();
    return ctx;
}

void SchnorrKeypair(const secp256k1_context* ctx,
                    std::span<const unsigned char, 32> master, secp256k1_keypair& keypair)
{
    Cleansed<Bytes32> secret;
    // Rejection sampling, never reduction modulo the curve order. Counter is big endian.
    for (uint32_t counter = 0; ; ++counter) {
        const std::array<unsigned char, 4> encoded_counter{
            static_cast<unsigned char>(counter >> 24), static_cast<unsigned char>(counter >> 16),
            static_cast<unsigned char>(counter >> 8), static_cast<unsigned char>(counter)};
        DeriveSecret(master, "QLU/BIP340/secret/v1", secret.value, encoded_counter);
        if (secp256k1_ec_seckey_verify(ctx, secret.value.data()) == 1) {
            if (secp256k1_keypair_create(ctx, &keypair, secret.value.data()) != 1) BackendError();
            return;
        }
        if (counter == UINT32_MAX) BackendError();
    }
}

OSSL_PARAM ContextParameter()
{
    return OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        const_cast<char*>(MLDSA_CONTEXT.data()), MLDSA_CONTEXT.size());
}
} // namespace

PublicKeys DeriveKeys(std::span<const unsigned char, 32> master)
{
    PublicKeys result;
    const auto ml_key = MLDSAPrivate(master);
    size_t length{0};
    if (EVP_PKEY_get_octet_string_param(ml_key.get(), OSSL_PKEY_PARAM_PUB_KEY,
        result.mldsa.data(), result.mldsa.size(), &length) != 1 || length != result.mldsa.size()) BackendError();
    auto secp = SigningContext();
    Cleansed<secp256k1_keypair> keypair;
    SchnorrKeypair(secp.get(), master, keypair.value);
    secp256k1_xonly_pubkey public_key;
    if (secp256k1_keypair_xonly_pub(secp.get(), &public_key, nullptr, &keypair.value) != 1 ||
        secp256k1_xonly_pubkey_serialize(secp.get(), result.schnorr.data(), &public_key) != 1) BackendError();
    return result;
}

HybridSignature Sign(std::span<const unsigned char, 32> master,
                     std::span<const unsigned char, 32> digest)
{
    HybridSignature result;
    const auto ml_key = MLDSAPrivate(master);
    PKeyContext ml_ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, ml_key.get(), "provider=default"), EVP_PKEY_CTX_free};
    SignatureAlgorithm algorithm{EVP_SIGNATURE_fetch(nullptr, "ML-DSA-65", "provider=default"), EVP_SIGNATURE_free};
    OSSL_PARAM params[]{ContextParameter(), OSSL_PARAM_construct_end()};
    size_t length{result.mldsa.size()};
    // Pure ML-DSA signs the canonical 32-byte transaction digest as its message.
    // The provider uses hedged randomness by default; no deterministic/test mode.
    if (!ml_ctx || !algorithm || EVP_PKEY_sign_message_init(ml_ctx.get(), algorithm.get(), params) != 1 ||
        EVP_PKEY_sign(ml_ctx.get(), result.mldsa.data(), &length, digest.data(), digest.size()) != 1 ||
        length != result.mldsa.size()) BackendError();
    auto secp = SigningContext();
    Cleansed<secp256k1_keypair> keypair;
    SchnorrKeypair(secp.get(), master, keypair.value);
    Cleansed<Bytes32> auxiliary;
    if (RAND_priv_bytes(auxiliary.value.data(), auxiliary.value.size()) != 1 ||
        secp256k1_schnorrsig_sign32(secp.get(), result.schnorr.data(), digest.data(),
                                  &keypair.value, auxiliary.value.data()) != 1) BackendError();
    return result;
}

bool Verify(std::span<const unsigned char> mldsa_public,
            std::span<const unsigned char> schnorr_public,
            std::span<const unsigned char> mldsa_signature,
            std::span<const unsigned char> schnorr_signature,
            std::span<const unsigned char, 32> digest)
{
    if (mldsa_public.size() != MLDSA_PUBLIC_KEY_SIZE || schnorr_public.size() != 32 ||
        mldsa_signature.size() != MLDSA_SIGNATURE_SIZE || schnorr_signature.size() != 64) return false;
    secp256k1_xonly_pubkey secp_key;
    if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &secp_key, schnorr_public.data()) != 1 ||
        secp256k1_schnorrsig_verify(secp256k1_context_static, schnorr_signature.data(),
                                  digest.data(), digest.size(), &secp_key) != 1) return false;
    auto ml_key = MLDSAPublic(mldsa_public);
    if (!ml_key) return false;
    PKeyContext ml_ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, ml_key.get(), "provider=default"), EVP_PKEY_CTX_free};
    SignatureAlgorithm algorithm{EVP_SIGNATURE_fetch(nullptr, "ML-DSA-65", "provider=default"), EVP_SIGNATURE_free};
    OSSL_PARAM params[]{ContextParameter(), OSSL_PARAM_construct_end()};
    return ml_ctx && algorithm &&
        EVP_PKEY_verify_message_init(ml_ctx.get(), algorithm.get(), params) == 1 &&
        EVP_PKEY_verify(ml_ctx.get(), mldsa_signature.data(), mldsa_signature.size(), digest.data(), digest.size()) == 1;
}

Bytes32 KeyCommitment(const PublicKeys& keys)
{
    constexpr std::string_view tag{"QLU/key-commitment/v1"};
    Bytes32 tag_hash, result;
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size()).Finalize(tag_hash.data());
    CSHA256().Write(tag_hash.data(), tag_hash.size()).Write(tag_hash.data(), tag_hash.size())
        .Write(&POLICY_VERSION, 1).Write(keys.mldsa.data(), keys.mldsa.size())
        .Write(keys.schnorr.data(), keys.schnorr.size()).Finalize(result.data());
    return result;
}

bool SelfTest() noexcept
{
    try {
        // Public fixture only. It must never receive funds. The fixed outputs
        // detect domain/serialization drift as well as backend unavailability.
        Bytes32 master, digest;
        for (size_t i = 0; i < master.size(); ++i) master[i] = i;
        digest.fill(42);
        constexpr Bytes32 expected_public_hash{
            0xa4,0x77,0x43,0x74,0x0f,0x26,0xc8,0x33,0x44,0xa8,0xd0,0x6d,0x03,0x99,0xa4,0x90,
            0x43,0xdb,0xfd,0x15,0xa1,0x4c,0x74,0x4b,0xf7,0xd1,0xe6,0x18,0x92,0x4d,0x8e,0x53};
        constexpr Bytes32 expected_commitment{
            0xe5,0xc4,0x62,0xb3,0x9f,0xea,0xa3,0x2e,0xa3,0x8c,0x22,0x67,0x33,0x9e,0xec,0xa7,
            0x77,0xf9,0xff,0x69,0x26,0xb1,0x77,0xf2,0x58,0x3f,0xd9,0xa8,0xbd,0x3d,0xcb,0x12};
        const auto keys = DeriveKeys(master);
        Bytes32 public_hash;
        CSHA256().Write(keys.mldsa.data(), keys.mldsa.size()).Finalize(public_hash.data());
        if (public_hash != expected_public_hash || KeyCommitment(keys) != expected_commitment) return false;
        const auto signature = Sign(master, digest);
        if (!Verify(keys.mldsa, keys.schnorr, signature.mldsa, signature.schnorr, digest)) return false;
        if (Verify(keys.mldsa, keys.schnorr, {}, signature.schnorr, digest) ||
            Verify(keys.mldsa, keys.schnorr, signature.mldsa, {}, digest)) return false;
        auto damaged = signature;
        damaged.mldsa[0] ^= 1;
        if (Verify(keys.mldsa, keys.schnorr, damaged.mldsa, damaged.schnorr, digest)) return false;
        damaged = signature;
        damaged.schnorr[0] ^= 1;
        if (Verify(keys.mldsa, keys.schnorr, damaged.mldsa, damaged.schnorr, digest)) return false;
        digest[0] ^= 1;
        return !Verify(keys.mldsa, keys.schnorr, signature.mldsa, signature.schnorr, digest);
    } catch (...) {
        return false;
    }
}
} // namespace qlu
