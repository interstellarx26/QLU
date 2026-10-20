// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see the accompanying file COPYING.

#include <qlu/crypto.h>
#include <support/cleanse.h>
#include <univalue.h>

#include <array>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
template <typename T> struct Cleansed {
    T value{};
    ~Cleansed() { memory_cleanse(&value, sizeof(value)); }
};

// UniValue is a general JSON parser, not a secure allocator. Clear all parsed
// strings before freeing them; this does not promise protection from paging,
// core dumps, a hostile OS, or copies made by the caller/runtime.
void CleanJSON(const UniValue& value)
{
    const auto& text = value.getValStr();
    if (!text.empty()) memory_cleanse(const_cast<char*>(text.data()), text.size());
    if (value.isObject() || value.isArray()) {
        for (const auto& child : value.getValues()) CleanJSON(child);
    }
}

struct InputJSON {
    UniValue value;
    ~InputJSON() { CleanJSON(value); }
};

int Nibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    throw std::runtime_error("invalid hex");
}

void Read32(const UniValue& value, qlu::Bytes32& out)
{
    if (!value.isStr() || value.get_str().size() != 64) throw std::runtime_error("invalid field");
    const auto& text = value.get_str();
    for (size_t i = 0; i < out.size(); ++i) out[i] = Nibble(text[i * 2]) * 16 + Nibble(text[i * 2 + 1]);
}

std::string Hex(std::span<const unsigned char> bytes)
{
    constexpr std::string_view alphabet{"0123456789abcdef"};
    std::string result(bytes.size() * 2, '0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        result[i * 2] = alphabet[bytes[i] >> 4];
        result[i * 2 + 1] = alphabet[bytes[i] & 15];
    }
    return result;
}
} // namespace

int main(int argc, char**)
{
    try {
        // The only interface is one bounded JSON object on stdin. Private keys
        // must never be passed in process arguments, node RPC, or output logs.
        if (argc != 1) throw std::runtime_error("unexpected arguments");
        Cleansed<std::array<char, 4097>> input;
        std::cin.read(input.value.data(), input.value.size());
        const auto length = std::cin.gcount();
        if (!std::cin.eof() || length > 4096) throw std::runtime_error("oversize input");
        InputJSON request;
        if (!request.value.read(std::string_view{input.value.data(), static_cast<size_t>(length)}) ||
            !request.value.isObject()) throw std::runtime_error("invalid object");
        const auto& action = request.value.find_value("action");
        if (!action.isStr()) throw std::runtime_error("missing action");
        const bool signing = action.get_str() == "sign";
        if (!signing && action.get_str() != "public") throw std::runtime_error("invalid action");
        std::set<std::string> expected{"action", "seed"};
        if (signing) expected.insert("digest");
        for (const auto& key : request.value.getKeys()) {
            if (expected.erase(key) != 1) throw std::runtime_error("unknown or duplicate field");
        }
        if (!expected.empty()) throw std::runtime_error("missing field");

        Cleansed<qlu::Bytes32> seed;
        Read32(request.value.find_value("seed"), seed.value);
        const auto keys = qlu::DeriveKeys(seed.value);
        UniValue result{UniValue::VOBJ};
        result.pushKV("policy_version", static_cast<int>(qlu::POLICY_VERSION));
        result.pushKV("mldsa_public", Hex(keys.mldsa));
        result.pushKV("schnorr_public", Hex(keys.schnorr));
        result.pushKV("key_commitment", Hex(qlu::KeyCommitment(keys)));
        if (signing) {
            qlu::Bytes32 digest;
            Read32(request.value.find_value("digest"), digest);
            const auto signature = qlu::Sign(seed.value, digest);
            result.pushKV("mldsa_signature", Hex(signature.mldsa));
            result.pushKV("schnorr_signature", Hex(signature.schnorr));
        }
        std::cout << result.write() << '\n';
        return 0;
    } catch (...) {
        // Never echo input, parser exceptions, or backend diagnostics that might
        // include secret material. No partial output is emitted on failure.
        std::cerr << "QLU key operation failed\n";
        return 1;
    }
}
