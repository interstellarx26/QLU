# Copyright (c) 2026 The QLU developers
# Distributed under the MIT software license, see the accompanying file COPYING.

# ML-DSA support first shipped in OpenSSL 3.5. Never silently fall back to classical signatures.
add_library(qlu_crypto STATIC crypto.cpp)
target_link_libraries(qlu_crypto PRIVATE core_interface bitcoin_crypto secp256k1 OpenSSL::Crypto)

add_executable(qlu-keytool keytool.cpp)
target_link_libraries(qlu-keytool PRIVATE core_interface qlu_crypto univalue bitcoin_crypto)
