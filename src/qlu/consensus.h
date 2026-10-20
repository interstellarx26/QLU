// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see COPYING.
#ifndef QLU_CONSENSUS_H
#define QLU_CONSENSUS_H

#include <primitives/transaction.h>
#include <uint256.h>
#include <cstddef>
#include <vector>

class CCoinsViewCache;
class TxValidationState;

namespace qlu {
inline constexpr uint32_t AUTH_VERSION{1};
inline constexpr size_t MAX_TX_INPUTS{16};
inline constexpr size_t MAX_TX_OUTPUTS{32};
inline constexpr size_t MAX_BLOCK_AUTHORIZATIONS{256};

/** Exact witness-v2/32 program, never Bitcoin's permissive unknown-witness semantics. */
bool IsHybridOutput(const CScript& script);
/** Non-witness structural rules, suitable for context-free block validation. */
bool CheckTransactionShape(const CTransaction& tx, TxValidationState& state);
/** Tagged single-SHA256, committing all transaction fields and all spent outputs. */
uint256 AuthorizationDigest(const CTransaction& tx, const std::vector<CTxOut>& spent,
                            uint32_t input_index, const uint256& genesis);
/** Strict hybrid authorization, independent of Bitcoin script caches/assumevalid. */
bool CheckInputs(const CTransaction& tx, TxValidationState& state,
                 const CCoinsViewCache& view, const uint256& genesis);
} // namespace qlu
#endif
