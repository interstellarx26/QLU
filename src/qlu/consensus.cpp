// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see COPYING.
#include <qlu/consensus.h>
#include <qlu/crypto.h>
#include <coins.h>
#include <consensus/validation.h>
#include <hash.h>
#include <script/script.h>

#include <algorithm>
#include <stdexcept>

namespace qlu {
bool IsHybridOutput(const CScript& script)
{
    return script.size() == 34 && script[0] == OP_2 && script[1] == 32;
}

bool CheckTransactionShape(const CTransaction& tx, TxValidationState& state)
{
    if (tx.version != 2) return state.Invalid(TxValidationResult::TX_CONSENSUS, "qlu-tx-version");
    if (tx.vin.empty() || tx.vin.size() > MAX_TX_INPUTS || tx.vout.empty() || tx.vout.size() > MAX_TX_OUTPUTS) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "qlu-tx-limits");
    }
    for (const auto& out : tx.vout) {
        if (IsHybridOutput(out.scriptPubKey)) continue;
        // Provably unspendable metadata (including SegWit commitments), never value-bearing.
        if (out.nValue == 0 && !out.scriptPubKey.empty() && out.scriptPubKey[0] == OP_RETURN && out.scriptPubKey.size() <= 83) continue;
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "qlu-output-policy");
    }
    if (!tx.IsCoinBase()) {
        for (const auto& in : tx.vin) {
            if (!in.scriptSig.empty()) return state.Invalid(TxValidationResult::TX_CONSENSUS, "qlu-scriptsig");
        }
    }
    return true;
}

uint256 AuthorizationDigest(const CTransaction& tx, const std::vector<CTxOut>& spent,
                            uint32_t input_index, const uint256& genesis)
{
    if (spent.size() != tx.vin.size() || input_index >= tx.vin.size()) throw std::invalid_argument("QLU authorization inputs mismatch");
    auto hash = TaggedHash("QLU/tx-auth/v1");
    hash << genesis << AUTH_VERSION << input_index << TX_NO_WITNESS(tx) << spent;
    return hash.GetSHA256();
}

bool CheckInputs(const CTransaction& tx, TxValidationState& state,
                 const CCoinsViewCache& view, const uint256& genesis)
{
    if (!CheckTransactionShape(tx, state)) return false;
    if (tx.IsCoinBase()) return true;
    std::vector<CTxOut> spent;
    spent.reserve(tx.vin.size());
    // Check all inexpensive structure and commitments before any signature operations.
    for (const auto& in : tx.vin) {
        const auto& coin = view.AccessCoin(in.prevout);
        if (coin.IsSpent()) return state.Invalid(TxValidationResult::TX_CONSENSUS, "qlu-input-missing");
        if (!IsHybridOutput(coin.out.scriptPubKey)) return state.Invalid(TxValidationResult::TX_CONSENSUS, "qlu-input-policy");
        const auto& w = in.scriptWitness.stack;
        if (w.size() != 4 || w[0].size() != MLDSA_PUBLIC_KEY_SIZE || w[1].size() != 32 ||
            w[2].size() != MLDSA_SIGNATURE_SIZE || w[3].size() != 64) {
            // Do not poison a txid with witness-stripped data received from a peer.
            return state.Invalid(tx.HasWitness() ? TxValidationResult::TX_WITNESS_MUTATED : TxValidationResult::TX_WITNESS_STRIPPED,
                                 "qlu-witness-shape");
        }
        PublicKeys keys;
        std::copy(w[0].begin(), w[0].end(), keys.mldsa.begin());
        std::copy(w[1].begin(), w[1].end(), keys.schnorr.begin());
        const auto commitment = KeyCommitment(keys);
        if (!std::equal(commitment.begin(), commitment.end(), coin.out.scriptPubKey.begin() + 2)) {
            return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "qlu-key-commitment");
        }
        spent.push_back(coin.out);
    }
    for (uint32_t i = 0; i < tx.vin.size(); ++i) {
        const auto& w = tx.vin[i].scriptWitness.stack;
        const auto digest = AuthorizationDigest(tx, spent, i, genesis);
        if (!Verify(w[0], w[1], w[2], w[3], std::span<const unsigned char, 32>{digest.begin(), 32})) {
            return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "qlu-hybrid-signature");
        }
    }
    return true;
}
} // namespace qlu
