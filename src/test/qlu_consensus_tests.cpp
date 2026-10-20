// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see COPYING.
#include <qlu/consensus.h>
#include <qlu/crypto.h>
#include <coins.h>
#include <consensus/validation.h>
#include <kernel/chainparams.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <boost/test/unit_test.hpp>

namespace {
struct HybridFixture : BasicTestingSetup {
    qlu::Bytes32 master{};
    CCoinsView base;
    CCoinsViewCache coins{&base};
    CMutableTransaction tx;
    std::vector<CTxOut> spent;
    uint256 genesis{CChainParams::QLUDevNet()->GetConsensus().hashGenesisBlock};
    HybridFixture() {
        master.fill(0x43);
        auto commitment = qlu::KeyCommitment(qlu::DeriveKeys(master));
        CScript policy = CScript() << OP_2 << std::vector<unsigned char>(commitment.begin(), commitment.end());
        for (int i = 0; i < 2; ++i) {
            COutPoint point{Txid::FromUint256(uint256{static_cast<uint8_t>(i + 1)}), 0};
            tx.vin.emplace_back(point);
            spent.emplace_back(1000000, policy);
            coins.AddCoin(point, Coin{CTxOut{spent.back()}, 1, false}, false);
        }
        tx.vout.emplace_back(1900000, policy);
        Authorize();
    }
    void Authorize() {
        const auto keys = qlu::DeriveKeys(master);
        for (uint32_t i = 0; i < tx.vin.size(); ++i) {
            auto digest = qlu::AuthorizationDigest(CTransaction{tx}, spent, i, genesis);
            const auto signature = qlu::Sign(master, std::span<const unsigned char, 32>{digest.begin(), 32});
            tx.vin[i].scriptWitness.stack = {
                {keys.mldsa.begin(), keys.mldsa.end()}, {keys.schnorr.begin(), keys.schnorr.end()},
                {signature.mldsa.begin(), signature.mldsa.end()}, {signature.schnorr.begin(), signature.schnorr.end()}};
        }
    }
    bool Valid(const CMutableTransaction& candidate) {
        TxValidationState state;
        return qlu::CheckInputs(CTransaction{candidate}, state, coins, genesis);
    }
};
}

BOOST_FIXTURE_TEST_SUITE(qlu_consensus_tests, HybridFixture)
BOOST_AUTO_TEST_CASE(both_signatures_and_all_fields_required)
{
    BOOST_CHECK(Valid(tx));
    auto changed = tx;
    changed.vout[0].nValue--;
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].nSequence--;
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.nLockTime++;
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].scriptWitness.stack[2][0] ^= 1;
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].scriptWitness.stack[3][0] ^= 1;
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].scriptWitness.stack.erase(changed.vin[0].scriptWitness.stack.begin() + 2);
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].scriptWitness.stack[0][0] ^= 1;
    BOOST_CHECK(!Valid(changed));
    changed = tx; std::swap(changed.vin[0].scriptWitness, changed.vin[1].scriptWitness);
    BOOST_CHECK(!Valid(changed));
    TxValidationState state;
    BOOST_CHECK(!qlu::CheckInputs(CTransaction{tx}, state, coins, uint256{17}));
    spent[1].nValue--;
    Authorize();
    BOOST_CHECK(!Valid(tx)); // Signing a false other-input amount fails.
}
BOOST_AUTO_TEST_CASE(no_legacy_or_unknown_output_escape)
{
    for (auto script : {CScript() << OP_TRUE, CScript() << OP_1 << std::vector<unsigned char>(32, 0),
                        CScript() << OP_3 << std::vector<unsigned char>(32, 0),
                        CScript() << OP_0 << std::vector<unsigned char>(20, 0),
                        CScript() << OP_RETURN}) {
        auto changed = tx;
        changed.vout[0].scriptPubKey = script;
        TxValidationState state;
        BOOST_CHECK(!qlu::CheckTransactionShape(CTransaction{changed}, state));
    }
    auto changed = tx; changed.version = 3;
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].scriptSig << OP_0;
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].scriptWitness.stack.push_back({});
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin[0].scriptWitness.stack[2].push_back(0);
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vout.assign(33, tx.vout[0]);
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vin.assign(17, tx.vin[0]);
    BOOST_CHECK(!Valid(changed));
    changed = tx; changed.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(36, 0));
    TxValidationState state;
    BOOST_CHECK(qlu::CheckTransactionShape(CTransaction{changed}, state));
}
BOOST_AUTO_TEST_CASE(legacy_prevout_is_never_spendable)
{
    coins.SpendCoin(tx.vin[0].prevout);
    coins.AddCoin(tx.vin[0].prevout, Coin{CTxOut{1000000, CScript() << OP_TRUE}, 1, false}, false);
    BOOST_CHECK(!Valid(tx));
}
BOOST_AUTO_TEST_CASE(block_authorization_limit_boundary)
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN);
    block.vtx.push_back(MakeTransactionRef(coinbase));
    for (uint32_t group = 0; group < 16; ++group) {
        CMutableTransaction item;
        for (uint8_t i = 1; i <= 16; ++i) item.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{i}), group});
        item.vout.emplace_back(0, CScript() << OP_RETURN);
        block.vtx.push_back(MakeTransactionRef(item));
    }
    BlockValidationState good_state;
    const auto params = CChainParams::QLUDevNet();
    BOOST_CHECK(CheckBlock(block, good_state, params->GetConsensus(), false, false));
    CMutableTransaction extra;
    extra.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{42}), 17});
    extra.vout.emplace_back(0, CScript() << OP_RETURN);
    block.vtx.push_back(MakeTransactionRef(extra));
    BlockValidationState bad_state;
    BOOST_CHECK(!CheckBlock(block, bad_state, params->GetConsensus(), false, false));
    BOOST_CHECK_EQUAL(bad_state.GetRejectReason(), "qlu-block-auth-limit");
}
BOOST_AUTO_TEST_SUITE_END()
