// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init.h>
#include <common/args.h>
#include <interfaces/init.h>
#include <rpc/server.h>

#include <boost/test/unit_test.hpp>
#include <test/util/common.h>
#include <test/util/setup_common.h>

using node::NodeContext;

//! Like BasicTestingSetup, but using regtest network instead of mainnet.
struct InitTestSetup : BasicTestingSetup {
    InitTestSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

BOOST_FIXTURE_TEST_SUITE(node_init_tests, InitTestSetup)

BOOST_AUTO_TEST_CASE(qlu_private_defaults)
{
    ArgsManager args;
    SetupServerArgs(args, true);
    args.ForceSetArg("-chain", "qludev");
    InitParameterInteraction(args);
    BOOST_CHECK_EQUAL(args.GetArg("-bind", ""), "127.0.0.1");
    BOOST_CHECK_EQUAL(args.GetArg("-connect", ""), "0");
    BOOST_CHECK(args.GetBoolArg("-listen", false));
    for (const auto* option : {"-dnsseed", "-fixedseeds", "-discover", "-natpmp", "-listenonion", "-i2pacceptincoming"}) {
        BOOST_CHECK(!args.GetBoolArg(option, true));
    }

    // An explicit no-listen operator choice must not acquire a conflicting bind.
    ArgsManager no_listen;
    SetupServerArgs(no_listen, true);
    no_listen.ForceSetArg("-chain", "qludev");
    no_listen.ForceSetArg("-listen", "0");
    InitParameterInteraction(no_listen);
    BOOST_CHECK(!no_listen.GetBoolArg("-listen", true));
    BOOST_CHECK(!no_listen.IsArgSet("-bind"));
}

//! Custom implementation of interfaces::Init for testing.
class TestInit : public interfaces::Init
{
public:
    TestInit(NodeContext& node) : m_node(node)
    {
        InitContext(m_node);
        m_node.init = this;
    }
    std::unique_ptr<interfaces::Chain> makeChain() override { return interfaces::MakeChain(m_node); }
    std::unique_ptr<interfaces::WalletLoader> makeWalletLoader(interfaces::Chain& chain) override
    {
        return MakeWalletLoader(chain, *Assert(m_node.args));
    }
    NodeContext& m_node;
};

BOOST_AUTO_TEST_CASE(init_test)
{
    // Clear state set by BasicTestingSetup that AppInitMain assumes is unset.
    LogInstance().DisconnectTestLogger();
    m_node.args->SetConfigFilePath({});

    // Prevent the test from trying to listen on ports 8332 and 8333.
    m_node.args->ForceSetArg("-server", "0");
    m_node.args->ForceSetArg("-listen", "0");

    // Run through initialization and shutdown code.
    TestInit init{m_node};
    BOOST_CHECK(AppInitInterfaces(m_node));
    BOOST_CHECK(AppInitMain(m_node));
    Interrupt(m_node);
    Shutdown(m_node);
}

BOOST_AUTO_TEST_SUITE_END()
