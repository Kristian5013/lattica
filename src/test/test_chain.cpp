// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// End-to-end test of the interfaces::Chain adapter (interfaces/chain.cpp): stand
// up a regtest ChainstateManager + mempool + ValidationSignals (immediate task
// runner), wrap it with MakeChain, and check
//   - the read surface: getHeight/getBlockHash/haveBlockOnDisk/findBlock/
//     havePruned/isInMempool on the genesis-only chain, and
//   - the notification bridge: after subscribing via handleNotifications, mining
//     block 1 delivers a blockConnected with the right height, hash and block data.

#include <interfaces/chain.h>
#include <node/context.h>
#include <interfaces/handler.h>

#include <validation.h>
#include <validationinterface.h>
#include <node/chainstate.h>
#include <node/blockstorage.h>
#include <kernel/context.h>
#include <kernel/chain.h>
#include <kernel/notifications_interface.h>
#include <kernel/caches.h>
#include <kernel/chainstatemanager_opts.h>
#include <kernel/blockmanager_opts.h>
#include <kernel/mempool_options.h>
#include <txmempool.h>
#include <consensus/validation.h>
#include <consensus/merkle.h>
#include <consensus/amount.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <pow.h>
#include <hash.h>
#include <sync.h>
#include <uint256.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <util/time.h>
#include <util/fs.h>
#include <dbwrapper.h>
#include <util/translation.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

struct TestNotifications : public interfaces::Chain::Notifications {
    int connected{0};
    int last_height{-1};
    uint256 last_hash;
    bool had_data{false};
    void blockConnected(const kernel::ChainstateRole&, const interfaces::BlockInfo& block) override
    {
        ++connected;
        last_height = block.height;
        last_hash = block.hash;
        had_data = (block.data != nullptr && !block.data->vtx.empty());
    }
};
} // namespace

int main()
{
    const char* lad = std::getenv("LOCALAPPDATA");
    const std::string base = (lad && *lad) ? (std::string(lad) + "/lattica_chain_iface_test")
                                           : std::string("lattica_chain_iface_test");
    const std::filesystem::path dd(base);
    std::filesystem::remove_all(dd);
    std::filesystem::create_directories(dd / "blocks");
    const fs::path datadir = fs::PathFromString(base);
    const fs::path blocksdir = fs::PathFromString(base + "/blocks");

    kernel::Context context;
    kernel::Notifications notifications;
    util::SignalInterrupt interrupt;
    const std::unique_ptr<const CChainParams> params = CChainParams::RegTest();

    SetMockTime(params->GenesisBlock().nTime + 600);

    // A validation-signal bus with an immediate (synchronous) task runner, wired
    // into the chainstate so block-connected events fire through it.
    node::NodeContext node_context;
    node_context.validation_signals = std::make_unique<ValidationSignals>(std::make_unique<util::ImmediateTaskRunner>());
    ValidationSignals& validation_signals = *node_context.validation_signals;

    ChainstateManager::Options chainman_opts{
        .chainparams = *params,
        .datadir = datadir,
        .notifications = notifications,
        .signals = &validation_signals,
    };
    node::BlockManager::Options blockman_opts{
        .chainparams = *params,
        .use_xor = false,
        .blocks_dir = blocksdir,
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = blocksdir,
            .cache_bytes = 1 << 20,
            .memory_only = true,
        },
    };
    node_context.chainman = std::make_unique<ChainstateManager>(interrupt, chainman_opts, blockman_opts);
    ChainstateManager& chainman = *node_context.chainman;

    kernel::MemPoolOptions mpopts;
    bilingual_str mperr;
    node_context.mempool = std::make_unique<CTxMemPool>(mpopts, mperr);
    CTxMemPool& mempool = *node_context.mempool;

    kernel::CacheSizes cache_sizes{1 << 22};
    node::ChainstateLoadOptions load_opts;
    load_opts.mempool = &mempool;
    load_opts.coins_db_in_memory = true;

    const auto [status, load_err] = node::LoadChainstate(chainman, cache_sizes, load_opts);
    Check("LoadChainstate success", status == node::ChainstateLoadStatus::SUCCESS);

    {
        BlockValidationState state;
        Check("activate genesis chain", chainman.ActiveChainstate().ActivateBestChain(state, nullptr));
    }

    // Build the chain adapter under test. MakeChain takes the NodeContext now,
    // so assemble one holding the pieces this test built by hand.
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(node_context);

    const uint256 genesis_hash = params->GetConsensus().hashGenesisBlock;

    // Read surface on the genesis-only chain.
    Check("getHeight == 0 (genesis only)", chain->getHeight() == std::optional<int>(0));
    Check("getBlockHash(0) == genesis", chain->getBlockHash(0) == genesis_hash);
    Check("haveBlockOnDisk(0)", chain->haveBlockOnDisk(0));
    Check("havePruned() == false", !chain->havePruned());
    Check("getPruneHeight() == nullopt", chain->getPruneHeight() == std::nullopt);
    {
        int h = -99;
        int64_t t = 0;
        bool ok = chain->findBlock(genesis_hash, interfaces::FoundBlock().height(h).time(t));
        Check("findBlock(genesis) found with height 0", ok && h == 0 && t == (int64_t)params->GenesisBlock().nTime);
        bool unknown = chain->findBlock(uint256::ONE, interfaces::FoundBlock());
        Check("findBlock(unknown) not found", !unknown);
    }

    // Subscribe to notifications (after genesis is already connected).
    auto notif = std::make_shared<TestNotifications>();
    std::unique_ptr<interfaces::Handler> handler = chain->handleNotifications(notif);

    // Build and process a valid block 1 on top of genesis.
    CBlock block1;
    {
        const CBlock& genesis = params->GenesisBlock();
        block1.nVersion = 4;
        block1.hashPrevBlock = genesis.GetHash();
        block1.nTime = genesis.nTime + 1;
        block1.nBits = genesis.nBits;
        block1.nNonce = 0;

        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vin[0].prevout.SetNull();
        cb.vin[0].scriptSig = CScript() << 1 << OP_0;
        cb.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        cb.vout.resize(1);
        cb.vout[0].nValue = GetBlockSubsidy(1, params->GetConsensus());
        cb.vout[0].scriptPubKey = CScript() << OP_TRUE;
        block1.vtx.push_back(MakeTransactionRef(std::move(cb)));
        block1.hashMerkleRoot = BlockMerkleRoot(block1);

        while (!CheckProofOfWork(block1.GetPoWHash(), block1.nBits, params->GetConsensus())) ++block1.nNonce;
    }

    auto pblock = std::make_shared<const CBlock>(block1);
    bool new_block = false;
    Check("ProcessNewBlock(block1) accepted",
          chainman.ProcessNewBlock(pblock, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block) && new_block);

    chain->waitForNotifications();

    // The adapter delivered blockConnected for block 1 with the right payload.
    Check("blockConnected fired exactly once", notif->connected == 1);
    Check("blockConnected height == 1", notif->last_height == 1);
    Check("blockConnected hash == block1", notif->last_hash == block1.GetHash());
    Check("blockConnected carried block data", notif->had_data);

    // Read surface reflects the new tip.
    Check("getHeight == 1 after block 1", chain->getHeight() == std::optional<int>(1));
    Check("getBlockHash(1) == block1", chain->getBlockHash(1) == block1.GetHash());
    Check("isInMempool(coinbase) == false", !chain->isInMempool(block1.vtx[0]->GetHash()));

    handler->disconnect();
    chain->waitForNotifications();

    std::filesystem::remove_all(dd);
    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
