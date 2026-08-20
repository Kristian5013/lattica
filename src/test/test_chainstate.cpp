// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// End-to-end sanity check of the validation engine: stand up a minimal
// ChainstateManager on regtest (in-memory UTXO db, a temp block-file dir),
// load and activate the genesis block, then build a valid block 1 (coinbase
// with the BIP34 height, mined to satisfy the SHA3-256d target) and drive it
// through ProcessNewBlock -> AcceptBlock -> ConnectBlock -> the
// UTXO set, confirming the active chain advances to height 1.

#include <validation.h>
#include <node/chainstate.h>
#include <node/blockstorage.h>
#include <kernel/context.h>
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
#include <script/script.h>
#include <pow.h>
#include <hash.h>
#include <sync.h>
#include <util/signalinterrupt.h>
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
} // namespace

int main()
{
    // Use a pure-ASCII absolute temp path: the repo lives under a Cyrillic
    // directory, and fs::path's u8 conversion would mangle a non-ASCII path.
    const char* lad = std::getenv("LOCALAPPDATA");
    const std::string base = (lad && *lad) ? (std::string(lad) + "/lattica_chainstate_test")
                                           : std::string("lattica_chainstate_test");
    const std::filesystem::path dd(base);
    std::filesystem::remove_all(dd);
    std::filesystem::create_directories(dd / "blocks");
    const fs::path datadir = fs::PathFromString(base);
    const fs::path blocksdir = fs::PathFromString(base + "/blocks");

    kernel::Context context;
    kernel::Notifications notifications;
    util::SignalInterrupt interrupt;
    const std::unique_ptr<const CChainParams> params = CChainParams::RegTest();

    // The genesis timestamp is in the future relative to the real clock, so pin
    // the node clock just past it; otherwise block 1 is rejected as time-too-new.
    SetMockTime(params->GenesisBlock().nTime + 600);

    ChainstateManager::Options chainman_opts{
        .chainparams = *params,
        .datadir = datadir,
        .notifications = notifications,
    };
    node::BlockManager::Options blockman_opts{
        .chainparams = *params,
        .use_xor = false,
        .blocks_dir = blocksdir,
        .notifications = notifications,
        .block_tree_db_params = DBParams{
            .path = blocksdir,        // unused: in-memory
            .cache_bytes = 1 << 20,
            .memory_only = true,
        },
    };
    ChainstateManager chainman{interrupt, chainman_opts, blockman_opts};

    kernel::MemPoolOptions mpopts;
    bilingual_str mperr;
    CTxMemPool mempool{mpopts, mperr};

    kernel::CacheSizes cache_sizes{1 << 22};
    node::ChainstateLoadOptions load_opts;
    load_opts.mempool = &mempool;
    load_opts.coins_db_in_memory = true;

    const auto [status, load_err] = node::LoadChainstate(chainman, cache_sizes, load_opts);
    Check("LoadChainstate success", status == node::ChainstateLoadStatus::SUCCESS);

    // Activate the genesis block (height 0).
    {
        BlockValidationState state;
        bool ok = chainman.ActiveChainstate().ActivateBestChain(state, nullptr);
        Check("activate genesis chain", ok);
    }
    {
        LOCK(chainman.GetMutex());
        Check("active height == 0 (genesis)", chainman.ActiveHeight() == 0);
        Check("tip is genesis", chainman.ActiveTip() && chainman.ActiveTip()->GetBlockHash() == params->GetConsensus().hashGenesisBlock);
    }

    // Build a valid block 1 on top of genesis.
    CBlock block1;
    {
        const CBlock& genesis = params->GenesisBlock();
        block1.nVersion = 4;
        block1.hashPrevBlock = genesis.GetHash();
        block1.nTime = genesis.nTime + 1;
        block1.nBits = genesis.nBits; // regtest does not retarget
        block1.nNonce = 0;

        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vin[0].prevout.SetNull();
        cb.vin[0].scriptSig = CScript() << 1 << OP_0; // BIP34 height (1) + extra-nonce byte (>=2 bytes)
        cb.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        cb.vout.resize(1);
        cb.vout[0].nValue = GetBlockSubsidy(1, params->GetConsensus());
        cb.vout[0].scriptPubKey = CScript() << OP_TRUE;
        block1.vtx.push_back(MakeTransactionRef(std::move(cb)));
        block1.hashMerkleRoot = BlockMerkleRoot(block1);

        // Mine the block: grind the nonce until the SHA3-256d PoW is under target.
        while (!CheckProofOfWork(block1.GetPoWHash(), block1.nBits, params->GetConsensus())) ++block1.nNonce;
    }

    auto pblock = std::make_shared<const CBlock>(block1);
    bool new_block = false;
    bool processed = chainman.ProcessNewBlock(pblock, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block);
    Check("ProcessNewBlock(block1) accepted", processed && new_block);

    {
        LOCK(chainman.GetMutex());
        Check("active height == 1 after block 1", chainman.ActiveHeight() == 1);
        Check("tip is block 1", chainman.ActiveTip() && chainman.ActiveTip()->GetBlockHash() == block1.GetHash());
        // The coinbase output is now a spendable UTXO.
        const Coin& coin = chainman.ActiveChainstate().CoinsTip().AccessCoin(COutPoint(block1.vtx[0]->GetHash(), 0));
        Check("coinbase UTXO present at height 1", !coin.IsSpent() && coin.nHeight == 1 && coin.IsCoinBase());
    }

    std::filesystem::remove_all(dd);
    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
