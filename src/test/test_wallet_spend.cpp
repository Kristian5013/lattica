// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// End-to-end test of wallet transaction creation (wallet/spend.cpp CreateTransaction):
// stand up a regtest ChainstateManager + mempool + MakeChain, attach a funded CWallet,
// and build a transaction through the full coin-selection + fee + change + sign path.
// Asserts the result conserves value (sum(inputs) == sum(outputs) + fee), pays the
// recipient, leaves change to the wallet, and that every input passes consensus
// VerifyScript with the real ML-DSA witness. This is the runtime counterpart to the
// static size-model check in test_wallet (the fee loop needs a live interfaces::Chain).

#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/db.h>
#include <wallet/receive.h>
#include <wallet/spend.h>

#include <consensus/merkle.h>
#include <hash.h>
#include <pow.h>

#include <interfaces/chain.h>
#include <validation.h>
#include <validationinterface.h>
#include <node/chainstate.h>
#include <node/blockstorage.h>
#include <kernel/context.h>
#include <kernel/chain.h>
#include <kernel/types.h>
#include <kernel/notifications_interface.h>
#include <kernel/caches.h>
#include <kernel/chainstatemanager_opts.h>
#include <kernel/blockmanager_opts.h>
#include <kernel/mempool_options.h>
#include <txmempool.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <key.h>
#include <addresstype.h>
#include <policy/policy.h>
#include <sync.h>
#include <uint256.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <util/time.h>
#include <util/translation.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

//! Build a block that pays `outs` and deliver it to the wallet via blockConnected as
//! `block_hash`@`height`, so the outputs land in the wallet's TXO cache as confirmed coins
//! and the wallet's processed tip becomes (height, block_hash). The tip block hash must be a
//! real block on the chain (the wallet's anti-fee-sniping looks it up via chain.findBlock).
void DeliverBlock(wallet::CWallet& w, const uint256& block_hash, int height, const std::vector<CTxOut>& outs)
{
    CBlock blk;
    uint32_t nonce = 0;
    for (const CTxOut& o : outs) {
        CMutableTransaction t;
        t.version = 2;
        t.vin.resize(1);
        t.vin[0].prevout.n = ++nonce; // ordinary (non-coinbase) input
        t.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        t.vout.push_back(o);
        blk.vtx.push_back(MakeTransactionRef(std::move(t)));
    }
    interfaces::BlockInfo info{block_hash};
    info.height = height;
    info.data = &blk;
    kernel::ChainstateRole role{};
    w.blockConnected(role, info);
}
} // namespace

int main()
{
    const char* lad = std::getenv("LOCALAPPDATA");
    const std::string base = (lad && *lad) ? (std::string(lad) + "/lattica_wallet_spend_test")
                                           : std::string("lattica_wallet_spend_test");
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(std::filesystem::path(base) / "blocks");
    const fs::path datadir = fs::PathFromString(base);
    const fs::path blocksdir = fs::PathFromString(base + "/blocks");
    const fs::path walletdir = fs::PathFromString(base + "/wallet");
    std::filesystem::create_directories(std::filesystem::path(base) / "wallet");

    kernel::Context context;
    kernel::Notifications notifications;
    util::SignalInterrupt interrupt;
    const std::unique_ptr<const CChainParams> params = CChainParams::RegTest();
    SetMockTime(params->GenesisBlock().nTime + 600);

    // ---- Stand up the chain: ChainstateManager + mempool + signal bus + adapter ----
    ValidationSignals validation_signals{std::make_unique<util::ImmediateTaskRunner>()};
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
        .block_tree_db_params = DBParams{.path = blocksdir, .cache_bytes = 1 << 20, .memory_only = true},
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
    {
        BlockValidationState state;
        Check("activate genesis chain", chainman.ActiveChainstate().ActivateBestChain(state, nullptr));
    }
    std::unique_ptr<interfaces::Chain> chain = interfaces::MakeChain(chainman, mempool, validation_signals);

    // ---- Attach a funded wallet ----
    wallet::CWallet w;
    {
        wallet::DatabaseOptions dbopts;
        wallet::DatabaseStatus dbstatus;
        bilingual_str dberr;
        w.SetDatabase(wallet::MakeDatabase(walletdir, dbopts, dbstatus, dberr));
    }
    w.SetChain(chain.get());
    w.SetChainParams(*params);
    Check("flags init", w.LoadWalletFlags(0));
    w.GenerateNewSeed();

    auto d0 = w.GetNewDestination("a0");
    auto d1 = w.GetNewDestination("a1");
    Check("derive two HD addresses", d0 && d1);

    // Two confirmed coins: 10 COIN + 5 COIN, delivered as the (real) genesis block so the
    // wallet's processed tip is a block the chain knows. The coins sit at depth 1.
    const uint256 genesis_hash = params->GetConsensus().hashGenesisBlock;
    DeliverBlock(w, genesis_hash, 0, {CTxOut{10 * COIN, GetScriptForDestination(*d0)},
                                      CTxOut{5 * COIN, GetScriptForDestination(*d1)}});
    Check("balance == 15 COIN", wallet::GetBalance(w, 1).m_mine_trusted == 15 * COIN);

    // ---- Create a real transaction paying 8 COIN, with change back to us ----
    const CKey payee = GenerateRandomKey();
    const CScript payee_spk = GetScriptForDestination(WitnessV0KeyHash(payee.GetPubKey()));
    std::vector<wallet::CRecipient> recips{{WitnessV0KeyHash(payee.GetPubKey()), 8 * COIN, false}};
    wallet::CCoinControl coin_control;
    // Pin an explicit feerate: the default wallet disables the fallback fee and there is no
    // estimator, so GetMinimumFeeRate would otherwise return 0. This also drives the fee loop
    // (select enough coins to cover recipient + fee at this rate).
    coin_control.m_feerate = CFeeRate{2000}; // 2 sat/vbyte

    auto res = wallet::CreateTransaction(w, recips, /*change_pos=*/std::nullopt, coin_control, /*sign=*/true);
    Check("CreateTransaction succeeds", bool(res));
    if (!res) {
        std::printf("    error: %s\n", util::ErrorString(res).original.c_str());
    } else {
        const CTransaction tx{*res->tx};
        Check("fee is positive", res->fee > 0);

        // Sum the inputs from the wallet's known coins.
        CAmount in_total = 0;
        bool inputs_known = true;
        for (const CTxIn& in : tx.vin) {
            const auto txo = WITH_LOCK(w.cs_wallet, return w.GetTXO(in.prevout));
            if (!txo) { inputs_known = false; continue; }
            in_total += txo->GetTxOut().nValue;
        }
        Check("all inputs are the wallet's coins", inputs_known);

        CAmount out_total = 0;
        bool paid = false, has_change = false;
        for (const CTxOut& o : tx.vout) {
            out_total += o.nValue;
            if (o.scriptPubKey == payee_spk && o.nValue == 8 * COIN) paid = true;
            if (WITH_LOCK(w.cs_wallet, return w.IsMine(o))) has_change = true;
        }
        Check("recipient is paid 8 COIN", paid);
        Check("change returns to the wallet", has_change);
        Check("value conserved: inputs == outputs + fee", in_total == out_total + res->fee);

        // Every input must pass consensus VerifyScript with its ML-DSA witness.
        bool all_verify = !tx.vin.empty();
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const auto txo = WITH_LOCK(w.cs_wallet, return w.GetTXO(tx.vin[i].prevout));
            if (!txo) { all_verify = false; continue; }
            const CTxOut& prev = txo->GetTxOut();
            const TransactionSignatureChecker checker(&tx, i, prev.nValue, MissingDataBehavior::FAIL);
            if (!VerifyScript(tx.vin[i].scriptSig, prev.scriptPubKey, &tx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker)) {
                all_verify = false;
            }
        }
        Check("every created input passes consensus VerifyScript", all_verify);
    }

    // ---- AttachChain: a wallet on the notification bus auto-follows the chain ----
    {
        auto w2 = std::make_shared<wallet::CWallet>();
        w2->SetChainParams(*params);
        bilingual_str aerr;
        Check("AttachChain registers + catches up tip", wallet::AttachChain(w2, *chain, aerr));
        Check("attached wallet tip == genesis height 0",
              WITH_LOCK(w2->cs_wallet, return w2->GetLastBlockHeight()) == 0);

        // Registry free functions.
        wallet::WalletContext ctx;
        Check("AddWallet", wallet::AddWallet(ctx, w2));
        Check("GetWallets size 1", wallet::GetWallets(ctx).size() == 1);
        size_t wcount = 0;
        Check("GetDefaultWallet", wallet::GetDefaultWallet(ctx, wcount) == w2 && wcount == 1);

        // Mine block 1 (coinbase to anyone-can-spend) and submit it through the chain.
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
        bool nb = false;
        Check("ProcessNewBlock(block1)", chainman.ProcessNewBlock(pblock, true, true, &nb) && nb);
        chain->waitForNotifications();

        // The attached wallet processed block 1 through the bus (no direct blockConnected call).
        Check("attached wallet auto-synced tip to height 1 via the notification bus",
              WITH_LOCK(w2->cs_wallet, return w2->GetLastBlockHeight()) == 1);

        Check("RemoveWallet", wallet::RemoveWallet(ctx, w2));
        w2->DisconnectChainNotifications();
    }

    w.SetChain(nullptr); // detach before the chain adapter is destroyed
    w.Close();

    std::printf(g_fail ? "\nFAILED (%d)\n" : "\nOK\n", g_fail);
    return g_fail ? 1 : 0;
}
