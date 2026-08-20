// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// End-to-end proof that an ML-DSA-44 signature is verified by the consensus
// engine inside ConnectBlock. We stand up a regtest ChainstateManager, fund a
// native P2WPKH output (OP_0 <HASH160(pubkey)>) from block 1's coinbase, mature
// it past COINBASE_MATURITY, then spend it with a witness carrying a real
// ML-DSA signature produced by CKey::Sign over the BIP-143 sighash.
//
// P2WPKH (not P2WSH) is used on purpose: the 1312-byte public key rides the
// witness stack (bounded by MAX_WITNESS_ITEM = 3600), while the executed script
// only pushes the 20-byte key hash -- so it never trips EvalScript's 520-byte
// MAX_SCRIPT_ELEMENT_SIZE push limit, which would block an inline ML-DSA pubkey.
//
// A negative control comes first: the same spend with one signature byte flipped
// must be rejected by ConnectBlock and leave the chain tip and UTXO untouched.
// That a tampered signature stops the block is what proves the signature is
// actually being checked, not ignored.

#include <validation.h>
#include <chain.h>
#include <node/chainstate.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <kernel/caches.h>
#include <kernel/mempool_options.h>
#include <txmempool.h>
#include <consensus/validation.h>
#include <consensus/merkle.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <key.h>
#include <pubkey.h>
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
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

std::vector<unsigned char> ToVec(const unsigned char* b, size_t n)
{
    return std::vector<unsigned char>(b, b + n);
}

// Assemble a block on top of the current tip and submit it. The coinbase pays
// `cb_spk`; `extra` are non-coinbase transactions; when `commitment` is set the
// engine writes the segwit witness commitment into the coinbase (required once a
// block carries witness data).
CBlock MineBlock(ChainstateManager& chainman, const CChainParams& params, int height,
                 const CScript& cb_spk, const std::vector<CTransactionRef>& extra,
                 bool commitment)
{
    const CBlockIndex* prev;
    {
        LOCK(chainman.GetMutex());
        prev = chainman.ActiveTip();
    }

    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = prev->GetBlockHash();
    block.nTime = prev->GetBlockTime() + 1;
    block.nBits = params.GenesisBlock().nBits; // regtest does not retarget
    block.nNonce = 0;

    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptSig = CScript() << height << OP_0; // BIP34 height + >=2-byte coinbase
    cb.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    cb.vout.resize(1);
    cb.vout[0].nValue = GetBlockSubsidy(height, params.GetConsensus());
    cb.vout[0].scriptPubKey = cb_spk;
    block.vtx.push_back(MakeTransactionRef(std::move(cb)));
    for (const auto& t : extra) block.vtx.push_back(t);

    if (commitment) chainman.GenerateCoinbaseCommitment(block, prev);
    block.hashMerkleRoot = BlockMerkleRoot(block);

    // Mine the block: grind the nonce until the SHA3-256d PoW is under target.
    while (!CheckProofOfWork(block.GetPoWHash(), block.nBits, params.GetConsensus())) ++block.nNonce;
    return block;
}

bool Submit(ChainstateManager& chainman, const CBlock& block)
{
    auto pblock = std::make_shared<const CBlock>(block);
    bool newblk = false;
    bool ok = chainman.ProcessNewBlock(pblock, /*force_processing=*/true, /*min_pow_checked=*/true, &newblk);
    return ok && newblk;
}

int Height(ChainstateManager& chainman)
{
    LOCK(chainman.GetMutex());
    return chainman.ActiveHeight();
}
} // namespace

int main()
{
    const char* lad = std::getenv("LOCALAPPDATA");
    const std::string base = (lad && *lad) ? (std::string(lad) + "/lattica_spend_test")
                                           : std::string("lattica_spend_test");
    const std::filesystem::path dd(base);
    std::filesystem::remove_all(dd);
    std::filesystem::create_directories(dd / "blocks");
    const fs::path datadir = fs::PathFromString(base);
    const fs::path blocksdir = fs::PathFromString(base + "/blocks");

    kernel::Context context;
    kernel::Notifications notifications;
    util::SignalInterrupt interrupt;
    const std::unique_ptr<const CChainParams> params = CChainParams::RegTest();

    SetMockTime(params->GenesisBlock().nTime + 100000);

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
        chainman.ActiveChainstate().ActivateBestChain(state, nullptr);
    }
    Check("starts at genesis (height 0)", Height(chainman) == 0);

    // The key whose ML-DSA signature the engine will verify, and the native
    // P2WPKH output paying to it.
    CKey key = GenerateRandomKey();
    CPubKey pub = key.GetPubKey();
    CKeyID keyid = pub.GetID();
    const std::vector<unsigned char> keyhash = ToVec(keyid.begin(), keyid.size());
    const CScript fund_spk = CScript() << OP_0 << keyhash;                 // P2WPKH scriptPubKey
    const CScript script_code = CScript() << OP_DUP << OP_HASH160 << keyhash << OP_EQUALVERIFY << OP_CHECKSIG; // BIP143 scriptCode

    // Block 1 funds the P2WPKH output from its coinbase.
    CBlock block1 = MineBlock(chainman, *params, 1, fund_spk, {}, /*commitment=*/false);
    Check("block 1 (funding) accepted", Submit(chainman, block1));
    const CAmount fund_value = block1.vtx[0]->vout[0].nValue;
    const COutPoint funded(block1.vtx[0]->GetHash(), 0);

    // Mature the coinbase: mine up to height 100 (spend at 101 satisfies
    // COINBASE_MATURITY = 100, since 101 - 1 == 100).
    for (int h = 2; h <= COINBASE_MATURITY; ++h) {
        CBlock f = MineBlock(chainman, *params, h, CScript() << OP_TRUE, {}, /*commitment=*/false);
        if (!Submit(chainman, f)) { Check("filler block accepted", false); break; }
    }
    Check("matured to height 100", Height(chainman) == COINBASE_MATURITY);
    {
        LOCK(chainman.GetMutex());
        const Coin& c = chainman.ActiveChainstate().CoinsTip().AccessCoin(funded);
        Check("funded P2WPKH coin present before spend", !c.IsSpent() && c.IsCoinBase());
    }

    // Build the spend: input = the P2WPKH coin, output = anyone-can-spend, fee 0.
    CMutableTransaction spend;
    spend.version = 2;
    spend.vin.resize(1);
    spend.vin[0].prevout = funded;
    spend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    spend.vout.resize(1);
    spend.vout[0].nValue = fund_value;
    spend.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // BIP-143 sighash over the implied P2PKH scriptCode, signed with ML-DSA.
    const uint256 sighash = SignatureHash(script_code, spend, 0, SIGHASH_ALL, fund_value, SigVersion::WITNESS_V0, nullptr);
    std::vector<unsigned char> sig;
    Check("CKey::Sign(sighash) succeeds", key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL)); // script-level sig = ML-DSA sig || sighash type

    const std::vector<unsigned char> pubvec = ToVec(pub.data(), pub.size());

    // --- Negative control: a spend whose signature byte is flipped must be
    //     rejected by ConnectBlock; the chain and UTXO stay put. ---
    {
        std::vector<unsigned char> bad_sig = sig;
        bad_sig[bad_sig.size() / 2] ^= 0xff; // corrupt the ML-DSA signature body
        CMutableTransaction bad = spend;
        bad.vin[0].scriptWitness.stack = {bad_sig, pubvec};
        CBlock bad_block = MineBlock(chainman, *params, COINBASE_MATURITY + 1, CScript() << OP_TRUE,
                                     {MakeTransactionRef(bad)}, /*commitment=*/true);
        // The block is stored, but the only height-101 candidate must fail to
        // connect: ProcessNewBlock can still return true (it kept the valid
        // height-100 tip), so the meaningful signals are the unchanged tip, the
        // block index marking the block invalid, and the unspent coin. The good
        // block below is identical except for the signature bytes, so a rejection
        // here can only be the signature.
        Submit(chainman, bad_block);
        Check("tip did not advance on tampered signature (still 100)", Height(chainman) == COINBASE_MATURITY);
        LOCK(chainman.GetMutex());
        const CBlockIndex* bi = chainman.m_blockman.LookupBlockIndex(bad_block.GetHash());
        Check("tampered block is marked invalid by ConnectBlock",
              bi && (bi->nStatus & (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD)));
        const Coin& c = chainman.ActiveChainstate().CoinsTip().AccessCoin(funded);
        Check("funded coin still unspent after tampered block", !c.IsSpent());
    }

    // --- The real spend: a valid ML-DSA witness, verified inside ConnectBlock. ---
    {
        CMutableTransaction good = spend;
        good.vin[0].scriptWitness.stack = {sig, pubvec};
        const CTransactionRef good_ref = MakeTransactionRef(good);
        CBlock spend_block = MineBlock(chainman, *params, COINBASE_MATURITY + 1, CScript() << OP_TRUE,
                                       {good_ref}, /*commitment=*/true);
        Check("block with valid ML-DSA signature accepted", Submit(chainman, spend_block));
        Check("chain advanced to height 101", Height(chainman) == COINBASE_MATURITY + 1);

        LOCK(chainman.GetMutex());
        const Coin& spent = chainman.ActiveChainstate().CoinsTip().AccessCoin(funded);
        Check("funded P2WPKH coin is now spent", spent.IsSpent());
        const Coin& created = chainman.ActiveChainstate().CoinsTip().AccessCoin(COutPoint(good_ref->GetHash(), 0));
        Check("spend output is a new UTXO at height 101",
              !created.IsSpent() && created.nHeight == COINBASE_MATURITY + 1 && !created.IsCoinBase());
    }

    std::filesystem::remove_all(dd);
    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
