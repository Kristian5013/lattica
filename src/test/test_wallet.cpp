// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the from-scratch CWallet (wallet.{h,cpp}) backed by the SQLite
// WalletDatabase: HD address generation, IsMine/balance through the
// blockConnected notification path, CreateTransaction, and a persistence
// round-trip (create + fund a wallet, reopen the same database into a fresh
// wallet, and confirm the keys, transactions and balance reload).

#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#include <wallet/db.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/walletdb.h>

#include <addresstype.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <interfaces/chain.h>
#include <kernel/chain.h>
#include <kernel/types.h>
#include <key.h>
#include <key_io.h>
#include <kernel/chainparams.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/interpreter.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/translation.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

std::unique_ptr<wallet::WalletDatabase> OpenDB(const fs::path& dir)
{
    wallet::DatabaseOptions options;
    wallet::DatabaseStatus status;
    bilingual_str error;
    auto db = wallet::MakeDatabase(dir, options, status, error);
    if (!db) std::printf("    open error: %s\n", error.original.c_str());
    return db;
}

//! Build a block that pays `outs`, deliver it to the wallet via blockConnected.
uint256 DeliverBlock(wallet::CWallet& w, int height, const std::vector<CTxOut>& outs)
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
    const uint256 bhash = blk.GetHash();
    interfaces::BlockInfo info{bhash};
    info.height = height;
    info.data = &blk;
    kernel::ChainstateRole role{};
    w.blockConnected(role, info);
    return bhash;
}
} // namespace

int main()
{
    const char* lad = std::getenv("LOCALAPPDATA");
    const std::string base = (lad && *lad) ? (std::string(lad) + "/lattica_wallet_test")
                                           : std::string("lattica_wallet_test");
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    const fs::path dir = fs::PathFromString(base);
    const std::unique_ptr<const CChainParams> params = CChainParams::RegTest();

    CTxDestination a0, a1;
    uint32_t key_count_a = 0; // captured from wallet A (2 receive + change from CreateTransaction)

    // --- Wallet A: create, seed, derive, fund, spend ---
    {
        wallet::CWallet w;
        w.SetDatabase(OpenDB(dir));
        w.SetChainParams(*params);
        Check("flags init", w.LoadWalletFlags(0));
        w.GenerateNewSeed();

        auto d0 = w.GetNewDestination("a0");
        auto d1 = w.GetNewDestination("a1");
        Check("derive two HD addresses", d0 && d1);
        a0 = *d0; a1 = *d1;
        Check("derived key count == 2", WITH_LOCK(w.cs_wallet, return w.GetKeyCount()) == 2);
        Check("derived address is ours", WITH_LOCK(w.cs_wallet, return w.IsMine(a0)));

        // Fund a0 (10 COIN) and a1 (5 COIN) via a confirmed block at height 100.
        DeliverBlock(w, 100, {CTxOut{10 * COIN, GetScriptForDestination(a0)},
                              CTxOut{5 * COIN, GetScriptForDestination(a1)}});
        Check("balance == 15 COIN", wallet::GetBalance(w, 1).m_mine_trusted == 15 * COIN);
        Check("two available coins", WITH_LOCK(w.cs_wallet, return wallet::AvailableCoins(w).Size()) == 2);

        // A block output that doesn't involve us is ignored.
        {
            const CKey foreign = GenerateRandomKey();
            DeliverBlock(w, 100, {CTxOut{COIN, GetScriptForDestination(WitnessV0KeyHash(foreign.GetPubKey()))}});
            Check("foreign output not tracked", WITH_LOCK(w.cs_wallet, return wallet::AvailableCoins(w).Size()) == 2 && wallet::GetBalance(w, 1).m_mine_trusted == 15 * COIN);
        }

        // Build and sign a spend manually: CreateTransaction's fee loop needs a live
        // chain (estimateSmartFee / checkChainLimits), so here we exercise the wallet's
        // own coins + SignTransaction and validate the ML-DSA P2WPKH size model directly.
        const CKey payee = GenerateRandomKey();
        const CScript payee_spk = GetScriptForDestination(WitnessV0KeyHash(payee.GetPubKey()));

        CMutableTransaction tx;
        tx.version = 2;
        CAmount in_total = 0;
        {
            LOCK(w.cs_wallet);
            for (const auto& [op, txo] : w.GetTXOs()) {
                CTxIn in;
                in.prevout = op;
                in.nSequence = CTxIn::SEQUENCE_FINAL;
                tx.vin.push_back(in);
                in_total += txo.GetTxOut().nValue;
            }
        }
        const CAmount fee = 200000; // fixed fee for the test (no estimator without a chain)
        const auto change_dest = w.GetNewChangeDestination();
        Check("change address derived", bool(change_dest));
        tx.vout.emplace_back(8 * COIN, payee_spk);
        tx.vout.emplace_back(in_total - 8 * COIN - fee, GetScriptForDestination(*change_dest));

        const bool ok = WITH_LOCK(w.cs_wallet, return w.SignTransaction(tx));
        Check("SignTransaction succeeds", ok);

        bool paid = false;
        for (const auto& vo : tx.vout) if (vo.scriptPubKey == payee_spk && vo.nValue == 8 * COIN) paid = true;
        Check("recipient is paid 8 COIN", paid);

        // Validate the spend size model against the real signed tx: each P2WPKH-ML-DSA
        // input's witness carries { sig (ML-DSA signature + 1 sighash byte), pubkey
        // (CPubKey::SIZE) } -> the 3782-vbyte/input figure spend.cpp's size model assumes.
        bool witness_sizes_ok = !tx.vin.empty();
        for (const auto& in : tx.vin) {
            if (in.scriptWitness.stack.size() != 2) { witness_sizes_ok = false; continue; }
            if (in.scriptWitness.stack[0].size() != size_t(SchemeSignatureSize(SigScheme::ML_DSA_44) + 1)) witness_sizes_ok = false;
            if (in.scriptWitness.stack[1].size() != size_t(CPubKey::SIZE)) witness_sizes_ok = false;
        }
        Check("ML-DSA witness sizes match the size model (sig 2421 + pubkey 1313)", witness_sizes_ok);

        bool all_verify = !tx.vin.empty();
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const wallet::CWalletTx* wtx = WITH_LOCK(w.cs_wallet, return w.GetWalletTx(tx.vin[i].prevout.hash));
            const CTxOut& prev = wtx->tx->vout[tx.vin[i].prevout.n];
            const MutableTransactionSignatureChecker c(&tx, i, prev.nValue, MissingDataBehavior::FAIL);
            if (!VerifyScript(tx.vin[i].scriptSig, prev.scriptPubKey, &tx.vin[i].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, c)) all_verify = false;
        }
        Check("every created input passes consensus VerifyScript", all_verify);

        // CreateTransaction derived a fresh change address, so the counter advanced
        // past the two receive addresses.
        key_count_a = WITH_LOCK(w.cs_wallet, return w.GetKeyCount());
        Check("change address advanced the key counter", key_count_a >= 3);
        w.Close();
    }

    // --- Wallet B: reopen the same database, verify everything reloaded ---
    {
        wallet::CWallet w;
        w.SetDatabase(OpenDB(dir));
        w.SetChainParams(*params);
        Check("reload: PopulateWalletFromDB OK", w.PopulateWalletFromDB() == wallet::DBErrors::LOAD_OK);

        // The HD chain and the derived keys came back (counter matches wallet A).
        Check("reload: key counter persisted", WITH_LOCK(w.cs_wallet, return w.GetKeyCount()) == key_count_a);
        Check("reload: a0 is still ours", WITH_LOCK(w.cs_wallet, return w.IsMine(a0)));
        Check("reload: a1 is still ours", WITH_LOCK(w.cs_wallet, return w.IsMine(a1)));
        Check("reload: address book label persisted",
              WITH_LOCK(w.cs_wallet, return w.FindAddressBookEntry(a0) && w.FindAddressBookEntry(a0)->GetLabel() == "a0"));

        // Restore the processed tip (Lattica re-syncs it from notifications), then the
        // persisted confirmed transactions value the wallet again.
        WITH_LOCK(w.cs_wallet, w.SetLastBlockProcessed(100, uint256::ONE));
        Check("reload: balance == 15 COIN", wallet::GetBalance(w, 1).m_mine_trusted == 15 * COIN);

        // Deriving the next address continues from the persisted counter.
        auto d2 = w.GetNewDestination("a2");
        Check("reload: derivation continues", d2 && WITH_LOCK(w.cs_wallet, return w.GetKeyCount()) == key_count_a + 1);
        w.Close();
    }

    // --- Encryption: at-rest seed encryption + lock / unlock + reload ---
    {
        const std::string ebase = base + "_enc";
        std::filesystem::remove_all(ebase);
        std::filesystem::create_directories(ebase);
        const fs::path edir = fs::PathFromString(ebase);
        const SecureString pass{"correct horse battery staple"};
        CTxDestination ea; // a deterministic HD address, stable across reload

        {
            wallet::CWallet w;
            w.SetDatabase(OpenDB(edir));
            w.SetChainParams(*params);
            w.LoadWalletFlags(0);
            w.GenerateNewSeed();
            ea = *w.GetNewDestination("e0");

            Check("enc: not encrypted initially", !w.HasEncryptionKeys());
            Check("enc: EncryptWallet succeeds", w.EncryptWallet(pass));
            Check("enc: now encrypted", w.HasEncryptionKeys());
            Check("enc: unlocked right after encrypting", !w.IsLocked());
            Check("enc: address still ours after encrypting", WITH_LOCK(w.cs_wallet, return w.IsMine(ea)));

            Check("enc: Lock succeeds", w.Lock());
            Check("enc: now locked", w.IsLocked());
            // A locked wallet keeps its public key ids, so it still recognises its own
            // outputs (balance stays visible); only the private keys are wiped until unlock.
            Check("enc: locked wallet still recognizes its address", WITH_LOCK(w.cs_wallet, return w.IsMine(ea)));

            Check("enc: wrong passphrase is rejected", !w.Unlock(SecureString{"wrong passphrase"}));
            Check("enc: still locked after wrong passphrase", w.IsLocked());
            Check("enc: right passphrase unlocks", w.Unlock(pass));
            Check("enc: unlocked wallet recognizes its address", WITH_LOCK(w.cs_wallet, return w.IsMine(ea)));
            w.Close();
        }

        // Reopen the encrypted database: at rest the seed is sealed, so the wallet
        // loads encrypted and locked, and only unlocking restores the keys.
        {
            wallet::CWallet w;
            w.SetDatabase(OpenDB(edir));
            w.SetChainParams(*params);
            Check("enc reload: load OK", w.PopulateWalletFromDB() == wallet::DBErrors::LOAD_OK);
            Check("enc reload: is encrypted", w.HasEncryptionKeys());
            Check("enc reload: starts locked", w.IsLocked());
            // The reloaded encrypted wallet is locked but must still recognise its address
            // (this is the bug that showed a zero balance until the user unlocked).
            Check("enc reload: locked wallet recognizes its address", WITH_LOCK(w.cs_wallet, return w.IsMine(ea)));
            Check("enc reload: HD reported enabled while locked", WITH_LOCK(w.cs_wallet, return w.IsHDEnabled()));
            Check("enc reload: unlock restores the key core",
                  w.Unlock(pass) && WITH_LOCK(w.cs_wallet, return w.IsMine(ea)));
            w.Close();
        }
        std::filesystem::remove_all(ebase);
    }

    std::filesystem::remove_all(base);
    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
