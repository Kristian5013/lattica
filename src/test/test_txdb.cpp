// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the UTXO database (txdb / CCoinsViewDB): coins added to a cache on
// top of an in-memory CCoinsViewDB are persisted by Flush() and then read back
// directly from the db (GetCoin/HaveCoin/GetBestBlock), with absent coins
// reported missing.

#include <txdb.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <consensus/amount.h>
#include <uint256.h>

#include <cstdio>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

COutPoint Op(uint8_t tag, uint32_t n)
{
    uint256 h;
    for (unsigned i = 0; i < uint256::size(); ++i) h.begin()[i] = (unsigned char)(tag + i);
    return COutPoint(Txid::FromUint256(h), n);
}

Coin MakeCoin(CAmount v, int height, bool cb)
{
    CScript spk; spk << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG;
    return Coin(CTxOut(v, spk), height, cb);
}

} // namespace

int main()
{
    CCoinsViewDB db({.path = "unused-utxo-db", .cache_bytes = 1 << 20, .memory_only = true}, CoinsViewOptions{});

    const COutPoint a = Op(1, 0), b = Op(2, 5);
    uint256 best;
    for (unsigned i = 0; i < uint256::size(); ++i) best.begin()[i] = (unsigned char)(0x40 + i);

    // Add coins through a cache and flush them into the db.
    {
        CCoinsViewCache cache(&db);
        cache.AddCoin(a, MakeCoin(50 * COIN, 100, /*coinbase=*/true), false);
        cache.AddCoin(b, MakeCoin(7 * COIN, 200, false), false);
        cache.SetBestBlock(best);
        cache.Flush();
    }

    // Read back straight from the database.
    {
        auto ca = db.GetCoin(a);
        Check("db GetCoin(a) value/height/coinbase", ca.has_value() && ca->out.nValue == 50 * COIN && ca->nHeight == 100 && ca->IsCoinBase());
        auto cb = db.GetCoin(b);
        Check("db GetCoin(b) value", cb.has_value() && cb->out.nValue == 7 * COIN);
        Check("db HaveCoin(a)", db.HaveCoin(a));
        Check("db best block persisted", db.GetBestBlock() == best);
        Check("db !HaveCoin(absent)", !db.HaveCoin(Op(9, 9)));
        Check("db GetCoin(absent) nullopt", !db.GetCoin(Op(9, 9)).has_value());
    }

    // A second cache layered on the db sees the persisted coins.
    {
        CCoinsViewCache cache2(&db);
        Check("re-opened cache sees coin a", cache2.AccessCoin(a).out.nValue == 50 * COIN);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
