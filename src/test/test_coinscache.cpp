// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Functional tests for the UTXO cache (CCoinsViewCache): add/have/access/spend
// and flush propagation through a two-layer cache. Exercises the real cache
// machinery (FRESH/DIRTY flagged-entry list, BatchWrite, the PoolAllocator map,
// the SaltedOutpointHasher), which requires util/hasher.cpp -> the RNG.

#include <coins.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdio>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

COutPoint MakeOutpoint(uint8_t tag, uint32_t n)
{
    uint256 h;
    for (unsigned i = 0; i < uint256::size(); ++i) h.begin()[i] = (unsigned char)(tag + i);
    return COutPoint(Txid::FromUint256(h), n);
}

Coin MakeCoin(CAmount value, int height, bool coinbase)
{
    CScript spk;
    spk << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xab) << OP_EQUALVERIFY << OP_CHECKSIG;
    return Coin(CTxOut(value, spk), height, coinbase);
}

} // namespace

int main()
{
    CCoinsView& empty = CoinsViewEmpty::Get();

    // Single cache: add / have / access / spend.
    {
        CCoinsViewCache cache(&empty, /*deterministic=*/true);
        const COutPoint op = MakeOutpoint(1, 0);

        Check("empty cache: !HaveCoin", !cache.HaveCoin(op));
        cache.AddCoin(op, MakeCoin(50 * COIN, 100, false), /*possible_overwrite=*/false);
        Check("after AddCoin: HaveCoin", cache.HaveCoin(op));
        Check("HaveCoinInCache", cache.HaveCoinInCache(op));
        Check("AccessCoin value", cache.AccessCoin(op).out.nValue == 50 * COIN);
        Check("AccessCoin height", cache.AccessCoin(op).nHeight == 100);
        Check("GetCacheSize == 1", cache.GetCacheSize() == 1);

        Coin moved;
        Check("SpendCoin returns moved data", cache.SpendCoin(op, &moved) && moved.out.nValue == 50 * COIN);
        Check("after spend: !HaveCoin", !cache.HaveCoin(op));
    }

    // Two layers: add to top, Flush, verify it reached the base cache.
    {
        CCoinsViewCache base(&empty, /*deterministic=*/true);
        const COutPoint op = MakeOutpoint(2, 7);
        {
            CCoinsViewCache top(&base, /*deterministic=*/true);
            top.AddCoin(op, MakeCoin(COIN, 5, false), false);
            Check("base does not see uncommitted coin", !base.HaveCoinInCache(op));
            top.Flush();
        }
        Check("after Flush: base HaveCoin", base.HaveCoin(op));
        Check("after Flush: base value", base.AccessCoin(op).out.nValue == COIN);
    }

    // HaveInputs over a cached prevout.
    {
        CCoinsViewCache cache(&empty, /*deterministic=*/true);
        const COutPoint op = MakeOutpoint(3, 0);
        cache.AddCoin(op, MakeCoin(10 * COIN, 1, false), false);
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = op;
        tx.vout.resize(1);
        tx.vout[0].nValue = 9 * COIN;
        Check("HaveInputs (prevout present)", cache.HaveInputs(CTransaction(tx)));
        CMutableTransaction tx2 = tx;
        tx2.vin[0].prevout = MakeOutpoint(9, 9); // absent
        Check("!HaveInputs (prevout absent)", !cache.HaveInputs(CTransaction(tx2)));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
