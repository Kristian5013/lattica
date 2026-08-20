// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Smoke tests for the transaction mempool (txmempool / CTxMemPool, the
// Boost.MultiIndex-indexed pool on top of the cluster-linearization engine):
// construct with default options, confirm it starts empty, and exercise a few
// read-only queries. The full add/evict behaviour is driven by validation.

#include <txmempool.h>
#include <kernel/mempool_options.h>
#include <policy/feerate.h>
#include <util/translation.h>

#include <cstdio>

// G_TRANSLATION_FUN is defined per-executable (Core does this in its test
// setup / the daemon); the headless default performs no translation.
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
    kernel::MemPoolOptions opts; // defaults; no validation signals
    bilingual_str error;
    CTxMemPool pool(opts, error);

    Check("constructs without error", error.empty());
    Check("starts empty (size 0)", pool.size() == 0);
    Check("total tx size 0", pool.GetTotalTxSize() == 0);

    // A txid that was never added is absent.
    uint256 h;
    for (unsigned i = 0; i < uint256::size(); ++i) h.begin()[i] = (unsigned char)(i + 1);
    Check("absent txid not in pool", !pool.exists(Txid::FromUint256(h)));

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
