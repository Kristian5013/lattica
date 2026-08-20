// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Difficulty retarget tests (Bitcoin Core 2016-block adjustment, ported
// verbatim). CalculateNextWorkRequired's math (target scaling, the +/-4x
// timespan clamp, the powLimit clamp) is cross-checked in --dump mode against
// an independent Python reference; GetNextWorkRequired's boundary dispatch and
// PermittedDifficultyTransition are exercised on a built CBlockIndex chain.
// Standalone for now (own main).

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

namespace {

const int64_t T = 1209600; // 2 weeks; with 600 s spacing -> interval 2016

// Realistic old targets (all <= powLimit 0x1d00ffff), same set in the Python ref.
const uint32_t kOldBits[] = {0x1d00ffff, 0x1c7fff00, 0x1b0404cb, 0x1c0fffff, 0x1d007fff};
// Actual timespans, in seconds: on-target, +/-2x, beyond the +/-4x clamp, exactly the clamp.
const int64_t kSpans[] = {T, T / 2, T * 2, T / 8, T * 8, T / 4, T * 4, T / 100, T * 100};

Consensus::Params MakeParams(uint32_t powLimitCompact, int64_t spacing, int64_t timespan)
{
    Consensus::Params p{};
    arith_uint256 bn;
    bn.SetCompact(powLimitCompact);
    p.powLimit = ArithToUint256(bn);
    p.fPowAllowMinDifficultyBlocks = false;
    p.enforce_BIP94 = false;
    p.fPowNoRetargeting = false;
    p.nPowTargetSpacing = spacing;
    p.nPowTargetTimespan = timespan;
    return p;
}

//! Build an n-block chain (heights 0..n-1), constant nBits, evenly spaced.
std::vector<std::unique_ptr<CBlockIndex>> BuildChain(int n, uint32_t bits, int64_t baseTime, int64_t spacing)
{
    std::vector<std::unique_ptr<CBlockIndex>> v;
    for (int h = 0; h < n; ++h) {
        auto idx = std::make_unique<CBlockIndex>();
        idx->nHeight = h;
        idx->nBits = bits;
        idx->nTime = (uint32_t)(baseTime + h * spacing);
        idx->pprev = (h > 0) ? v[h - 1].get() : nullptr;
        idx->BuildSkip();
        v.push_back(std::move(idx));
    }
    return v;
}

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc >= 2 && std::strcmp(argv[1], "--dump") == 0) {
        const Consensus::Params params = MakeParams(0x1d00ffff, 600, T);
        for (uint32_t oldBits : kOldBits) {
            for (int64_t span : kSpans) {
                CBlockIndex last;
                last.nBits = oldBits;
                last.nTime = 2000000000u;
                const int64_t firstTime = (int64_t)last.nTime - span;
                unsigned int got = CalculateNextWorkRequired(&last, firstTime, params);
                std::printf("%08x %lld %08x\n", oldBits, (long long)span, got);
            }
        }
        return 0;
    }

    // GetNextWorkRequired boundary dispatch on an interval-10 chain.
    const Consensus::Params p10 = MakeParams(0x1d00ffff, 600, 6000); // interval = 10
    auto chain = BuildChain(11, 0x1d00ffff, 1000000000, 600);
    CBlockHeader dummy; // only read in the (disabled) min-difficulty path

    // Height 8 -> next height 9, not a boundary: returns the last block's nBits.
    Check("non-boundary returns last nBits",
          GetNextWorkRequired(chain[8].get(), &dummy, p10) == 0x1d00ffff);
    // Height 9 -> next height 10, a boundary: routes to CalculateNextWorkRequired
    // over the period's first block (height 0).
    {
        unsigned int got = GetNextWorkRequired(chain[9].get(), &dummy, p10);
        unsigned int expect = CalculateNextWorkRequired(chain[9].get(), chain[0]->GetBlockTime(), p10);
        Check("boundary routes to CalculateNextWorkRequired", got == expect);
        // 9 intervals of 600 s = 5400 s actual vs 6000 s target -> easier, target grows ~10%.
        Check("boundary eased target (5400 < 6000)", got != 0x1d00ffff);
    }

    // fPowNoRetargeting: difficulty pinned.
    {
        Consensus::Params pNo = p10;
        pNo.fPowNoRetargeting = true;
        Check("fPowNoRetargeting keeps last nBits",
              CalculateNextWorkRequired(chain[9].get(), chain[0]->GetBlockTime(), pNo) == 0x1d00ffff);
    }

    // PermittedDifficultyTransition.
    Check("non-boundary same nBits permitted",
          PermittedDifficultyTransition(p10, 5, 0x1d00ffff, 0x1d00ffff));
    Check("non-boundary changed nBits rejected",
          !PermittedDifficultyTransition(p10, 5, 0x1d00ffff, 0x1c7fff00));
    Check("boundary same nBits permitted",
          PermittedDifficultyTransition(p10, 10, 0x1d00ffff, 0x1d00ffff));
    Check("boundary out-of-range (too easy) rejected",
          !PermittedDifficultyTransition(p10, 10, 0x1d00ffff, 0x1f00ffff));

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
