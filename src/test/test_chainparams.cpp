// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// chainparams / genesis self-test: construct each network's CChainParams (the
// constructors already assert the hardcoded genesis hash + merkle root), then
// independently confirm the mined genesis is proof-of-work-valid under our
// consensus code and that powLimit round-trips to the genesis nBits.

#include <arith_uint256.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdio>
#include <memory>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

void CheckParams(const char* net, const std::unique_ptr<const CChainParams>& params)
{
    const CBlock& g = params->GenesisBlock();
    const Consensus::Params& c = params->GetConsensus();

    char name[96];

    std::snprintf(name, sizeof(name), "%s: genesis hash == consensus.hashGenesisBlock", net);
    Check(name, g.GetHash() == c.hashGenesisBlock);

    // The mined genesis satisfies proof of work: SHA3-256d(header) <= target.
    std::snprintf(name, sizeof(name), "%s: genesis CheckProofOfWork", net);
    Check(name, CheckProofOfWork(g.GetPoWHash(), g.nBits, c));

    // powLimit decodes back to the genesis nBits (the genesis starts at powLimit).
    std::snprintf(name, sizeof(name), "%s: powLimit.GetCompact() == genesis nBits", net);
    Check(name, UintToArith256(c.powLimit).GetCompact() == g.nBits);

    std::printf("    %s genesis=%s\n", net, c.hashGenesisBlock.ToString().c_str());
}

} // namespace

int main()
{
    CheckParams("main", CChainParams::Main());
    CheckParams("testnet", CChainParams::TestNet());
    CheckParams("regtest", CChainParams::RegTest());

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
