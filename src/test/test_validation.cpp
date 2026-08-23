// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the consensus block-validation entry points (validation.cpp):
// GetBlockSubsidy's halving schedule, and CheckBlock run against each network's
// real mined genesis block (PoW via the SHA3-256d header check, merkle root,
// coinbase, per-tx checks), with a tampered nonce rejected as high-hash and a
// tampered merkle root rejected.

#include <validation.h>
#include <kernel/chainparams.h>
#include <pow.h>
#include <hash.h>
#include <consensus/validation.h>
#include <consensus/amount.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/translation.h>

#include <cstdio>
#include <memory>

// Defined per-executable (Core does this in its test setup); no translation.
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
    const std::unique_ptr<const CChainParams> params = CChainParams::Main();
    const Consensus::Params& c = params->GetConsensus();
    const CBlock& genesis = params->GenesisBlock();

    // GetBlockSubsidy halving schedule (50 -> 25 -> ... -> 0).
    Check("subsidy at height 0 == 50 COIN", GetBlockSubsidy(0, c) == 50 * COIN);
    Check("subsidy at first halving == 25 COIN", GetBlockSubsidy(c.nSubsidyHalvingInterval, c) == 25 * COIN);
    Check("subsidy at second halving == 12.5 COIN", GetBlockSubsidy(2 * c.nSubsidyHalvingInterval, c) == 1250000000);
    Check("subsidy after 64 halvings == 0", GetBlockSubsidy(64 * c.nSubsidyHalvingInterval, c) == 0);

    // The real mined genesis passes the full context-free block check.
    {
        BlockValidationState state;
        bool ok = CheckBlock(genesis, state, c, /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true);
        Check("main genesis passes CheckBlock", ok && state.IsValid());
        if (!ok) std::printf("    reject: %s\n", state.ToString().c_str());
    }

    // Tampering the nonce makes the SHA3-256d proof of work miss the (hard) target.
    {
        CBlock bad = genesis;
        bad.fChecked = false; bad.m_checked_merkle_root = false; bad.m_checked_witness_commitment = false;
        bad.nNonce = genesis.nNonce + 1;
        BlockValidationState state;
        bool ok = CheckBlock(bad, state, c, /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true);
        Check("tampered nonce -> high-hash", !ok && state.GetRejectReason() == "high-hash");
    }

    // Tampering a transaction makes the computed merkle root mismatch the header.
    {
        CBlock bad = genesis;
        bad.fChecked = false; bad.m_checked_merkle_root = false; bad.m_checked_witness_commitment = false;
        CMutableTransaction cb{*bad.vtx[0]};
        cb.vout[0].nValue ^= 1;
        bad.vtx[0] = MakeTransactionRef(std::move(cb));
        BlockValidationState state;
        bool ok = CheckBlock(bad, state, c, /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true);
        Check("tampered tx -> bad-txnmrklroot", !ok && state.GetRejectReason() == "bad-txnmrklroot");
    }

    // Regtest genesis also validates (different, easy difficulty).
    {
        const auto rt = CChainParams::RegTest();
        BlockValidationState state;
        bool ok = CheckBlock(rt->GenesisBlock(), state, rt->GetConsensus(), true, true);
        Check("regtest genesis passes CheckBlock", ok && state.IsValid());
    }


    // ---- Which hash the proof of work is over is consensus, and it is not the
    // one Bitcoin uses. Here the header hash is hashed once more -- SHA3-256d,
    // CBlockHeader::GetPoWHash -- and that is what miners grind and what a node
    // must check. Porting validation.cpp from Core silently put GetHash() back
    // in five places, which broke nothing at compile time and would have made
    // the node reject every block ever mined for this chain.
    //
    // Grind a header that meets a target under GetHash but not under
    // GetPoWHash: whichever of the two the code uses, this tells them apart.
    {
        const auto rt = CChainParams::RegTest();
        const Consensus::Params& rc = rt->GetConsensus();

        // A target a little under regtest's powLimit, so that grinding is cheap
        // and DeriveTarget accepts it. nBits goes into the header, so it has to
        // be fixed before grinding, not after: changing it changes both hashes.
        arith_uint256 target = UintToArith256(rc.powLimit) >> 9;
        const unsigned int nBits = target.GetCompact();
        target.SetCompact(nBits);

        CBlockHeader h = static_cast<const CBlockHeader&>(rt->GenesisBlock());
        h.nBits = nBits;
        bool found = false;
        for (uint32_t n = 0; n < 4000000 && !found; ++n) {
            h.nNonce = n;
            found = UintToArith256(h.GetHash()) <= target && UintToArith256(h.GetPoWHash()) > target;
        }
        Check("a header meeting the target under GetHash but not GetPoWHash exists", found);
        if (found) {
            const std::vector<CBlockHeader> checked{h};
            // It only fails if the code hashes twice. Put GetHash() back in
            // HasValidProofOfWork and this check goes red.
            Check("HasValidProofOfWork rejects it, so the proof is over GetPoWHash",
                  !HasValidProofOfWork(checked, rc));

            // ...and the converse: the regtest genesis, mined against
            // GetPoWHash, is accepted.
            const std::vector<CBlockHeader> genesis_header{static_cast<const CBlockHeader&>(rt->GenesisBlock())};
            Check("...while the genesis header, mined against it, is accepted",
                  HasValidProofOfWork(genesis_header, rc));
        }
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
