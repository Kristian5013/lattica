// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// pow (CheckProofOfWork) tests: structurally-certain rejections (target 0,
// negative/overflow nBits, above-powLimit clamp) plus a positive control, and a
// --dump mode whose target-decode + clamp + compare predicate is cross-checked
// against an independent Python reference (arbitrary-precision integers).
// Standalone for now.

#include <arith_uint256.h>
#include <consensus/params.h>
#include <hash.h>
#include <pow.h>
#include <uint256.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

// Same compact targets and powLimits the Python reference iterates (same order).
const uint32_t kBits[] = {
    0x2100ffff, 0x2000ffff, 0x1f00ffff, 0x1d00ffff, 0x03000000, 0x04923456, 0xff123456,
};
const uint32_t kLimits[] = {0x2100ffff, 0x1f00ffff};
const int kNumCommits = 8;

//! Deterministic 32-byte input pattern, identical formula in the Python ref.
uint256 GenInput(int idx)
{
    uint256 h;
    for (unsigned int i = 0; i < uint256::size(); ++i)
        h.begin()[i] = (unsigned char)((idx * 131 + (int)i * 197 + 17) & 0xff);
    return h;
}

//! A minimal Consensus::Params carrying just the powLimit the pow check needs.
Consensus::Params MakeParams(uint32_t powLimitCompact)
{
    Consensus::Params p{};
    arith_uint256 bn;
    bn.SetCompact(powLimitCompact);
    p.powLimit = ArithToUint256(bn);
    return p;
}

//! A deterministic proof-of-work value to probe CheckProofOfWork with.
uint256 PowOf(int idx) { return Hash(GenInput(idx)); }

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
        for (uint32_t limitC : kLimits) {
            const Consensus::Params params = MakeParams(limitC);
            for (int idx = 0; idx < kNumCommits; ++idx) {
                const uint256 pow = PowOf(idx);
                for (uint32_t bits : kBits) {
                    int ok = CheckProofOfWork(pow, bits, params) ? 1 : 0;
                    std::printf("%08x %d %08x %d\n", limitC, idx, bits, ok);
                }
            }
        }
        return 0;
    }

    const uint256 pow0 = PowOf(0);
    const Consensus::Params pMax = MakeParams(0x2100ffff);   // ~2^256 - 2^240 (near max)
    const Consensus::Params pSmall = MakeParams(0x1f00ffff); // ~2^240

    // Structurally-certain rejections (independent of the hash value).
    Check("target 0 (0x03000000) rejected", !CheckProofOfWork(pow0, 0x03000000, pMax));
    Check("negative nBits (0x04923456) rejected", !CheckProofOfWork(pow0, 0x04923456, pMax));
    Check("overflow nBits (0xff123456) rejected", !CheckProofOfWork(pow0, 0xff123456, pMax));
    // Target decodes fine but exceeds powLimit -> rejected by the clamp.
    Check("above-powLimit target rejected", !CheckProofOfWork(pow0, 0x2100ffff, pSmall));

    // Positive control: at a near-max target some pow must pass, proving the
    // function is not vacuously false (and the big-endian path is wired).
    bool anyValid = false;
    for (int i = 0; i < 256 && !anyValid; ++i) {
        if (CheckProofOfWork(PowOf(i), 0x2100ffff, pMax)) anyValid = true;
    }
    Check("some pow passes at near-max target", anyValid);

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
