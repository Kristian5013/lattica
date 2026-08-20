// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// RNG tests for the SHA3-adapted random subsystem (entropy pool mixed with
// SHA3-512 instead of Bitcoin's SHA-512/SHA-256; ChaCha20 output; OS entropy):
// deterministic reproducibility, seeded reproducibility, entropy across
// instances, the global secure RNG, and the OS-RNG sanity check.

#include <random.h>
#include <uint256.h>

#include <cstdio>
#include <vector>

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
    // Deterministic FastRandomContext: two instances produce the same stream.
    {
        FastRandomContext a(true), b(true);
        bool ok = true;
        for (int i = 0; i < 16; ++i) if (a.rand64() != b.rand64()) ok = false;
        Check("deterministic FastRandomContext reproducible", ok);
    }

    // Seeded FastRandomContext: same seed -> same stream; different seed -> differs.
    {
        uint256 seed1 = uint256{"00000000000000000000000000000000000000000000000000000000000000aa"};
        uint256 seed2 = uint256{"00000000000000000000000000000000000000000000000000000000000000bb"};
        FastRandomContext a(seed1), b(seed1), c(seed2);
        bool same = true, diff = false;
        for (int i = 0; i < 16; ++i) {
            uint64_t va = a.rand64(), vb = b.rand64(), vc = c.rand64();
            if (va != vb) same = false;
            if (va != vc) diff = true;
        }
        Check("seeded FastRandomContext reproducible (same seed)", same);
        Check("seeded FastRandomContext differs (different seed)", diff);
    }

    // Non-deterministic contexts are seeded with real entropy and differ.
    {
        FastRandomContext c, d;
        Check("non-deterministic contexts differ", c.rand64() != d.rand64());
    }

    // Global secure RNG: SHA3-512 entropy pool + OS entropy + ChaCha20.
    {
        std::vector<unsigned char> z1(32, 0), z2(32, 0);
        GetRandBytes(z1);
        GetRandBytes(z2);
        Check("GetRandBytes varies", z1 != z2);
        GetStrongRandBytes(z1);
        bool nonzero = false;
        for (auto b : z1) if (b) nonzero = true;
        Check("GetStrongRandBytes nonzero", nonzero);
    }

    // randrange stays in bounds.
    {
        FastRandomContext rng(true);
        bool ok = true;
        for (int i = 0; i < 1000; ++i) if (rng.randrange(100) >= 100) ok = false;
        Check("randrange(100) in [0,100)", ok);
    }

    Check("Random_SanityCheck (OS RNG)", Random_SanityCheck());

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
