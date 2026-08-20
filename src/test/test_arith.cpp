// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// arith_uint256 tests: arithmetic invariants + the difficulty "compact" codec
// (SetCompact/GetCompact) and UintToArith256/ArithToUint256. The --dump mode
// emits target/recompact for a fixed compact set, cross-checked byte-for-byte
// against an independent Python implementation of the same format. Standalone
// for now (own main); folds into the test framework when it lands.

#include <arith_uint256.h>
#include <uint256.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

// The exact compact inputs the Python reference also iterates (same order).
const uint32_t kCompacts[] = {
    0x00000000, 0x01003456, 0x01123456, 0x02008000, 0x05009234,
    0x05123456, 0x0600c0de, 0x04923456, 0x01fedcba, 0x1d00ffff,
    0x1f00ffff, 0x20123456, 0x207fffff, 0x03000000, 0xff123456,
};

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
        for (uint32_t c : kCompacts) {
            arith_uint256 n;
            bool neg = false, ovf = false;
            n.SetCompact(c, &neg, &ovf);
            std::printf("%08x %s %08x %d %d\n",
                        c, n.GetHex().c_str(), n.GetCompact(false), neg ? 1 : 0, ovf ? 1 : 0);
        }
        return 0;
    }

    // --- arithmetic invariants (no external reference needed) ---
    {
        arith_uint256 z;
        Check("zero.GetCompact()==0", z.GetCompact() == 0);
        Check("zero==0", z == 0);
    }
    {
        arith_uint256 a = 0x123456789aULL;
        Check("GetLow64", a.GetLow64() == 0x123456789aULL);
    }
    {
        arith_uint256 a = 0x123456789aULL, b = 0x1000ULL;
        Check("(a+b)-b==a", ((a + b) - b) == a);
        Check("a*1==a", (a * (uint32_t)1) == a);
        Check("a*0==0", (a * (uint32_t)0) == 0);
    }
    {
        arith_uint256 one = 1;
        Check("(1<<200)>>200==1", ((one << 200) >> 200) == one);
        Check("(1<<255)>>255==1", ((one << 255) >> 255) == one);
        Check("(1<<255)>>256==0", ((one << 255) >> 256) == 0);
    }
    {
        // multiply / divide consistency: (x*y)/y == x
        arith_uint256 x = 0xdeadbeefULL, y = 0x1234ULL;
        Check("(x*y)/y==x", ((x * y) / y) == x);
    }
    {
        // ordering
        arith_uint256 a = 5, b = 6;
        Check("a<b", a < b);
        Check("b>a", b > a);
        Check("a<=a", a <= a && a >= a);
    }

    // --- compact codec: canonical round-trips (GetCompact∘SetCompact == id) ---
    for (uint32_t c : {0x05123456u, 0x0600c0deu, 0x1d00ffffu, 0x1f00ffffu, 0x20123456u}) {
        arith_uint256 n;
        n.SetCompact(c);
        char name[64];
        std::snprintf(name, sizeof(name), "recompact 0x%08x", c);
        Check(name, n.GetCompact() == c);
    }
    {
        // documented sign handling: 0x04923456 is negative; positive re-encode is 0x04123456,
        // and asking for the negative form returns the original.
        arith_uint256 n;
        bool neg = false, ovf = false;
        n.SetCompact(0x04923456, &neg, &ovf);
        Check("0x04923456 negative flag", neg && !ovf);
        Check("0x04923456 GetCompact(false)", n.GetCompact(false) == 0x04123456);
        Check("0x04923456 GetCompact(true)", n.GetCompact(true) == 0x04923456);
    }
    {
        // overflow flag (size byte huge); value truncates to 0 in 256 bits.
        arith_uint256 n;
        bool neg = false, ovf = false;
        n.SetCompact(0xff123456, &neg, &ovf);
        Check("0xff123456 overflow flag", ovf);
    }

    // --- UintToArith256 / ArithToUint256 round-trip ---
    {
        arith_uint256 n;
        n.SetCompact(0x1f00ffff);
        Check("Uint<->Arith round-trip", UintToArith256(ArithToUint256(n)) == n);
        // exact target hex (incl. 0x1d00ffff -> 00000000ffff00..00) is verified
        // against the independent Python reference via the --dump cross-check.
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
