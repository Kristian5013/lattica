// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// SHA3-512 (FIPS 202) tests: NIST known answers + byte-for-byte cross-check
// against Python hashlib.sha3_512, plus streaming-equivalence and midstate-copy
// (the copy is relied on by the SHA3-adapted RNG entropy pool). The --dump mode
// emits hex digests for a fixed input set the Python reference reproduces.

#include <crypto/sha3_512.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::string ToHex(const unsigned char* d, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += h[d[i] >> 4]; s += h[d[i] & 0xf]; }
    return s;
}

std::string SHA3_512Hex(const std::vector<unsigned char>& in)
{
    unsigned char out[SHA3_512::OUTPUT_SIZE];
    SHA3_512().Write(in.data(), in.size()).Finalize(out);
    return ToHex(out, sizeof(out));
}

// Deterministic input #idx, identical formula in the Python reference.
std::vector<unsigned char> GenInput(int idx)
{
    const size_t len = (size_t)(idx * 37) % 400; // 0..399, crosses the 72-byte rate
    std::vector<unsigned char> v(len);
    for (size_t i = 0; i < len; ++i) v[i] = (unsigned char)((idx * 131 + i * 197 + 17) & 0xff);
    return v;
}
const int kNumInputs = 12;

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
        for (int i = 0; i < kNumInputs; ++i) std::printf("%s\n", SHA3_512Hex(GenInput(i)).c_str());
        return 0;
    }

    // NIST known answers.
    Check("SHA3-512(\"\")",
          SHA3_512Hex({}) == "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    {
        std::vector<unsigned char> abc{'a', 'b', 'c'};
        Check("SHA3-512(\"abc\")",
              SHA3_512Hex(abc) == "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    }

    // Streaming in odd chunks == one-shot (crosses the 72-byte rate boundary).
    {
        std::vector<unsigned char> in = GenInput(7); // ~259 bytes
        unsigned char one[64], streamed[64];
        SHA3_512().Write(in.data(), in.size()).Finalize(one);
        SHA3_512 h;
        for (size_t off = 0; off < in.size();) {
            size_t chunk = std::min<size_t>(13, in.size() - off);
            h.Write(in.data() + off, chunk);
            off += chunk;
        }
        h.Finalize(streamed);
        Check("streaming == one-shot", std::memcmp(one, streamed, 64) == 0);
    }

    // Midstate copy: copy after a partial write, finish both with different tails.
    {
        SHA3_512 base;
        const unsigned char pre[] = "common-prefix-entropy";
        base.Write(pre, sizeof(pre) - 1);
        SHA3_512 a = base, b = base; // copy midstate
        const unsigned char ta[] = "AAAA";
        const unsigned char tb[] = "BBBB";
        unsigned char da[64], db[64], ref_a[64], ref_b[64];
        a.Write(ta, 4); a.Finalize(da);
        b.Write(tb, 4); b.Finalize(db);
        // Independent references.
        { SHA3_512 r; r.Write(pre, sizeof(pre) - 1); r.Write(ta, 4); r.Finalize(ref_a); }
        { SHA3_512 r; r.Write(pre, sizeof(pre) - 1); r.Write(tb, 4); r.Finalize(ref_b); }
        Check("midstate copy (branch A)", std::memcmp(da, ref_a, 64) == 0);
        Check("midstate copy (branch B)", std::memcmp(db, ref_b, 64) == 0);
        Check("Size() tracks bytes", a.Size() == sizeof(pre) - 1 + 4);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
