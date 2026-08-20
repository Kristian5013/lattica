// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Lattica — RIPEMD-160 known-answer tests, plus the Hash160 composition.
//
// The eight message KATs are the reference vectors published with the algorithm
// (Dobbertin/Bosselaers/Preneel), including the one-million-'a' case that is the
// only one exercising the 64-bit length counter past a single block. Streaming
// and Reset() are checked separately because Hash160 feeds a 32-byte digest in
// one Write, which on its own would never touch the buffered path.
//
// The last two checks are about the composition rather than the primitive: that
// Hash160 really is RIPEMD160(SHA3-256(x)), and that it is no longer a prefix of
// SHA3-256(x) — the property the second stage exists to break.

#include <crypto/ripemd160.h>
#include <hash.h>
#include <uint256.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

void Check(const char* name, const std::string& got, const std::string& want)
{
    const bool ok = (got == want);
    std::printf("[%s] %-28s %s\n", ok ? "PASS" : "FAIL", name, got.c_str());
    if (!ok) { std::printf("       want                         %s\n", want.c_str()); ++g_fail; }
}

void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

std::string ToHex(std::span<const unsigned char> b)
{
    static constexpr char k[] = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (unsigned char c : b) { s.push_back(k[c >> 4]); s.push_back(k[c & 0x0f]); }
    return s;
}

std::string RIPEMD160Hex(std::span<const unsigned char> in)
{
    std::array<unsigned char, CRIPEMD160::OUTPUT_SIZE> out{};
    CRIPEMD160().Write(in.data(), in.size()).Finalize(out.data());
    return ToHex(out);
}

std::string RIPEMD160Hex(const std::string& s)
{
    return RIPEMD160Hex(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(s.data()), s.size()));
}

} // namespace

int main()
{
    // --- Reference vectors ---------------------------------------------------
    Check("\"\"", RIPEMD160Hex(std::string{}),
          "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    Check("\"a\"", RIPEMD160Hex("a"),
          "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    Check("\"abc\"", RIPEMD160Hex("abc"),
          "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    Check("\"message digest\"", RIPEMD160Hex("message digest"),
          "5d0689ef49d2fae572b881b123a85ffa21595f36");
    Check("a..z", RIPEMD160Hex("abcdefghijklmnopqrstuvwxyz"),
          "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    Check("abcdbcde..nopq",
          RIPEMD160Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
          "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
    Check("A..Za..z0..9",
          RIPEMD160Hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
          "b0e20b6e3116640286ed3a87a5713079b21f5189");
    {
        std::string s;
        for (int i = 0; i < 8; ++i) s += "1234567890";
        Check("8x\"1234567890\"", RIPEMD160Hex(s),
              "9b752e45573d4b39f4dbd3323cab82bf63326bfb");
    }
    {
        const std::vector<unsigned char> million(1000000, 'a');
        Check("1e6 x 'a'", RIPEMD160Hex(million),
              "52783243c1697bdbe16d37f97f68f08325dc1528");
    }

    // --- Streaming and Reset -------------------------------------------------
    {
        std::vector<unsigned char> data(1000);
        for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<unsigned char>(i * 7 + 3);
        const std::string oneshot = RIPEMD160Hex(data);

        // Chunk sizes straddling the 64-byte block so the buffered path runs.
        CRIPEMD160 h;
        size_t pos = 0;
        for (size_t chunk : {1u, 63u, 64u, 65u, 127u, 200u}) {
            const size_t n = std::min(chunk, data.size() - pos);
            h.Write(data.data() + pos, n);
            pos += n;
        }
        h.Write(data.data() + pos, data.size() - pos);
        std::array<unsigned char, CRIPEMD160::OUTPUT_SIZE> out{};
        h.Finalize(out.data());
        Check("chunked == one-shot", ToHex(out), oneshot);

        CRIPEMD160 r;
        r.Write(data.data(), data.size());
        std::array<unsigned char, CRIPEMD160::OUTPUT_SIZE> discard{};
        r.Finalize(discard.data());
        r.Reset().Write(data.data(), data.size());
        std::array<unsigned char, CRIPEMD160::OUTPUT_SIZE> after{};
        r.Finalize(after.data());
        Check("Reset() == fresh hasher", ToHex(after), oneshot);
    }

    // --- Hash160 composition -------------------------------------------------
    {
        const std::vector<unsigned char> data{'s', 'c', 'r', 'i', 'p', 't'};
        const uint256 inner = Hash(data);
        std::array<unsigned char, CRIPEMD160::OUTPUT_SIZE> expected{};
        CRIPEMD160().Write(inner.begin(), inner.size()).Finalize(expected.data());

        const uint160 h160 = Hash160(data);
        Check("Hash160 == RIPEMD160(SHA3-256)",
              ToHex(std::span<const unsigned char>(h160.begin(), h160.size())),
              ToHex(expected));

        // The reason the second stage is a hash and not a truncation.
        bool is_prefix = true;
        for (size_t i = 0; i < h160.size(); ++i) {
            if (h160.begin()[i] != inner.begin()[i]) { is_prefix = false; break; }
        }
        Check("Hash160 is not a SHA3-256 prefix", !is_prefix);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
