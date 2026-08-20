// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the bech32/bech32m string codec (bech32.cpp), a verbatim port of the
// standard BIP173/BIP350 implementation. Uses official spec test vectors: valid
// strings decode with the right encoding/hrp and re-encode to the lowercase
// input; invalid strings decode to Encoding::INVALID.

#include <bech32.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

std::string ToLower(std::string s)
{
    for (char& c : s) if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
    return s;
}
} // namespace

int main()
{
    // BIP173 valid bech32 strings.
    const char* valid_bech32[] = {
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "?1ezyfcl",
    };
    for (const char* s : valid_bech32) {
        const auto dec = bech32::Decode(s);
        Check("valid bech32 decodes as BECH32", dec.encoding == bech32::Encoding::BECH32);
        Check("bech32 re-encodes to lowercase input", bech32::Encode(bech32::Encoding::BECH32, dec.hrp, dec.data) == ToLower(s));
    }

    // BIP350 valid bech32m strings.
    const char* valid_bech32m[] = {
        "A1LQFN3A",
        "a1lqfn3a",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    };
    for (const char* s : valid_bech32m) {
        const auto dec = bech32::Decode(s);
        Check("valid bech32m decodes as BECH32M", dec.encoding == bech32::Encoding::BECH32M);
        Check("bech32m re-encodes to lowercase input", bech32::Encode(bech32::Encoding::BECH32M, dec.hrp, dec.data) == ToLower(s));
    }

    // Spot-check the decoded contents and that the two encodings are distinguished.
    {
        const auto a = bech32::Decode("A12UEL5L");
        Check("A12UEL5L -> hrp 'a', empty data, BECH32",
              a.hrp == "a" && a.data.empty() && a.encoding == bech32::Encoding::BECH32);
        const auto b = bech32::Decode("A1LQFN3A");
        Check("A1LQFN3A -> hrp 'a', BECH32M", b.hrp == "a" && b.encoding == bech32::Encoding::BECH32M);
    }

    // Invalid strings -> INVALID.
    const char* invalid[] = {
        "",                  // empty
        "A12UEL5X",          // invalid checksum
        "x1b4n0q5v",         // invalid checksum
        "pzry9x0s0muk",      // no separator
        "1qzzfhee",          // empty hrp
        "a12UEL5L",          // mixed case
    };
    for (const char* s : invalid) {
        Check("invalid string -> INVALID", bech32::Decode(s).encoding == bech32::Encoding::INVALID);
    }

    // Arbitrary 5-bit payload round-trips, and bech32 != bech32m of the same data.
    {
        std::vector<uint8_t> data;
        for (int i = 0; i < 40; ++i) data.push_back(static_cast<uint8_t>(i % 32));
        const std::string enc = bech32::Encode(bech32::Encoding::BECH32, "flow", data);
        const auto dec = bech32::Decode(enc);
        Check("custom-hrp bech32 round-trips",
              dec.encoding == bech32::Encoding::BECH32 && dec.hrp == "flow" && dec.data == data);
        const std::string encm = bech32::Encode(bech32::Encoding::BECH32M, "flow", data);
        const auto decm = bech32::Decode(encm);
        Check("custom-hrp bech32m round-trips",
              decm.encoding == bech32::Encoding::BECH32M && decm.data == data);
        Check("bech32 and bech32m of same data differ", enc != encm);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
