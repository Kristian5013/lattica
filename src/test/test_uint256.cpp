// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// uint256 known-answer / property tests + cross-check CLI.
// Standalone for now (own main); folds into the test framework when it lands.
//
//   no args            run the built-in checks, exit non-zero on any failure
//   --roundtrip <64h>  FromHex(h).GetHex()  (must echo h back)
//   --raw <64h>        the raw little-endian bytes of FromHex(h) as forward hex
//                      (must equal python: reversed(bytes.fromhex(h)).hex())

#include <uint256.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace {

std::string FwdHex(const unsigned char* p, size_t n)
{
    static constexpr char k[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(k[p[i] >> 4]); s.push_back(k[p[i] & 0x0f]); }
    return s;
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
    if (argc == 3 && std::strcmp(argv[1], "--roundtrip") == 0) {
        auto v = uint256::FromHex(argv[2]);
        if (!v) { std::fprintf(stderr, "bad hex\n"); return 2; }
        std::printf("%s\n", v->GetHex().c_str());
        return 0;
    }
    if (argc == 3 && std::strcmp(argv[1], "--raw") == 0) {
        auto v = uint256::FromHex(argv[2]);
        if (!v) { std::fprintf(stderr, "bad hex\n"); return 2; }
        std::printf("%s\n", FwdHex(v->data(), 32).c_str());
        return 0;
    }

    // ZERO / ONE constants.
    Check("ZERO.IsNull", uint256::ZERO.IsNull());
    Check("ZERO.GetHex", uint256::ZERO.GetHex() == std::string(64, '0'));
    const std::string one_hex = std::string(62, '0') + "01";
    Check("ONE.GetHex", uint256::ONE.GetHex() == one_hex);
    Check("ONE.data[0]==1", uint256::ONE.data()[0] == 1);
    Check("ONE.GetUint64(0)==1", uint256::ONE.GetUint64(0) == 1);

    // Ordering / equality.
    Check("ZERO<ONE", uint256::ZERO < uint256::ONE);
    Check("!(ONE<ZERO)", !(uint256::ONE < uint256::ZERO));
    Check("ZERO!=ONE", !(uint256::ZERO == uint256::ONE));

    // FromHex round-trip + reverse-byte property.
    {
        const std::string h = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        auto v = uint256::FromHex(h);
        Check("FromHex ok", v.has_value());
        Check("FromHex roundtrip", v && v->GetHex() == h);
        Check("FromHex reverse b0==ff", v && v->data()[0] == 0xff);
        Check("FromHex reverse b31==00", v && v->data()[31] == 0x00);
    }

    // span constructor + GetHex reverse + GetUint64.
    {
        std::array<unsigned char, 32> b{};
        for (int i = 0; i < 32; ++i) b[i] = static_cast<unsigned char>(i);
        uint256 u{std::span<const unsigned char>(b)};
        const std::string g = u.GetHex();
        Check("span GetHex head==1f", g.substr(0, 2) == "1f");
        Check("span GetHex tail==00", g.substr(62, 2) == "00");
        Check("span GetUint64(0)", u.GetUint64(0) == 0x0706050403020100ULL);
    }

    // consteval string_view constructor (evaluated at compile time).
    {
        static constexpr uint256 K{std::string_view{"0000000000000000000000000000000000000000000000000000000000000001"}};
        Check("consteval ctor == ONE", K == uint256::ONE);
    }

    // FromHex rejects bad input; FromUserHex accepts 0x prefix + padding.
    Check("FromHex bad length", !uint256::FromHex("00").has_value());
    Check("FromHex non-hex", !uint256::FromHex(std::string(63, '0') + "g").has_value());
    {
        auto v = uint256::FromUserHex("0x1");
        Check("FromUserHex 0x1", v && v->GetHex() == one_hex);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
