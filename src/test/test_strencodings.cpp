// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// util/strencodings known-answer / property tests + cross-check CLI.
// Standalone for now (own main); folds into the test framework when it lands.
//
//   no args         run the built-in checks, exit non-zero on any failure
//   --hexrt  <hex>  HexStr(ParseHex(hex))                 (forward-hex round-trip)
//   --b64enc <hex>  EncodeBase64(ParseHex(hex))
//   --b64dec <b64>  forward hex of DecodeBase64(b64)
//   --b32enc <hex>  EncodeBase32(ParseHex(hex))

#include <crypto/hex_base.h>
#include <util/strencodings.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace util::hex_literals;

namespace {

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 3) {
        const std::string arg = argv[2];
        if (std::strcmp(argv[1], "--hexrt") == 0) {
            std::printf("%s\n", HexStr(ParseHex(arg)).c_str());
            return 0;
        }
        if (std::strcmp(argv[1], "--b64enc") == 0) {
            std::printf("%s\n", EncodeBase64(std::span<const unsigned char>(ParseHex<unsigned char>(arg))).c_str());
            return 0;
        }
        if (std::strcmp(argv[1], "--b64dec") == 0) {
            auto d = DecodeBase64(arg);
            if (!d) { std::fprintf(stderr, "bad b64\n"); return 2; }
            std::printf("%s\n", HexStr(*d).c_str());
            return 0;
        }
        if (std::strcmp(argv[1], "--b32enc") == 0) {
            std::printf("%s\n", EncodeBase32(std::span<const unsigned char>(ParseHex<unsigned char>(arg))).c_str());
            return 0;
        }
    }

    // IsHex.
    Check("IsHex 00ff", IsHex("00ff"));
    Check("IsHex empty=false", !IsHex(""));
    Check("IsHex odd=false", !IsHex("0"));
    Check("IsHex non-hex=false", !IsHex("0g"));

    // ParseHex / TryParseHex.
    {
        auto v = ParseHex("00ff10");
        Check("ParseHex bytes", v.size() == 3 && v[0] == 0x00 && v[1] == 0xff && v[2] == 0x10);
        Check("ParseHex skips ws", ParseHex("00 ff") == std::vector<uint8_t>({0x00, 0xff}));
        Check("TryParseHex odd=null", !TryParseHex("abc").has_value());
        Check("TryParseHex bad=null", !TryParseHex("zz").has_value());
    }

    // Base64 round-trip + known answer.
    {
        Check("EncodeBase64 empty", EncodeBase64(std::string_view("")) == "");
        Check("EncodeBase64 'foobar'", EncodeBase64(std::string_view("foobar")) == "Zm9vYmFy");
        auto d = DecodeBase64("Zm9vYmFy");
        Check("DecodeBase64 'foobar'", d && std::string(d->begin(), d->end()) == "foobar");
    }

    // Base32 (Core uses a lowercase alphabet).
    Check("EncodeBase32 'foobar'", EncodeBase32(std::string_view("foobar")) == "mzxw6ytboi======");
    {
        auto d = DecodeBase32("mzxw6ytboi======");
        Check("DecodeBase32 'foobar'", d && std::string(d->begin(), d->end()) == "foobar");
    }

    // Case conversion (locale-independent, ASCII only).
    Check("ToLower", ToLower(std::string_view("AbC123Z")) == "abc123z");
    Check("ToUpper", ToUpper(std::string_view("AbC123z")) == "ABC123Z");

    // ToIntegral.
    Check("ToIntegral 123", ToIntegral<int>("123") == std::optional<int>(123));
    Check("ToIntegral trailing=null", !ToIntegral<int>("12a").has_value());
    Check("ToIntegral leading-ws=null", !ToIntegral<int>(" 12").has_value());

    // ParseFixedPoint (8 decimals, like an amount).
    {
        int64_t out = 0;
        Check("ParseFixedPoint 1.5", ParseFixedPoint("1.5", 8, &out) && out == 150000000);
        Check("ParseFixedPoint bad", !ParseFixedPoint("1.5.5", 8, &out));
    }

    // Compile-time _hex literal.
    {
        constexpr auto h = "deadbeef"_hex;
        Check("\"deadbeef\"_hex", h.size() == 4 && h[0] == std::byte{0xde} && h[3] == std::byte{0xef});
    }

    // Char classifiers.
    Check("IsDigit/IsSpace", IsDigit('7') && !IsDigit('a') && IsSpace(' ') && IsSpace('\n') && !IsSpace('x'));

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
