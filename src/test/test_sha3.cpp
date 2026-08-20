// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Lattica — SHA3-256 known-answer tests + cross-check CLI.
//
// Standalone for now (own main); folds into the test framework when it lands.
//
//   no args        run the built-in KATs, exit non-zero on any failure
//   --hex <hex>    print SHA3-256 of the given hex-encoded bytes (one line)
//
// The --hex mode lets an external oracle (e.g. python hashlib.sha3_256) feed
// arbitrary inputs and diff the digests, proving correctness across the
// multi-block (>136-byte rate) absorb path, not just the short KATs below.

#include <crypto/sha3.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

std::string ToHex(std::span<const unsigned char> b)
{
    static constexpr char k[] = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (unsigned char c : b) { s.push_back(k[c >> 4]); s.push_back(k[c & 0x0f]); }
    return s;
}

bool FromHex(const std::string& h, std::vector<unsigned char>& out)
{
    if (h.size() % 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    for (size_t i = 0; i < h.size(); i += 2) {
        int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string Sha3Hex(std::span<const unsigned char> in)
{
    std::array<unsigned char, SHA3_256::OUTPUT_SIZE> out{};
    SHA3_256().Write(in).Finalize(out);
    return ToHex(out);
}

std::string Sha3Hex(const std::string& s)
{
    return Sha3Hex(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size()));
}

int g_fail = 0;
void Check(const char* name, const std::string& got, const std::string& want)
{
    const bool ok = (got == want);
    std::printf("[%s] %-22s %s\n", ok ? "PASS" : "FAIL", name, got.c_str());
    if (!ok) { std::printf("       want                   %s\n", want.c_str()); ++g_fail; }
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 3 && std::strcmp(argv[1], "--hex") == 0) {
        std::vector<unsigned char> in;
        if (!FromHex(argv[2], in)) { std::fprintf(stderr, "bad hex\n"); return 2; }
        std::printf("%s\n", Sha3Hex(std::span<const unsigned char>(in.data(), in.size())).c_str());
        return 0;
    }

    // NIST FIPS 202 known-answer vectors.
    Check("empty", Sha3Hex(std::string("")),
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    Check("abc", Sha3Hex(std::string("abc")),
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    // Incremental Write (chunked) must equal the one-shot digest, including
    // across the 136-byte rate boundary. Build a 200-byte 0xa3 message.
    {
        std::vector<unsigned char> msg(200, 0xa3);
        const std::string oneshot = Sha3Hex(std::span<const unsigned char>(msg.data(), msg.size()));
        SHA3_256 h;
        size_t off = 0;
        for (size_t step : {1u, 7u, 8u, 9u, 64u, 111u}) {
            const size_t n = std::min<size_t>(step, msg.size() - off);
            h.Write(std::span<const unsigned char>(msg.data() + off, n));
            off += n;
        }
        h.Write(std::span<const unsigned char>(msg.data() + off, msg.size() - off));
        std::array<unsigned char, SHA3_256::OUTPUT_SIZE> out{};
        h.Finalize(out);
        Check("chunked==oneshot(200B)", ToHex(out), oneshot);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
