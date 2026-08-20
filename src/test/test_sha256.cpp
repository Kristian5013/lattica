// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Known-answer test for the generic SHA-256 (FIPS 180-4). This primitive is off
// Lattica's SHA3 consensus path and exists only for I2P .b32 address derivation,
// so its sole correctness requirement is bit-exact agreement with the standard
// vectors — verified here against the NIST/FIPS examples and a multi-block input.

#include <crypto/sha256.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

namespace {
int g_fail = 0;

std::string Hex(const unsigned char* d, size_t n)
{
    static const char* k = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += k[d[i] >> 4]; s += k[d[i] & 0xf]; }
    return s;
}

void KAT(const char* name, const std::string& msg, const std::string& expect)
{
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(msg.data()), msg.size()).Finalize(out);
    const std::string got = Hex(out, sizeof(out));
    const bool ok = got == expect;
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) { std::printf("      got %s\n      exp %s\n", got.c_str(), expect.c_str()); ++g_fail; }
}
} // namespace

int main()
{
    // FIPS 180-4 / NIST CAVP example vectors.
    KAT("empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    KAT("abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    KAT("two-block",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // 1,000,000 'a' (FIPS 180-4 long-message vector) — exercises the multi-block path.
    {
        CSHA256 h;
        const std::string chunk(1000, 'a');
        for (int i = 0; i < 1000; ++i) {
            h.Write(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
        }
        unsigned char out[CSHA256::OUTPUT_SIZE];
        h.Finalize(out);
        const std::string got = Hex(out, sizeof(out));
        const std::string exp = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        const bool ok = got == exp;
        std::printf("[%s] million-a\n", ok ? "PASS" : "FAIL");
        if (!ok) { std::printf("      got %s\n      exp %s\n", got.c_str(), exp.c_str()); ++g_fail; }
    }

    // Reset() returns the hasher to the initial state.
    {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>("garbage"), 7);
        h.Reset();
        unsigned char out[CSHA256::OUTPUT_SIZE];
        h.Finalize(out);
        const bool ok = Hex(out, sizeof(out)) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        std::printf("[%s] reset-to-empty\n", ok ? "PASS" : "FAIL");
        if (!ok) ++g_fail;
    }

    std::printf(g_fail ? "\nFAILED (%d)\n" : "\nOK\n", g_fail);
    return g_fail ? 1 : 0;
}
