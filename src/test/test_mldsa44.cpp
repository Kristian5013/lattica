// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// ML-DSA-44 (FIPS 204) vendored library smoke test: keypair / sign / verify
// round-trip + rejection of tampered signature, tampered message, and a wrong
// public key. Standalone for now (own main); folds into the test framework
// when it lands.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include "api.h"
}

namespace {
std::vector<uint8_t> FromHex(const char* h)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
        out.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    }
    return out;
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
    // KAT driver: verify one (pk, msg, sig[, ctx]) and print "valid"/"invalid".
    // Drives the wycheproof ML-DSA-44 sigVer vectors via FIPS 204 verify_ctx.
    if (argc >= 5 && std::strcmp(argv[1], "--verify") == 0) {
        const std::vector<uint8_t> pk = FromHex(argv[2]);
        const std::vector<uint8_t> msg = FromHex(argv[3]);
        const std::vector<uint8_t> sig = FromHex(argv[4]);
        const std::vector<uint8_t> ctx = (argc >= 6) ? FromHex(argv[5]) : std::vector<uint8_t>{};
        // The raw verify takes no public-key length; a well-formed ML-DSA-44 key
        // is exactly 1312 bytes, so reject any other length here (the job of the
        // wrapper that will sit on top of this library).
        if (pk.size() != PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES) {
            std::printf("invalid\n");
            return 0;
        }
        const int r = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(
            sig.data(), sig.size(), msg.data(), msg.size(), ctx.data(), ctx.size(), pk.data());
        std::printf("%s\n", r == 0 ? "valid" : "invalid");
        return 0;
    }

    constexpr size_t PK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
    constexpr size_t SK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
    constexpr size_t SIGMAX = PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;

    // FIPS 204 ML-DSA-44 fixed sizes.
    Check("pubkey size == 1312", PK == 1312);
    Check("seckey size == 2560", SK == 2560);
    Check("signature size == 2420", SIGMAX == 2420);

    static uint8_t pk[PK], sk[SK], sig[SIGMAX];
    size_t siglen = 0;
    uint8_t msg[] = "Lattica ML-DSA-44 (FIPS 204) test message";
    const size_t mlen = sizeof(msg) - 1;

    Check("keypair", PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) == 0);
    Check("sign", PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, mlen, sk) == 0);
    Check("siglen == 2420", siglen == SIGMAX);
    Check("verify valid", PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk) == 0);

    // Tampered signature is rejected, and restoring it makes it valid again.
    sig[100] ^= 0x01;
    Check("tampered signature rejected",
          PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk) != 0);
    sig[100] ^= 0x01;
    Check("restored signature valid",
          PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk) == 0);

    // Tampered message is rejected.
    msg[0] ^= 0x01;
    Check("tampered message rejected",
          PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk) != 0);
    msg[0] ^= 0x01;

    // A signature does not verify under a different key pair.
    static uint8_t pk2[PK], sk2[SK];
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk2, sk2);
    Check("wrong public key rejected",
          PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk2) != 0);

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
