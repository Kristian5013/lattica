// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Correctness test for the vendored ML-KEM-768 (FIPS 203) KEM wrapper: a keypair's
// encapsulation/decapsulation round-trips to the same shared secret, a tampered
// ciphertext implicitly rejects to a different secret, and the size guards hold.

#include <crypto/mlkem.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>

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
    std::array<uint8_t, mlkem::PUBLICKEY_SIZE> pk{};
    std::array<uint8_t, mlkem::SECRETKEY_SIZE> sk{};
    Check("keypair generates", mlkem::Keypair(pk, sk));

    std::array<uint8_t, mlkem::CIPHERTEXT_SIZE> ct{};
    std::array<uint8_t, mlkem::SHARED_SECRET_SIZE> ss_enc{}, ss_dec{};
    Check("encapsulate to pk", mlkem::Encapsulate(ct, ss_enc, pk));
    Check("decapsulate with sk", mlkem::Decapsulate(ss_dec, ct, sk));
    Check("encapsulated == decapsulated shared secret", ss_enc == ss_dec);

    // A second keypair gives an independent shared secret (sanity: not all-zero/constant).
    std::array<uint8_t, mlkem::PUBLICKEY_SIZE> pk2{};
    std::array<uint8_t, mlkem::SECRETKEY_SIZE> sk2{};
    std::array<uint8_t, mlkem::CIPHERTEXT_SIZE> ct2{};
    std::array<uint8_t, mlkem::SHARED_SECRET_SIZE> ss2{};
    Check("second keypair", mlkem::Keypair(pk2, sk2));
    Check("encapsulate to pk2", mlkem::Encapsulate(ct2, ss2, pk2));
    Check("independent keypairs -> different shared secrets", ss2 != ss_enc);

    // Implicit rejection: a tampered ciphertext decapsulates to a *different* secret
    // (ML-KEM is IND-CCA2 and never reuses the encapsulated secret on bad input).
    auto bad_ct = ct;
    bad_ct[0] ^= 0xff;
    std::array<uint8_t, mlkem::SHARED_SECRET_SIZE> ss_bad{};
    Check("decapsulate tampered ct (no error)", mlkem::Decapsulate(ss_bad, bad_ct, sk));
    Check("tampered ciphertext -> different shared secret", ss_bad != ss_enc);

    // Size guards.
    std::array<uint8_t, 10> too_small{};
    Check("mis-sized pk rejected", !mlkem::Encapsulate(ct, ss_enc, too_small));
    Check("mis-sized sk rejected", !mlkem::Keypair(pk, too_small));

    std::printf(g_fail ? "\nFAILED (%d)\n" : "\nOK\n", g_fail);
    return g_fail ? 1 : 0;
}
