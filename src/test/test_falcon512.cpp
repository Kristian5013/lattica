// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Falcon-512 (PQClean falcon-padded-512) vendored library smoke test: keypair /
// sign / verify round-trip, rejection of a tampered signature, a tampered
// message and a foreign public key, and the two properties the padded variant
// exists for — a signature that is always exactly CRYPTO_BYTES long, and a
// length the verifier will not accept anything else at.
//
// Also pinned here: Falcon signing is randomized, so two signatures over the
// same message differ. That is the opposite of the ML-DSA and secp256k1 paths
// in this tree and it is worth failing loudly if it ever changes, because a
// deterministic Falcon would mean the nonce source was replaced.
//
// The entry points are declared rather than included: three PQClean trees ship
// an "api.h" on the shared include path, so crypto/mlkem.cpp established
// declaring the symbols directly. Standalone for now (own main).

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(uint8_t* pk, uint8_t* sk);
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
    uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
    const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
}

namespace {

constexpr size_t PK_BYTES = 897;
constexpr size_t SK_BYTES = 1281;
constexpr size_t SIG_BYTES = 666;

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

} // namespace

int main()
{
    std::vector<uint8_t> pk(PK_BYTES), sk(SK_BYTES);
    Check("keypair succeeds",
          PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0);

    // A Falcon public key is a packed polynomial whose first byte encodes the
    // degree; for n = 512 that header is 0x09.
    Check("public key header says n = 512", pk[0] == 0x09);

    const char* msg = "Lattica Falcon-512 round-trip";
    const size_t mlen = std::strlen(msg);
    const auto* m = reinterpret_cast<const uint8_t*>(msg);

    std::vector<uint8_t> sig(SIG_BYTES);
    size_t siglen = 0;
    Check("sign succeeds",
          PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
              sig.data(), &siglen, m, mlen, sk.data()) == 0);
    Check("signature is exactly 666 bytes (the padded form)", siglen == SIG_BYTES);
    Check("signature verifies",
          PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
              sig.data(), siglen, m, mlen, pk.data()) == 0);

    // Padding is load-bearing: the verifier must reject any other length, or the
    // fixed-size contract SchemeSignatureSize() rests on would be a fiction.
    Check("a 665-byte signature is rejected",
          PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
              sig.data(), siglen - 1, m, mlen, pk.data()) != 0);

    {
        std::vector<uint8_t> bad = sig;
        bad[10] ^= 0x01;
        Check("a tampered signature is rejected",
              PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                  bad.data(), siglen, m, mlen, pk.data()) != 0);
    }

    {
        std::vector<uint8_t> other_msg(m, m + mlen);
        other_msg[0] ^= 0x01;
        Check("a tampered message is rejected",
              PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                  sig.data(), siglen, other_msg.data(), mlen, pk.data()) != 0);
    }

    {
        std::vector<uint8_t> pk2(PK_BYTES), sk2(SK_BYTES);
        PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk2.data(), sk2.data());
        Check("two keypairs differ", pk2 != pk);
        Check("a foreign public key does not verify",
              PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                  sig.data(), siglen, m, mlen, pk2.data()) != 0);
    }

    // Falcon's Gaussian sampler is seeded per signature, so this is randomized.
    {
        std::vector<uint8_t> sig2(SIG_BYTES);
        size_t siglen2 = 0;
        PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
            sig2.data(), &siglen2, m, mlen, sk.data());
        Check("signing is randomized, not deterministic", sig2 != sig);
        Check("the second signature also verifies",
              PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                  sig2.data(), siglen2, m, mlen, pk.data()) == 0);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
