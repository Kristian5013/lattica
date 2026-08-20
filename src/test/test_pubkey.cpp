// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the crypto-agile CPubKey over the vendored ML-DSA-44: scheme sizes,
// validity by key length, end-to-end sign/verify through CPubKey::Verify (with
// tampered message / signature / key rejected), and GetID = first 20 bytes of
// SHA3-256(scheme byte || pubkey) cross-checked against an independent digest.

#include <pubkey.h>
#include <crypto/ripemd160.h>
#include <crypto/sha3.h>
#include <uint256.h>

extern "C" {
#include "api.h"
}

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <span>
#include <vector>

namespace {
int g_fail = 0;
bool Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
    return ok;
}
} // namespace

int main()
{
    constexpr size_t PK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES; // 1312
    constexpr size_t SK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES; // 2560
    constexpr size_t SIGMAX = PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;      // 2420

    // Scheme metadata.
    Check("IsKnownScheme(ML_DSA_44)", IsKnownScheme(SigScheme::ML_DSA_44));
    Check("PublicKeySize == 1312", SchemePublicKeySize(SigScheme::ML_DSA_44) == PK);
    Check("SignatureSize == 2420", SchemeSignatureSize(SigScheme::ML_DSA_44) == SIGMAX);
    Check("SecretKeySize == 2560", SchemeSecretKeySize(SigScheme::ML_DSA_44) == SK);
    Check("SigOpCost == 1", SchemeSigOpCost(SigScheme::ML_DSA_44) == 1);

    // A real keypair.
    std::vector<unsigned char> pk(PK), sk(SK);
    Check("keypair", PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0);

    CPubKey key(SigScheme::ML_DSA_44, pk);
    Check("CPubKey IsValid (right length)", key.IsValid());
    CPubKey short_key(SigScheme::ML_DSA_44, std::span<const unsigned char>(pk.data(), PK - 1));
    Check("CPubKey !IsValid (wrong length)", !short_key.IsValid());

    // Sign a sighash-sized message (a uint256) and verify through CPubKey.
    uint256 msg;
    for (size_t i = 0; i < uint256::size(); ++i) msg.begin()[i] = (unsigned char)(i * 7 + 1);
    std::vector<unsigned char> sig(SIGMAX);
    size_t siglen = 0;
    Check("sign", PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig.data(), &siglen, msg.begin(), msg.size(), sk.data()) == 0);
    sig.resize(siglen);
    Check("siglen == 2420", siglen == SIGMAX);

    Check("Verify valid", key.Verify(msg, sig));

    // Tampered message.
    {
        uint256 bad = msg; bad.begin()[0] ^= 0x01;
        Check("Verify rejects tampered message", !key.Verify(bad, sig));
    }
    // Tampered signature.
    {
        std::vector<unsigned char> bad = sig; bad[10] ^= 0x80;
        Check("Verify rejects tampered signature", !key.Verify(msg, bad));
    }
    // Different key.
    {
        std::vector<unsigned char> pk2(PK), sk2(SK);
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk2.data(), sk2.data());
        CPubKey other(SigScheme::ML_DSA_44, pk2);
        Check("Verify rejects wrong key", !other.Verify(msg, sig));
    }
    // Invalid key never verifies.
    Check("invalid key !Verify", !short_key.Verify(msg, sig));

    // GetID = first 20 bytes of SHA3-256(scheme || pubkey), checked independently.
    {
        // The key is hashed as it stands: no scheme byte in front of it, since
        // the scheme is the length.
        unsigned char digest[SHA3_256::OUTPUT_SIZE];
        SHA3_256 h;
        h.Write(std::span<const unsigned char>(pk.data(), pk.size()));
        h.Finalize(digest);
        unsigned char expected[CRIPEMD160::OUTPUT_SIZE];
        CRIPEMD160().Write(digest, sizeof(digest)).Finalize(expected);
        CKeyID id = key.GetID();
        bool match = true;
        for (size_t i = 0; i < uint160::size(); ++i) if (id.begin()[i] != expected[i]) match = false;
        Check("GetID == RIPEMD160(SHA3-256(pubkey))", match);
    }

    // Length is the whole of the dispatch: no byte in front of the key says
    // which scheme it is, so the sizes must stay pairwise distinct and nothing
    // else may be accepted.
    {
        Check("33 -> secp256k1", SchemeFromPubKeySize(33) == SigScheme::SECP256K1);
        Check("897 -> Falcon-512", SchemeFromPubKeySize(897) == SigScheme::FALCON_512);
        Check("1312 -> ML-DSA-44", SchemeFromPubKeySize(1312) == SigScheme::ML_DSA_44);

        // The rule any future scheme has to obey.
        std::vector<size_t> sizes;
        for (const SigScheme sc : ALL_SIG_SCHEMES) sizes.push_back(SchemePublicKeySize(sc));
        std::sort(sizes.begin(), sizes.end());
        Check("no two schemes share a public-key length",
              std::adjacent_find(sizes.begin(), sizes.end()) == sizes.end());

        for (const size_t bad : {size_t{0}, size_t{1}, size_t{32}, size_t{34}, size_t{65},
                                 size_t{896}, size_t{898}, size_t{1311}, size_t{1313}, size_t{2048}}) {
            if (!Check("a length no scheme uses is refused", !SchemeFromPubKeySize(bad))) break;
        }

        // ...and CPubKey agrees, which is what keeps a wrong-length push off the
        // stack in the first place.
        Check("CPubKey rejects a 34-byte key (the old tagged secp length)",
              !CPubKey(std::vector<unsigned char>(34, 0x02)).IsValid());
        Check("CPubKey rejects a 1313-byte key (the old tagged ML-DSA length)",
              !CPubKey(std::vector<unsigned char>(1313, 0x01)).IsValid());
        Check("CPubKey accepts a 33-byte key", CPubKey(std::vector<unsigned char>(33, 0x02)).IsValid());
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
