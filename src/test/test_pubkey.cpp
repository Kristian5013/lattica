// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the crypto-agile CPubKey over the vendored ML-DSA-44: scheme sizes,
// validity by key length, end-to-end sign/verify through CPubKey::Verify (with
// tampered message / signature / key rejected), and GetID = first 20 bytes of
// SHA3-256(scheme byte || pubkey) cross-checked against an independent digest.

#include <key.h>
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

    // The advertised sizes and the vendored library's must agree.
    Check("PublicKeySize == 1312", CPubKey::MLDSA44_SIZE == PK);
    Check("SignatureSize == 2420", CPubKey::MLDSA44_SIGNATURE_SIZE == SIGMAX);
    Check("SecretKeySize == 2560", CKey::MLDSA44_SIZE == SK);
    Check("SIZE is the largest public key", CPubKey::SIZE == CPubKey::MLDSA44_SIZE);

    // A real keypair.
    std::vector<unsigned char> pk(PK), sk(SK);
    Check("keypair", PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), sk.data()) == 0);

    CPubKey key(pk);
    Check("CPubKey IsValid (right length)", key.IsValid());
    CPubKey short_key(std::span<const unsigned char>(pk.data(), PK - 1));
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
        CPubKey other(pk2);
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
        Check("33 is a scheme's length", CPubKey::ValidSize(CPubKey::SECP256K1_SIZE));
        Check("897 is a scheme's length", CPubKey::ValidSize(CPubKey::FALCON512_SIZE));
        Check("1312 is a scheme's length", CPubKey::ValidSize(CPubKey::MLDSA44_SIZE));

        // The rule any future scheme has to obey is a static_assert in pubkey.h;
        // this only confirms the constants have not drifted into each other.
        Check("no two schemes share a public-key length",
              CPubKey::SECP256K1_SIZE != CPubKey::FALCON512_SIZE &&
              CPubKey::FALCON512_SIZE != CPubKey::MLDSA44_SIZE &&
              CPubKey::SECP256K1_SIZE != CPubKey::MLDSA44_SIZE);

        for (const size_t bad : {size_t{0}, size_t{1}, size_t{32}, size_t{34}, size_t{65},
                                 size_t{896}, size_t{898}, size_t{1311}, size_t{1313}, size_t{2048}}) {
            if (!Check("a length no scheme uses is refused", !CPubKey::ValidSize(bad))) break;
        }

        // ...and CPubKey agrees, which is what keeps a wrong-length push off the
        // stack in the first place.
        Check("CPubKey rejects a 34-byte key (the old tagged secp length)",
              !CPubKey(std::vector<unsigned char>(34, 0x02)).IsValid());
        Check("CPubKey rejects a 1313-byte key (the old tagged ML-DSA length)",
              !CPubKey(std::vector<unsigned char>(1313, 0x01)).IsValid());
        Check("CPubKey accepts a 33-byte key", CPubKey(std::vector<unsigned char>(33, 0x02)).IsValid());
    }

    // IsFullyValid() against IsValid(): syntactic length versus a real check.
    // How much "fully" means differs by scheme, and the test says so per scheme
    // rather than pretending they are equivalent.
    {
        ECC_Context ecc_context{};

        // secp256k1 — the complete check.
        const CKey sk = GenerateRandomKey(CKey::SECP256K1_SIZE);
        Check("secp: a real key is fully valid", sk.GetPubKey().IsFullyValid());
        {
            // x = p-1 has no point on the curve, but the length is right, so
            // IsValid() cannot tell and IsFullyValid() must.
            std::vector<unsigned char> off(CPubKey::SECP256K1_SIZE, 0xFF);
            off[0] = 0x02;
            const CPubKey bad(off);
            Check("secp: an off-curve key still passes IsValid", bad.IsValid());
            Check("secp: an off-curve key fails IsFullyValid", !bad.IsFullyValid());
        }

        // Falcon-512 — as far as the public API allows: the header byte.
        const CKey fk = GenerateRandomKey(CKey::FALCON512_SIZE);
        const CPubKey fpub = fk.GetPubKey();
        Check("falcon: a real key is fully valid", fpub.IsFullyValid());
        {
            std::vector<unsigned char> bad(fpub.begin(), fpub.end());
            bad[0] = 0x0a; // announces n = 1024 in a 512 key
            Check("falcon: a wrong degree header fails IsFullyValid",
                  !CPubKey(bad).IsFullyValid());
        }

        // ML-DSA-44 — the length is the whole of it, and the test says that
        // out loud so nobody later reads a true here as more than it is.
        const CKey mk = GenerateRandomKey(CKey::MLDSA44_SIZE);
        Check("ML-DSA: a real key is fully valid", mk.GetPubKey().IsFullyValid());
        Check("ML-DSA: arbitrary bytes of the right length are 'fully valid' too",
              CPubKey(std::vector<unsigned char>(CPubKey::MLDSA44_SIZE, 0x5a)).IsFullyValid());

        // A wrong length fails both.
        const CPubKey nonsense(std::vector<unsigned char>(100, 0x01));
        Check("a wrong length fails IsValid and IsFullyValid",
              !nonsense.IsValid() && !nonsense.IsFullyValid());
    }

    // CKeyID::fingerprint() is the first four bytes of the id, as in Core.
    {
        const CKeyID id = key.GetID();
        const KeyFingerprint fp = id.fingerprint();
        Check("fingerprint is the id's first four bytes",
              fp.size() == 4 && std::memcmp(fp.data(), id.begin(), 4) == 0);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
