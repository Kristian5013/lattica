// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for CKey (key.cpp), across both schemes it can hold.
//
// ML-DSA-44: fresh key generation yields a
// valid secret + matching public key; signing a sighash produces a signature
// that verifies under that public key (and only that one); a tampered signature
// or message is rejected; GetPrivKey/Load round-trips a key; and VerifyPubKey
// accepts the matching public key while rejecting a foreign one.

#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <hash.h>

#include <cstdio>
#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

//! Parse a hex string into bytes. Small enough not to pull in strencodings here.
std::vector<unsigned char> FromHex(const std::string& h)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<unsigned char>(nib(h[i]) * 16 + nib(h[i + 1])));
    }
    return out;
}
} // namespace

int main()
{
    // secp256k1 key generation and signing need the global signing context.
    ECC_Context ecc_context{};

    // A freshly generated key is valid and exposes a valid, well-formed pubkey.
    CKey key = GenerateRandomKey();
    Check("generated key is valid", key.IsValid());
    Check("key scheme is ML-DSA-44", key.size() == CKey::MLDSA44_SIZE);
    Check("secret key size == 2560", key.size() == CKey::MLDSA44_SIZE);

    CPubKey pub = key.GetPubKey();
    Check("public key is valid", pub.IsValid());
    Check("public key size == 1312", pub.size() == CPubKey::MLDSA44_SIZE);
    Check("scheme is read off the length", pub.size() == CPubKey::MLDSA44_SIZE);

    // Sign a sighash and verify it under the public key.
    const uint256 hash = Hash(std::span<const unsigned char>(pub.data(), pub.size()));
    std::vector<unsigned char> sig;
    bool signed_ok = key.Sign(hash, sig);
    Check("Sign succeeds", signed_ok);
    Check("signature size == 2420", sig.size() == CPubKey::MLDSA44_SIGNATURE_SIZE);
    Check("signature verifies under own pubkey", pub.Verify(hash, sig));

    // A different message must not verify against that signature.
    {
        uint256 other = hash;
        other.begin()[0] ^= 0x01;
        Check("signature does not verify over a different hash", !pub.Verify(other, sig));
    }

    // A tampered signature is rejected.
    {
        std::vector<unsigned char> bad = sig;
        bad[bad.size() / 2] ^= 0xff;
        Check("tampered signature is rejected", !pub.Verify(hash, bad));
    }

    // Signing is the hedged (randomized) ML-DSA variant: two signatures over the
    // same message differ, yet both verify.
    {
        std::vector<unsigned char> sig2;
        bool ok2 = key.Sign(hash, sig2);
        Check("second Sign succeeds", ok2);
        Check("two signatures over same msg differ (hedged)", sig2 != sig);
        Check("second signature also verifies", pub.Verify(hash, sig2));
    }

    // A second, independent key has a different pubkey, and cross-verification
    // fails both ways.
    CKey key2 = GenerateRandomKey();
    CPubKey pub2 = key2.GetPubKey();
    Check("two fresh keys have different pubkeys", pub2 != pub);
    Check("key1 signature does not verify under key2's pubkey", !pub2.Verify(hash, sig));
    {
        std::vector<unsigned char> sig2;
        key2.Sign(hash, sig2);
        Check("key2 signature does not verify under key1's pubkey", !pub.Verify(hash, sig2));
    }

    // GetPrivKey / Load round-trips: the rebuilt key equals the original, exposes
    // the same pubkey, and still produces verifiable signatures.
    {
        CPrivKey priv = key.GetPrivKey();
        Check("serialized private key size == 2560", priv.size() == CKey::MLDSA44_SIZE);
        CKey loaded;
        bool load_ok = loaded.Load(priv, pub, /*fSkipCheck=*/false);
        Check("Load (with check) succeeds", load_ok);
        Check("loaded key equals original", loaded == key);
        Check("loaded key exposes same pubkey", loaded.GetPubKey() == pub);
        std::vector<unsigned char> sig3;
        Check("loaded key signs", loaded.Sign(hash, sig3));
        Check("loaded key's signature verifies", pub.Verify(hash, sig3));
    }

    // Load with a mismatched pubkey is rejected by the round-trip check.
    {
        CPrivKey priv = key.GetPrivKey();
        CKey loaded;
        Check("Load with foreign pubkey is rejected", !loaded.Load(priv, pub2, /*fSkipCheck=*/false));
    }

    // VerifyPubKey: accepts the matching key, rejects a foreign one.
    Check("VerifyPubKey accepts own pubkey", key.VerifyPubKey(pub));
    Check("VerifyPubKey rejects foreign pubkey", !key.VerifyPubKey(pub2));

    // Set() rebuilds a key from raw secret bytes + the matching public key, and
    // rejects a mismatched public key (leaving the key invalid).
    {
        CPrivKey priv = key.GetPrivKey();
        CKey via_set;
        via_set.Set(priv.begin(), priv.end(), pub);
        Check("Set(secret, matching pubkey) yields a valid key", via_set.IsValid() && via_set == key);
        CKey via_set_bad;
        via_set_bad.Set(priv.begin(), priv.end(), pub2);
        Check("Set(secret, foreign pubkey) is rejected", !via_set_bad.IsValid());
    }

    // Load with fSkipCheck=true trusts the caller and skips the round-trip.
    {
        CPrivKey priv = key.GetPrivKey();
        CKey fast;
        Check("Load(fSkipCheck=true) succeeds", fast.Load(priv, pub, /*fSkipCheck=*/true));
        Check("fSkipCheck-loaded key equals original", fast == key);
        std::vector<unsigned char> s;
        Check("fSkipCheck-loaded key signs verifiably", fast.Sign(hash, s) && pub.Verify(hash, s));
    }

    // ---------------------------------------------------------------- secp256k1
    //
    // Only key generation and public-key derivation are implemented so far;
    // signing is not (see CKey::Sign), and the checks below say so explicitly so
    // that the day it lands, this test fails and gets updated rather than
    // silently passing.
    {
        CKey k = GenerateRandomKey(CKey::SECP256K1_SIZE);
        Check("secp: generated key is valid", k.IsValid());
        Check("secp: scheme is SECP256K1", k.size() == CKey::SECP256K1_SIZE);
        Check("secp: secret is 32 bytes", k.size() == 32);

        const CPubKey pub = k.GetPubKey();
        Check("secp: pubkey is valid", pub.IsValid());
        Check("secp: pubkey is 33 bytes, no tag in front", pub.size() == 33);
        Check("secp: 33 bytes means secp256k1", pub.size() == CPubKey::SECP256K1_SIZE);
        Check("secp: key is compressed SEC (0x02/0x03)",
              pub[0] == 0x02 || pub[0] == 0x03);

        Check("secp: VerifyPubKey accepts its own", k.VerifyPubKey(pub));

        CKey other = GenerateRandomKey(CKey::SECP256K1_SIZE);
        Check("secp: two fresh keys differ", !(other == k) && other.GetPubKey() != pub);
        Check("secp: VerifyPubKey rejects a foreign key", !k.VerifyPubKey(other.GetPubKey()));

        // Cross-scheme confusion must not pass in either direction.
        const CKey mldsa = GenerateRandomKey(CKey::MLDSA44_SIZE);
        Check("secp: VerifyPubKey rejects an ML-DSA pubkey", !k.VerifyPubKey(mldsa.GetPubKey()));
        Check("ML-DSA: VerifyPubKey rejects a secp pubkey", !mldsa.VerifyPubKey(pub));

        // --- Signing ---
        const uint256 msg = Hash(std::vector<unsigned char>{'s', 'e', 'c', 'p'});
        std::vector<unsigned char> sig;
        Check("secp: Sign succeeds", k.Sign(msg, sig));
        Check("secp: signature is DER within its bound",
              sig.size() <= CPubKey::SECP256K1_SIGNATURE_SIZE && sig.size() > 8 && sig[0] == 0x30);
        Check("secp: signing grinds for low R, so the DER stays under 71 bytes",
              sig.size() <= 71);
        Check("secp: signature verifies", pub.Verify(msg, sig));

        // RFC6979: the nonce comes from the key and the message, so a second
        // signature over the same input is byte-identical. No entropy involved.
        std::vector<unsigned char> sig2;
        k.Sign(msg, sig2);
        Check("secp: signing is deterministic", sig2 == sig);

        std::vector<unsigned char> sig_other;
        k.Sign(Hash(std::vector<unsigned char>{'o', 't', 'h', 'e', 'r'}), sig_other);
        Check("secp: a different message gives a different signature", sig_other != sig);

        Check("secp: a foreign key does not verify it", !other.GetPubKey().Verify(msg, sig));
        Check("secp: the wrong message does not verify",
              !pub.Verify(Hash(std::vector<unsigned char>{'x'}), sig));
        {
            std::vector<unsigned char> bad = sig;
            bad[10] ^= 0x01;
            Check("secp: a tampered signature is rejected", !pub.Verify(msg, bad));
        }
        {
            std::vector<unsigned char> truncated(sig.begin(), sig.end() - 1);
            Check("secp: a truncated signature is rejected", !pub.Verify(msg, truncated));
            // Trailing junk after the SEQUENCE is what the lax parser exists to
            // tolerate, exactly as in Bitcoin. Rejecting it is BIP66's job, and
            // BIP66 lives in the script interpreter behind SCRIPT_VERIFY_DERSIG.
            std::vector<unsigned char> padded = sig;
            padded.push_back(0x00);
            Check("secp: trailing junk still verifies, as the lax parser allows",
                  pub.Verify(msg, padded));
        }

        // Low-S is BIP62 rule 5, which Bitcoin enforces at script level rather
        // than inside verification: CPubKey::Verify normalizes and accepts, and
        // CheckLowS is what reports the form. Signing always produces low-S.
        Check("secp: a fresh signature is low-S", CPubKey::CheckLowS(sig));
        Check("secp: CheckLowS refuses a blob that is not a signature",
              !CPubKey::CheckLowS(std::vector<unsigned char>{0x01, 0x02, 0x03}));

        // An ML-DSA public key must not accept a secp signature, or vice versa.
        {
            std::vector<unsigned char> mldsa_sig;
            mldsa.Sign(msg, mldsa_sig);
            Check("secp pubkey rejects an ML-DSA signature", !pub.Verify(msg, mldsa_sig));
            Check("ML-DSA pubkey rejects a secp signature",
                  !mldsa.GetPubKey().Verify(msg, sig));
        }

        // GetPrivKey / Load round-trip.
        const CPrivKey priv = k.GetPrivKey();
        Check("secp: serialized secret is DER, as in Bitcoin",
              priv.size() == CKey::DER_COMPRESSED_SIZE);
        CKey loaded;
        Check("secp: Load round-trips", loaded.Load(priv, pub, /*fSkipCheck=*/false));
        Check("secp: loaded key equals original", loaded == k);
    }

    // Independent check of the derivation itself: the scalar 1 must map to the
    // curve's generator, and 2 to 2G. These are fixed constants of secp256k1, so
    // this validates CKey's whole derive-and-compare path against something that
    // does not come from the same code.
    {
        struct { const char* scalar; const char* pubkey; const char* name; } kats[] = {
            {"0000000000000000000000000000000000000000000000000000000000000001",
             "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "1 -> G"},
            {"0000000000000000000000000000000000000000000000000000000000000002",
             "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", "2 -> 2G"},
        };
        for (const auto& kat : kats) {
            const std::vector<unsigned char> sk = FromHex(kat.scalar);
            const std::vector<unsigned char> raw = FromHex(kat.pubkey);
            const CPubKey expected(raw);
            CKey k;
            // Load() with fSkipCheck=false goes through Set(), which derives the
            // public key and compares; success means the derivation produced
            // exactly these bytes.
            // The scalar is loaded as a seed: CPrivKey is DER for secp256k1, as
            // in Bitcoin, and a KAT names the scalar itself.
            const bool ok = k.MakeKeyFromSeed(CKey::SECP256K1_SIZE, sk);
            Check((std::string("secp KAT: ") + kat.name).c_str(), ok && k.GetPubKey() == expected);
        }

        // ...and a wrong pairing must be refused.
        const std::vector<unsigned char> sk = FromHex("0000000000000000000000000000000000000000000000000000000000000001");
        const std::vector<unsigned char> wrong = FromHex("02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
        CKey k;
        Check("secp: Load rejects a mismatched pubkey",
              !k.Load(CPrivKey(sk.begin(), sk.end()), CPubKey(wrong), false));

        // Out-of-range scalars are rejected: zero, and n itself.
        for (const char* bad : {"0000000000000000000000000000000000000000000000000000000000000000",
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"}) {
            const std::vector<unsigned char> b = FromHex(bad);
            CKey bk;
            const CPubKey any(FromHex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"));
            Check("secp: out-of-range scalar refused",
                  !bk.Load(CPrivKey(b.begin(), b.end()), any, false));
        }
    }

    // ---------------------------------------------------------------- Falcon-512
    {
        CKey k = GenerateRandomKey(CKey::FALCON512_SIZE);
        Check("falcon: generated key is valid", k.IsValid());
        Check("falcon: scheme is FALCON_512", k.size() == CKey::FALCON512_SIZE);
        Check("falcon: secret is 1281 bytes", k.size() == 1281);

        const CPubKey pub = k.GetPubKey();
        Check("falcon: pubkey is valid", pub.IsValid());
        Check("falcon: pubkey is 897 bytes, no tag in front", pub.size() == 897);
        Check("falcon: 897 bytes means Falcon-512", pub.size() == CPubKey::FALCON512_SIZE);
        // A Falcon public key is a packed polynomial whose first byte encodes
        // the degree; 0x09 is n = 512.
        Check("falcon: key says n = 512", pub[0] == 0x09);
        Check("falcon: VerifyPubKey accepts its own", k.VerifyPubKey(pub));

        const uint256 msg = Hash(std::vector<unsigned char>{'f', 'a', 'l'});
        std::vector<unsigned char> sig;
        Check("falcon: Sign succeeds", k.Sign(msg, sig));
        Check("falcon: signature is exactly 666 bytes",
              sig.size() == CPubKey::FALCON512_SIGNATURE_SIZE);
        Check("falcon: signature verifies", pub.Verify(msg, sig));

        // Falcon salts every signature, unlike the other two schemes here.
        std::vector<unsigned char> sig2;
        k.Sign(msg, sig2);
        Check("falcon: signing is randomized", sig2 != sig && pub.Verify(msg, sig2));

        {
            std::vector<unsigned char> bad = sig;
            bad[100] ^= 0x01;
            Check("falcon: a tampered signature is rejected", !pub.Verify(msg, bad));
        }
        Check("falcon: the wrong message does not verify",
              !pub.Verify(Hash(std::vector<unsigned char>{'x'}), sig));

        CKey other = GenerateRandomKey(CKey::FALCON512_SIZE);
        Check("falcon: two fresh keys differ", !(other == k) && other.GetPubKey() != pub);
        Check("falcon: a foreign key does not verify it", !other.GetPubKey().Verify(msg, sig));

        // Cross-scheme confusion, in every direction that exists.
        const CKey mldsa_k = GenerateRandomKey(CKey::MLDSA44_SIZE);
        const CKey secp_k = GenerateRandomKey(CKey::SECP256K1_SIZE);
        Check("falcon: VerifyPubKey rejects an ML-DSA pubkey", !k.VerifyPubKey(mldsa_k.GetPubKey()));
        Check("falcon: VerifyPubKey rejects a secp pubkey", !k.VerifyPubKey(secp_k.GetPubKey()));
        {
            std::vector<unsigned char> secp_sig;
            secp_k.Sign(msg, secp_sig);
            Check("falcon pubkey rejects a secp signature", !pub.Verify(msg, secp_sig));
            Check("secp pubkey rejects a falcon signature",
                  !secp_k.GetPubKey().Verify(msg, sig));
        }

        const CPrivKey priv = k.GetPrivKey();
        Check("falcon: serialized secret is 1281 bytes", priv.size() == 1281);
        CKey loaded;
        Check("falcon: Load round-trips", loaded.Load(priv, pub, /*fSkipCheck=*/false));
        Check("falcon: loaded key equals original", loaded == k);
    }

    // Seeded key generation, per scheme. The lattice schemes share one entropy
    // seam in randombytes; secp256k1 takes the seed as the scalar directly.
    {
        std::array<unsigned char, 32> seed;
        for (unsigned i = 0; i < seed.size(); ++i) seed[i] = static_cast<unsigned char>(0x20 + i);

        for (const unsigned int secret_size : {CKey::SECP256K1_SIZE, CKey::FALCON512_SIZE, CKey::MLDSA44_SIZE}) {
            CKey a, b;
            Check("seeded keygen succeeds", a.MakeKeyFromSeed(secret_size, seed));
            b.MakeKeyFromSeed(secret_size, seed);
            Check("seeded keygen is deterministic", a == b && a.GetPubKey() == b.GetPubKey());
            Check("seeded keygen rejects a 31-byte seed",
                  !CKey{}.MakeKeyFromSeed(secret_size, std::span<const unsigned char>(seed.data(), 31)));
        }

        // The same seed must not produce related keys across schemes.
        CKey f, m;
        f.MakeKeyFromSeed(CKey::FALCON512_SIZE, seed);
        m.MakeKeyFromSeed(CKey::MLDSA44_SIZE, seed);
        Check("one seed gives unrelated keys in different schemes",
              f.GetPubKey() != m.GetPubKey());

        // The seam must be OFF again afterwards. If a deterministic seed leaked
        // past keygen, Falcon's per-signature salt would be fixed — so a
        // seeded Falcon key must still sign randomly.
        const uint256 msg = Hash(std::vector<unsigned char>{'s', 'e', 'a', 'm'});
        std::vector<unsigned char> s1, s2;
        f.Sign(msg, s1);
        f.Sign(msg, s2);
        Check("the deterministic seam is cleared after keygen",
              s1 != s2 && f.GetPubKey().Verify(msg, s1) && f.GetPubKey().Verify(msg, s2));
    }

    // Startup self-test of the signature primitive.
    Check("KeyCryptoSanityCheck passes", KeyCryptoSanityCheck());

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
