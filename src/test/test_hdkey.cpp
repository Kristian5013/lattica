// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for hardened-only hierarchical-deterministic key derivation (CExtKey)
// and the deterministic ML-DSA key generation it rests on (CKey::MakeKeyFromSeed
// -> PQClean crypto_sign_keypair_from_seed). Confirms: a seed reproduces the same
// master and child keys (recovery), distinct seeds/indices give distinct keys,
// derived keys sign and verify, an extended key round-trips through Encode/Decode,
// and the seeded keygen entry point added to the vendored ML-DSA is deterministic
// and produces working keys (so the sign.c refactor preserved correctness).

#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <hash.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

bool SignsAndVerifies(const CKey& k, const uint256& h)
{
    std::vector<unsigned char> sig;
    return k.Sign(h, sig) && k.GetPubKey().Verify(h, sig);
}
} // namespace

int main()
{
    std::vector<unsigned char> seed(32);
    for (unsigned i = 0; i < seed.size(); ++i) seed[i] = static_cast<unsigned char>(i);
    const uint256 h = Hash(std::span<const unsigned char>(seed.data(), seed.size()));

    // --- Seeded ML-DSA key generation (the sign.c refactor) ---
    {
        std::array<unsigned char, 32> ks;
        for (unsigned i = 0; i < ks.size(); ++i) ks[i] = static_cast<unsigned char>(0x40 + i);
        CKey k1, k2;
        Check("MakeKeyFromSeed succeeds", k1.MakeKeyFromSeed(CKey::MLDSA44_SIZE, ks));
        k2.MakeKeyFromSeed(CKey::MLDSA44_SIZE, ks);
        Check("seeded keygen is deterministic", k1 == k2 && k1.GetPubKey() == k2.GetPubKey());
        Check("seeded key signs and verifies", SignsAndVerifies(k1, h));
        CKey bad;
        Check("seeded keygen rejects wrong-length seed",
              !bad.MakeKeyFromSeed(CKey::MLDSA44_SIZE, std::span<const unsigned char>(ks.data(), 31)) && !bad.IsValid());
        // A different seed yields a different key.
        std::array<unsigned char, 32> ks2 = ks;
        ks2[0] ^= 0xff;
        CKey k3;
        k3.MakeKeyFromSeed(CKey::MLDSA44_SIZE, ks2);
        Check("different seed -> different key", !(k3 == k1) && k3.GetPubKey() != k1.GetPubKey());
    }

    // --- Master extended key: determinism + recovery ---
    CExtKey m1, m2;
    m1.SetSeed(seed);
    m2.SetSeed(seed);
    Check("master is deterministic from seed", m1 == m2);
    Check("master key + pubkey valid", m1.key.IsValid() && m1.key.GetPubKey().IsValid());
    Check("master depth 0 / child 0", m1.nDepth == 0 && m1.nChild == 0);
    Check("master key signs and verifies", SignsAndVerifies(m1.key, h));
    {
        std::vector<unsigned char> seed2 = seed;
        seed2[0] ^= 0xff;
        CExtKey m3;
        m3.SetSeed(seed2);
        Check("different seed -> different master", !(m3.key == m1.key));
    }

    // --- Hardened child derivation ---
    CExtKey c0a, c0b, c1;
    Check("derive child 0 (from m1)", m1.Derive(c0a, 0));
    Check("derive child 0 (from m2)", m2.Derive(c0b, 0));
    Check("child 0 is deterministic", c0a == c0b);
    Check("derive child 1", m1.Derive(c1, 1));
    Check("child0 != child1", !(c0a.key == c1.key));
    Check("child != master", !(c0a.key == m1.key));
    Check("child depth == 1", c0a.nDepth == 1 && c0a.nChild == 0);
    Check("child fingerprint == parent keyid[:4]",
          c0a.fingerprint == m1.key.GetPubKey().GetID().fingerprint());
    Check("child key signs and verifies", SignsAndVerifies(c0a.key, h));

    // A two-level path m/0/5 is reproducible and deepens correctly.
    {
        CExtKey t1, g1, t2, g2;
        Check("derive m/0", m1.Derive(t1, 0));
        Check("derive m/0/5", t1.Derive(g1, 5));
        m2.Derive(t2, 0);
        t2.Derive(g2, 5);
        Check("path m/0/5 is deterministic", g1 == g2);
        Check("grandchild depth == 2", g1.nDepth == 2 && g1.nChild == 5);
        Check("grandchild key signs and verifies", SignsAndVerifies(g1.key, h));
    }

    // --- Encode / Decode round-trip (serialized backup) ---
    {
        unsigned char code[CExtKey::SIZE];
        c0a.Encode(code);
        CExtKey dec;
        dec.Decode(code);
        Check("Encode/Decode round-trips", dec == c0a);
        Check("decoded key matches and signs", dec.key == c0a.key && SignsAndVerifies(dec.key, h));
    }

    // --- One seed, three schemes, three unrelated trees ---
    //
    // The scheme goes into the master node's preimage rather than sitting beside
    // it as a label. If it did not, the three trees would share every node seed
    // and a key in one would stand in a fixed relation to the key at the same
    // path in the others -- which is not a property anyone should have to reason
    // about, and not one a seed backup implies.
    {
        ECC_Context ecc_context{};
        const std::array<unsigned char, 32> seed{{'o', 'n', 'e', ' ', 's', 'e', 'e', 'd'}};

        CExtKey m_secp, m_falcon, m_mldsa;
        m_secp.SetSeed(seed, CKey::SECP256K1_SIZE);
        m_falcon.SetSeed(seed, CKey::FALCON512_SIZE);
        m_mldsa.SetSeed(seed, CKey::MLDSA44_SIZE);

        Check("each master carries its own scheme",
              m_secp.secret_size == CKey::SECP256K1_SIZE &&
              m_falcon.secret_size == CKey::FALCON512_SIZE &&
              m_mldsa.secret_size == CKey::MLDSA44_SIZE);
        Check("each master's key is of that scheme",
              m_secp.key.size() == CKey::SECP256K1_SIZE &&
              m_falcon.key.size() == CKey::FALCON512_SIZE &&
              m_mldsa.key.size() == CKey::MLDSA44_SIZE);
        Check("the three trees do not share a node seed",
              m_secp.nodeseed != m_falcon.nodeseed &&
              m_falcon.nodeseed != m_mldsa.nodeseed &&
              m_secp.nodeseed != m_mldsa.nodeseed);
        Check("nor a chain code",
              !(m_secp.chaincode == m_falcon.chaincode) &&
              !(m_falcon.chaincode == m_mldsa.chaincode));

        // A child is its parent's scheme, at every depth.
        CExtKey c_secp, c_falcon, g_falcon;
        Check("secp derives", m_secp.Derive(c_secp, 0));
        Check("falcon derives", m_falcon.Derive(c_falcon, 0));
        Check("...and again", c_falcon.Derive(g_falcon, 7));
        Check("a child keeps the scheme",
              c_secp.secret_size == CKey::SECP256K1_SIZE &&
              c_secp.key.size() == CKey::SECP256K1_SIZE &&
              g_falcon.secret_size == CKey::FALCON512_SIZE &&
              g_falcon.key.size() == CKey::FALCON512_SIZE);
        Check("derived keys of each scheme sign and verify",
              SignsAndVerifies(c_secp.key, h) && SignsAndVerifies(g_falcon.key, h));

        // The scheme survives a backup, and a corrupted one is refused rather
        // than expanded under whatever the field happens to hold.
        {
            unsigned char code[CExtKey::SIZE];
            c_secp.Encode(code);
            CExtKey dec;
            dec.Decode(code);
            Check("Encode/Decode round-trips a secp256k1 tree", dec == c_secp);

            code[CExtKey::SIZE - 1] ^= 0xff;
            CExtKey bad;
            bad.Decode(code);
            Check("a scheme no size names leaves the key invalid", !bad.key.IsValid());
        }
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
