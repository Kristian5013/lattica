// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the key layer Taproot rests on: XOnlyPubKey, KeyPair and BIP-340
// signing. Two things here are ours rather than Core's and are what the tests
// are mainly for.
//
// The tagged hash underneath BIP-341 is SHA3-256, and the tag is written once
// where BIP-340 writes it twice — so H_TapTweak is pinned below against a
// digest built by hand out of SHA3_256, not taken on trust from TaggedHash.
//
// And an x-only key is a secp256k1 x coordinate, which neither lattice scheme
// has. Handing one to XOnlyPubKey or to KeyPair must fail closed rather than
// reinterpret 32 bytes of a lattice secret as a scalar — which would succeed,
// silently, and sign under a key nobody holds.

#include <crypto/sha3.h>
#include <hash.h>
#include <key.h>
#include <pubkey.h>
#include <uint256.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
bool Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
    return ok;
}

//! H_TapTweak built from the primitive, with no help from TaggedHash: the
//! SHA3-256 of the tag, then the message, then one pass. If TaggedHash ever
//! grows a second tag copy back, or reverts to SHA-256, this stops matching.
uint256 TapTweakByHand(const XOnlyPubKey& key, const uint256* merkle_root)
{
    const std::string tag{"TapTweak"};
    uint256 taghash;
    SHA3_256().Write(std::span{reinterpret_cast<const unsigned char*>(tag.data()), tag.size()}).Finalize(taghash);

    SHA3_256 h;
    h.Write(taghash);
    h.Write(std::span{key.data(), key.size()});
    if (merkle_root) h.Write(*merkle_root);
    uint256 out;
    h.Finalize(out);
    return out;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};

    const CKey secp = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CKey mldsa = GenerateRandomKey(CKey::MLDSA44_SIZE);
    const CKey falcon = GenerateRandomKey(CKey::FALCON512_SIZE);
    // Bind before taking pointers: GetPubKey() returns by value.
    const CPubKey p_secp = secp.GetPubKey();
    const CPubKey p_mldsa = mldsa.GetPubKey();
    const CPubKey p_falcon = falcon.GetPubKey();

    // ---- XOnlyPubKey is the x coordinate, and only secp256k1 has one.
    const XOnlyPubKey xonly{p_secp};
    Check("XOnlyPubKey(secp) is bytes 1..33 of the compressed key",
          xonly.size() == 32 && std::equal(xonly.begin(), xonly.end(), p_secp.begin() + 1));
    Check("XOnlyPubKey(secp) is fully valid", xonly.IsFullyValid());
    Check("XOnlyPubKey(ML-DSA) is null", XOnlyPubKey{p_mldsa}.IsNull());
    Check("XOnlyPubKey(Falcon) is null", XOnlyPubKey{p_falcon}.IsNull());
    Check("a null XOnlyPubKey is not fully valid", !XOnlyPubKey{p_mldsa}.IsFullyValid());
    Check("NUMS_H is a point on the curve", XOnlyPubKey::NUMS_H.IsFullyValid());

    // ---- H_TapTweak, against a digest assembled from SHA3_256 by hand.
    const uint256 root = uint256::FromHex("1122334455667788990011223344556677889900112233445566778899001122").value();
    Check("H_TapTweak(P) is SHA3-256(SHA3-256(\"TapTweak\") || P)",
          xonly.ComputeTapTweakHash(nullptr) == TapTweakByHand(xonly, nullptr));
    Check("H_TapTweak(P || root) likewise",
          xonly.ComputeTapTweakHash(&root) == TapTweakByHand(xonly, &root));
    Check("the two tweaks differ",
          xonly.ComputeTapTweakHash(nullptr) != xonly.ComputeTapTweakHash(&root));

    // ---- The output key, and that CheckTapTweak accepts exactly it.
    const auto tweaked_no_root = xonly.CreateTapTweak(nullptr);
    const auto tweaked_root = xonly.CreateTapTweak(&root);
    Check("CreateTapTweak(nullptr) succeeds", tweaked_no_root.has_value());
    Check("CreateTapTweak(&root) succeeds", tweaked_root.has_value());
    if (!tweaked_no_root || !tweaked_root) { std::printf("FAILURES\n"); return 1; }
    Check("output key differs from the internal key", tweaked_root->first != xonly);
    Check("CheckTapTweak accepts the output key it produced",
          tweaked_root->first.CheckTapTweak(xonly, root, tweaked_root->second));
    Check("CheckTapTweak rejects the wrong parity",
          !tweaked_root->first.CheckTapTweak(xonly, root, !tweaked_root->second));
    Check("CheckTapTweak rejects the wrong merkle root",
          !tweaked_root->first.CheckTapTweak(xonly, uint256::ONE, tweaked_root->second));

    // ---- BIP-340 signing, in the three modes BIP-341 defines for merkle_root.
    const uint256 msg = uint256::FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").value();
    const uint256 aux = uint256::FromHex("f0e0d0c0b0a090807060504030201000f0e0d0c0b0a09080706050403020100f").value();
    {
        // nullptr: no tweak. This is the BIP-342 tapscript case.
        std::vector<unsigned char> sig(64);
        Check("SignSchnorr(merkle_root = nullptr) succeeds",
              secp.SignSchnorr(msg, sig, nullptr, aux));
        Check("...and verifies under the untweaked key", xonly.VerifySchnorr(msg, sig));
        Check("...and not under the tweaked one", !tweaked_no_root->first.VerifySchnorr(msg, sig));
        Check("...and not over another message", !xonly.VerifySchnorr(uint256::ONE, sig));
    }
    {
        // IsNull(): key path with no scripts, tweaked by H_TapTweak(P).
        std::vector<unsigned char> sig(64);
        const uint256 no_scripts;
        Check("SignSchnorr(merkle_root->IsNull()) succeeds",
              secp.SignSchnorr(msg, sig, &no_scripts, aux));
        Check("...and verifies under CreateTapTweak(nullptr)",
              tweaked_no_root->first.VerifySchnorr(msg, sig));
        Check("...and not under the internal key", !xonly.VerifySchnorr(msg, sig));
    }
    {
        // A real merkle root: key path with a script tree.
        std::vector<unsigned char> sig(64);
        Check("SignSchnorr(merkle_root = &root) succeeds",
              secp.SignSchnorr(msg, sig, &root, aux));
        Check("...and verifies under CreateTapTweak(&root)",
              tweaked_root->first.VerifySchnorr(msg, sig));
        Check("...and not under the no-root output key",
              !tweaked_no_root->first.VerifySchnorr(msg, sig));
    }
    {
        // aux is nonce entropy, so two signatures over one message differ and
        // both verify. Nothing may depend on a BIP-340 signature being unique.
        std::vector<unsigned char> a(64), b(64);
        secp.SignSchnorr(msg, a, nullptr, aux);
        secp.SignSchnorr(msg, b, nullptr, uint256::ONE);
        Check("different aux gives a different signature", a != b);
        Check("both verify", xonly.VerifySchnorr(msg, a) && xonly.VerifySchnorr(msg, b));
    }

    // ---- A lattice key has no scalar to sign with, and must not be read as one.
    {
        std::vector<unsigned char> sig(64);
        Check("ML-DSA key cannot Schnorr-sign", !mldsa.SignSchnorr(msg, sig, nullptr, aux));
        Check("Falcon key cannot Schnorr-sign", !falcon.SignSchnorr(msg, sig, nullptr, aux));
        Check("ML-DSA ComputeKeyPair is invalid", !mldsa.ComputeKeyPair(nullptr).IsValid());
        Check("Falcon ComputeKeyPair is invalid", !falcon.ComputeKeyPair(nullptr).IsValid());
        Check("secp ComputeKeyPair is valid", secp.ComputeKeyPair(nullptr).IsValid());
        Check("an invalid KeyPair signs nothing", !KeyPair{}.SignSchnorr(msg, sig, aux));
    }

    // ---- Recovering the candidate CPubKeys behind an x-only key.
    {
        const std::vector<CPubKey> keys = xonly.GetCPubKeys();
        const std::vector<CKeyID> ids = xonly.GetKeyIDs();
        Check("GetCPubKeys gives the 0x02 and 0x03 prefixes",
              keys.size() == 2 && keys[0].size() == CPubKey::SECP256K1_SIZE &&
              keys[0][0] == 0x02 && keys[1][0] == 0x03 &&
              std::equal(xonly.begin(), xonly.end(), keys[0].begin() + 1) &&
              std::equal(xonly.begin(), xonly.end(), keys[1].begin() + 1));
        Check("GetKeyIDs are those keys' Hash160s",
              ids.size() == 2 && ids[0] == keys[0].GetID() && ids[1] == keys[1].GetID());
        const CPubKey even = xonly.GetEvenCorrespondingCPubKey();
        Check("GetEvenCorrespondingCPubKey is the 0x02 one", even == keys[0]);
        // The real key was generated at random, so it is even half the time;
        // whichever it is, one of the two candidates must be it.
        Check("the true public key is among the candidates",
              p_secp == keys[0] || p_secp == keys[1]);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
