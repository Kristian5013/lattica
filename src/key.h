// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Private key + signing, modeled on Bitcoin Core's key.h (CKey / CPrivKey).
//
// Lattica is crypto-agile: a CKey holds the secret of ONE scheme, tagged by the
// SigScheme byte that also leads its public key. Where Core's CKey is always a
// 32-byte secp256k1 scalar, ours is a std::variant over the schemes the chain
// knows — today secp256k1 and ML-DSA-44 (PQClean / FIPS 204), with Falcon-512's
// storage reserved so adding it does not move the layout.
//
// Two structural differences from Core are forced by the post-quantum half:
//
//   * A CKey carries its public key. secp256k1 derives one cheaply from the
//     secret; ML-DSA cannot — the secret packs t0 while the public key packs t1,
//     and recovering t1 means re-expanding A and recomputing t = A*s1 + s2, work
//     the PQClean API does not expose. Rather than branch on storage, the public
//     key is captured at generation time for every scheme.
//
//   * There is no compression flag. Core's public-key header byte (0x02/0x03 vs
//     0x04) IS the compression marker; here the leading byte is the scheme tag,
//     and CPubKey::GetLen() maps one tag to exactly one length. secp256k1 keys
//     are therefore compressed-only.
//
// Parts of Core's key.h with no analog here are not dropped silently — they are
// enumerated with the reason at the bottom of the CKey class, mirroring how
// pubkey.h documents the public-key types it omits.

#ifndef LATTICA_KEY_H
#define LATTICA_KEY_H

#include <pubkey.h>
#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <array>
#include <cstring>
#include <span>
#include <type_traits>
#include <variant>
#include <vector>

/**
 * CPrivKey is a serialized private key, with all parameters included.
 * For ML-DSA-44 this is simply the raw 2560-byte secret key; the matching
 * public key (which carries the scheme tag) is stored alongside it in a CKey.
 */
typedef std::vector<unsigned char, secure_allocator<unsigned char>> CPrivKey;

/** An encapsulated post-quantum (ML-DSA-44) private key. */
class CKey
{
public:
    /**
     * The key-generation seed size. It is deliberately NOT per-scheme: ML-DSA's
     * FIPS 204 xi and a secp256k1 scalar are both 32 bytes, which is what lets
     * one HD tree carry both.
     *
     * The per-scheme secret / public / signature sizes that used to live here as
     * CKey::SIZE, PUBLIC_KEY_SIZE and SIGNATURE_SIZE are gone: a CKey no longer
     * has one size. They are SchemeSecretKeySize(), SchemePublicKeySize() and
     * SchemeSignatureSize() in pubkey.h, keyed by the scheme tag.
     */
    static constexpr unsigned int SEED_SIZE = 32;

private:
    //! Per-scheme secret-key buffers. secp256k1 is a 32-byte scalar, ML-DSA-44 a
    //! 2560-byte packed secret. Falcon-512's 1281-byte NTRU secret is declared
    //! now, before the scheme itself exists, so that adding it later does not
    //! move this storage around.
    using SecpKey = std::array<unsigned char, 32>;
    using MLDSAKey = std::array<unsigned char, 2560>;
    using FalconKey = std::array<unsigned char, 1281>;
    using KeyVariant = std::variant<SecpKey, MLDSAKey, FalconKey>;

    //! secure_unique_ptr's deleter hands the storage straight back to the locked
    //! pool without running a destructor, which is sound only while every
    //! alternative is trivially destructible. A non-trivial one added here would
    //! leak without any diagnostic.
    static_assert(std::is_trivially_destructible_v<KeyVariant>,
                  "CKey's secure storage is freed without running a destructor");

    /**
     * The secret-key material. Null means invalid.
     *
     * The variant sits INSIDE the secure allocation rather than being a plain
     * member: secure_allocator draws from the locked pool and memory_cleanse()s
     * on release, whereas a bare std::variant member would live in ordinary
     * memory that can be paged to disk and is never wiped. The cost is that the
     * allocation is always the size of the largest alternative, so a 32-byte
     * secp256k1 scalar still occupies an ML-DSA-sized slot; locked-pool space is
     * not the scarce resource here.
     */
    secure_unique_ptr<KeyVariant> m_keydata;

    //! Which scheme m_keydata holds. Only meaningful while m_keydata is non-null.
    SigScheme m_scheme{SigScheme::ML_DSA_44};

    /**
     * The matching public key.
     *
     * secp256k1 can recompute this from the secret and ML-DSA cannot — the
     * secret packs t0 while the public key packs t1, and recovering t1 means
     * re-expanding A and recomputing t = A*s1 + s2. Rather than branching on
     * storage, a CKey carries the public key for every scheme; for secp256k1 it
     * is simply derived once at generation time.
     *
     * Note there is no compression flag. Core has one because its public-key
     * header byte (0x02/0x03 vs 0x04) IS the compression marker; here the
     * leading byte is the scheme tag, and CPubKey::GetLen() maps one scheme tag
     * to exactly one length. Two lengths for one tag would break ValidSize(), so
     * secp256k1 public keys are compressed-only (33 bytes).
     */
    CPubKey m_pubkey;

    //! Allocate (if needed) and select the alternative for `scheme`, zeroed.
    void MakeKeyData(SigScheme scheme);

    void ClearKeyData()
    {
        m_keydata.reset();
        m_pubkey = CPubKey();
    }

    //! Mutable view of the active secret bytes. Undefined unless m_keydata holds
    //! the alternative matching m_scheme.
    unsigned char* MutableData();

public:
    CKey() noexcept = default;
    CKey(CKey&&) noexcept = default;
    CKey& operator=(CKey&&) noexcept = default;

    CKey& operator=(const CKey& other)
    {
        if (other.m_keydata) {
            if (!m_keydata) m_keydata = make_secure_unique<KeyVariant>();
            *m_keydata = *other.m_keydata;
            m_scheme = other.m_scheme;
        } else {
            ClearKeyData();
            m_scheme = other.m_scheme;
        }
        m_pubkey = other.m_pubkey;
        return *this;
    }

    CKey(const CKey& other) { *this = other; }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return a.m_scheme == b.m_scheme && a.size() == b.size() &&
               (a.size() == 0 || std::memcmp(a.data(), b.data(), a.size()) == 0);
    }

    /**
     * Initialize from a secret and its matching public key. The scheme is taken
     * from the public key, and the secret must be exactly that scheme's secret
     * size. This replaces Core's `Set(pbegin, pend, fCompressed)`: the flag it
     * carried is meaningless here (see m_pubkey), and ML-DSA cannot recompute
     * the public key from the secret, so it must be supplied rather than derived.
     * The key is left invalid if the length is wrong or the pair does not match.
     */
    template <typename T>
    void Set(const T sk_begin, const T sk_end, const CPubKey& pubkey)
    {
        if (!pubkey.IsValid()) {
            ClearKeyData();
            return;
        }
        const SigScheme scheme{pubkey.GetScheme()};
        const size_t len{static_cast<size_t>(sk_end - sk_begin)};
        if (len != SchemeSecretKeySize(scheme) || !Check(scheme, UCharCast(&sk_begin[0]))) {
            ClearKeyData();
            return;
        }
        MakeKeyData(scheme);
        std::memcpy(MutableData(), (const unsigned char*)&sk_begin[0], len);
        m_pubkey = pubkey;
        if (!VerifyPubKey(pubkey)) ClearKeyData();
    }

    //! Simple read-only vector-like interface over the active secret-key bytes.
    unsigned int size() const;
    const unsigned char* data() const;
    const unsigned char* begin() const { return data(); }
    const unsigned char* end() const { return data() + size(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return !!m_keydata; }

    //! The signature scheme of this key.
    SigScheme GetScheme() const { return m_scheme; }

    /**
     * Whether a secret-key buffer is structurally acceptable for `scheme`.
     *
     * For secp256k1 this is a real predicate — the scalar must lie in [1, n-1],
     * and secp256k1_ec_seckey_verify decides it. ML-DSA has no cheap equivalent:
     * any buffer of the right length is structurally fine, and semantic validity
     * is established by VerifyPubKey's sign+verify round-trip.
     */
    static bool Check(SigScheme scheme, const unsigned char* vch);

    //! Generate a fresh random keypair for `scheme` (secret + matching public key).
    void MakeNewKey(SigScheme scheme = SigScheme::ML_DSA_44);

    //! Deterministically generate an ML-DSA-44 keypair from a SEED_SIZE-byte seed
    //! (FIPS 204 ML-DSA.KeyGen_internal(xi)). Backs hierarchical-deterministic
    //! derivation (see CExtKey); the key is left invalid if the seed is the wrong
    //! length. secp256k1's seed semantics differ (the seed IS the scalar, modulo
    //! the range check) and are handled when HD derivation grows a secp branch.
    bool MakeKeyFromSeed(std::span<const unsigned char> seed);

    //! Convert the private key to a serialized (raw secret-key byte) form.
    CPrivKey GetPrivKey() const;

    //! The public key matching this private key.
    CPubKey GetPubKey() const { return m_pubkey; }

    /**
     * Sign the 32-byte message `hash` (a sighash). The produced signature is the
     * bare scheme signature; callers building a witness append the one-byte
     * sighash type themselves.
     *
     * Core's `grind` / `test_case` parameters drive low-R grinding of a DER
     * ECDSA signature and are not reproduced: the DER encoding rules they serve
     * are exactly what this chain's script engine does not implement.
     */
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    /**
     * Verify that a candidate public key is the one matching this private key.
     *
     * secp256k1 derives the public key and compares it. ML-DSA cannot derive,
     * so it signs a random challenge and checks it verifies under the candidate.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load a private key and (re)build the CKey. The public key must be supplied
    //! because ML-DSA cannot recompute it from the secret alone.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);

    // --- Surface of Core's CKey not reproduced here ---------------------------
    //
    //   IsCompressed()                    secp256k1 keys are compressed-only in
    //                                     Lattica; see m_pubkey for why the flag
    //                                     cannot exist alongside a scheme tag.
    //   SignCompact()                     65-byte recoverable ECDSA for public-key
    //                                     recovery; the recovery module is not
    //                                     built (see cmake/secp256k1.cmake), and
    //                                     ML-DSA has no key recovery at all.
    //   SignSchnorr() / ComputeKeyPair()  BIP-340 / Taproot key-path; Lattica has
    //                                     no witness v1, and schnorrsig/extrakeys
    //                                     are not built.
    //   EllSwiftCreate() /                BIP-324 transport; this transport is
    //   ComputeBIP324ECDHSecret()         ML-KEM-768 (see v2cipher.h).

};

//! Produce a fresh random private key of `scheme` (with its matching public key).
CKey GenerateRandomKey(SigScheme scheme = SigScheme::ML_DSA_44) noexcept;

/**
 * Self-test the key primitives at startup, once per implemented scheme. This is
 * the analog of Core's ECC_InitSanityCheck(), widened because there is now more
 * than one scheme to get wrong.
 *
 * ML-DSA-44 gets a full generate/sign/verify round-trip. secp256k1 gets
 * generate + public-key derivation + a serialize/parse round-trip; it does not
 * sign yet (see CKey::Sign), so there is nothing further to check.
 */
bool KeyCryptoSanityCheck();

//! A BIP32-style chain code: 256 bits of derivation entropy carried alongside a key.
using ChainCode = uint256;

/**
 * A hierarchical-deterministic extended private key, the Lattica analog of
 * Core's CExtKey (BIP32). Because ML-DSA has no additive key tweak, the chainable
 * secret is NOT the (2560-byte) signing key but the 32-byte key-generation seed
 * that deterministically expands to it (FIPS 204 KeyGen_internal). A child is
 * derived by mixing the parent's secret node seed into a SHA3-512 PRF keyed by
 * the chain code, so derivation is HARDENED-ONLY: a parent extended *public* key
 * cannot derive child public keys (there is no key homomorphism for a lattice
 * scheme), which is why there is no Neuter() / CExtPubKey here. One master seed
 * still backs up and recovers the whole tree.
 */
struct CExtKey {
    unsigned char nDepth{0};
    unsigned char vchFingerprint[4]{0, 0, 0, 0};
    unsigned int nChild{0};
    ChainCode chaincode;
    uint256 nodeseed;  //!< the 32-byte ML-DSA key-generation seed (the chainable secret)
    CKey key;          //!< signing key, expanded from nodeseed

    //! Serialized size: depth(1) + fingerprint(4) + child(4) + chaincode(32) + nodeseed(32).
    static constexpr unsigned int SIZE = 1 + 4 + 4 + 32 + 32;

    friend bool operator==(const CExtKey& a, const CExtKey& b)
    {
        return a.nDepth == b.nDepth &&
               std::memcmp(a.vchFingerprint, b.vchFingerprint, sizeof(vchFingerprint)) == 0 &&
               a.nChild == b.nChild &&
               a.chaincode == b.chaincode &&
               a.nodeseed == b.nodeseed &&
               a.key == b.key;
    }

    //! Initialize as the master extended key from a wallet seed (any length).
    void SetSeed(std::span<const unsigned char> seed);


    //! Compute the master node from a seed and a personalization tag (shared by the two above).
    void SetSeedFromTag(std::span<const unsigned char> seed, const unsigned char* tag, size_t taglen);

    //! Derive the hardened child at index nChild. Returns false if this key is invalid.
    [[nodiscard]] bool Derive(CExtKey& out, unsigned int nChild) const;

    //! Serialize / deserialize the extended key to a fixed SIZE-byte form. Decode
    //! re-expands the signing key from the stored node seed.
    void Encode(unsigned char code[SIZE]) const;
    void Decode(const unsigned char code[SIZE]);

    // No Neuter() / CExtPubKey: child public keys cannot be derived from a parent
    // public key under ML-DSA (no key homomorphism). HD here is hardened-only.
};

#endif // LATTICA_KEY_H
