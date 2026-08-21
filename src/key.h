// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_KEY_H
#define LATTICA_KEY_H

#include <pubkey.h>
#include <script/keyorigin.h>
#include <serialize.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

struct secp256k1_context_struct;
typedef struct secp256k1_context_struct secp256k1_context;

/**
 * CPrivKey is a serialized private key, with all parameters included
 * (DER_SIZE bytes) for secp256k1, and the raw secret for either lattice scheme,
 * which has no DER encoding to be serialized into.
 */
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

class KeyPair;

/** An encapsulated private key. */
class CKey
{
public:
    /**
     * secp256k1, Falcon-512, ML-DSA-44. As in CPubKey nothing tags the scheme:
     * the length of the secret names it, and the three lengths are pairwise
     * distinct so that it can. SIZE is the largest, which is what the secure
     * allocation is sized to.
     */
    static constexpr unsigned int SECP256K1_SIZE{32};
    static constexpr unsigned int FALCON512_SIZE{1281};
    static constexpr unsigned int MLDSA44_SIZE{2560};
    static constexpr unsigned int SIZE{MLDSA44_SIZE};

    /**
     * The DER lengths of a serialized secp256k1 private key, which is what
     * Core's CKey::SIZE{279} and COMPRESSED_SIZE{214} measure. SIZE above
     * measures the secret itself, so these carry their own names.
     */
    static constexpr unsigned int DER_SIZE{279};
    static constexpr unsigned int DER_COMPRESSED_SIZE{214};

    /**
     * The key-generation seed size, deliberately not per-scheme: ML-DSA's FIPS
     * 204 xi, Falcon's keygen seed and a secp256k1 scalar are all 32 bytes,
     * which is what lets one hierarchical tree carry every scheme.
     */
    static constexpr unsigned int SEED_SIZE{32};

    static_assert(
        SIZE >= SECP256K1_SIZE && SIZE >= FALCON512_SIZE,
        "SIZE is not the largest secret");
    static_assert(
        DER_SIZE >= DER_COMPRESSED_SIZE,
        "DER_COMPRESSED_SIZE is larger than DER_SIZE");
    static_assert(
        SECP256K1_SIZE != FALCON512_SIZE && FALCON512_SIZE != MLDSA44_SIZE && SECP256K1_SIZE != MLDSA44_SIZE,
        "secret sizes must be pairwise distinct: the length is what names the scheme");

    //! Whether this length is one an implemented scheme uses.
    static bool ValidSize(size_t len)
    {
        return len == SECP256K1_SIZE || len == FALCON512_SIZE || len == MLDSA44_SIZE;
    }

private:
    /** Internal data containers for private key material, one per scheme. */
    using SecpKey = std::array<unsigned char, SECP256K1_SIZE>;
    using FalconKey = std::array<unsigned char, FALCON512_SIZE>;
    using MLDSAKey = std::array<unsigned char, MLDSA44_SIZE>;
    using KeyVariant = std::variant<SecpKey, FalconKey, MLDSAKey>;

    //! secure_unique_ptr's deleter returns the storage to the locked pool without
    //! running a destructor, which is sound only while every alternative is
    //! trivially destructible. A non-trivial one added here would leak silently.
    static_assert(std::is_trivially_destructible_v<KeyVariant>,
                  "CKey's secure storage is freed without running a destructor");

    //! The actual byte data. nullptr for invalid keys. Core keeps a fixed 32-byte
    //! array; here the variant is what makes one class hold three schemes, and it
    //! lives inside the secure allocation rather than beside it so that the locked
    //! pool cleanses it on release.
    secure_unique_ptr<KeyVariant> m_keydata;

    //! The matching public key. Core recomputes it from the secret and stores
    //! nothing; only secp256k1 can do that here. ML-DSA cannot at all — its
    //! secret packs t0 while the public key packs t1 — and Falcon's is
    //! recomputable in principle but PQClean exposes that only as an internal
    //! symbol. So every scheme captures the public key at generation time.
    CPubKey m_pubkey;

    //! Check whether the buffer pointed to by vch is valid keydata for that size.
    bool static Check(unsigned int secret_size, const unsigned char* vch);

    //! Allocate if needed, then select and zero the alternative for a secret of
    //! `secret_size`. Leaves the key invalid if no scheme uses that size.
    void MakeKeyData(unsigned int secret_size);

    void ClearKeyData()
    {
        m_keydata.reset();
        m_pubkey = CPubKey();
    }

    //! Mutable view of the active secret bytes. Requires m_keydata.
    unsigned char* MutableData();

public:
    CKey() noexcept = default;
    CKey(CKey&&) noexcept = default;
    CKey& operator=(CKey&&) noexcept = default;

    CKey& operator=(const CKey& other)
    {
        if (this != &other) {
            if (other.m_keydata) {
                if (!m_keydata) m_keydata = make_secure_unique<KeyVariant>();
                *m_keydata = *other.m_keydata;
            } else {
                ClearKeyData();
            }
            m_pubkey = other.m_pubkey;
        }
        return *this;
    }

    CKey(const CKey& other) { *this = other; }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return a.size() == b.size() &&
            (a.size() == 0 || memcmp(a.data(), b.data(), a.size()) == 0);
    }

    /**
     * Initialize using begin and end iterators to byte data.
     *
     * This is Core's Set(pbegin, pend, fCompressedIn) with the compression flag
     * replaced by the public key. The flag has nothing to say here, and ML-DSA
     * cannot recompute a public key from its secret, so one has to be supplied:
     * it is also what names the scheme, and the secret must be exactly that
     * scheme's length.
     */
    template <typename T>
    void Set(const T sk_begin, const T sk_end, const CPubKey& pubkey)
    {
        if (!pubkey.IsValid()) {
            ClearKeyData();
            return;
        }
        const size_t len{static_cast<size_t>(sk_end - sk_begin)};
        if (!ValidSize(len) || len != SecretSizeForPubKey(pubkey.size()) ||
            !Check(static_cast<unsigned int>(len), UCharCast(&sk_begin[0]))) {
            ClearKeyData();
            return;
        }
        MakeKeyData(static_cast<unsigned int>(len));
        if (!m_keydata) return;
        memcpy(MutableData(), (const unsigned char*)&sk_begin[0], len);
        m_pubkey = pubkey;
        if (!VerifyPubKey(pubkey)) ClearKeyData();
    }

    //! Simple read-only vector-like interface. Core hands back std::byte; these
    //! are unsigned char, which is what every scheme's library takes anyway.
    unsigned int size() const;
    const unsigned char* data() const;
    const unsigned char* begin() const { return data(); }
    const unsigned char* end() const { return data() + size(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return !!m_keydata; }

    //! Check whether the public key corresponding to this private key is (to be)
    //! compressed. True exactly for secp256k1: one scheme cannot have two lengths
    //! here, so a secp256k1 key is compressed and nothing else.
    bool IsCompressed() const { return size() == SECP256K1_SIZE; }

    //! The secret size a scheme uses given its public key size, or 0 if that
    //! public key size belongs to no scheme. The one place the two size
    //! namespaces are bridged.
    static unsigned int SecretSizeForPubKey(unsigned int pubkey_size);

    //! Generate a new private key using a cryptographic PRNG. secp256k1 and
    //! Falcon-512 need a signing context; see ECC_Context.
    void MakeNewKey(unsigned int secret_size = MLDSA44_SIZE);

    /**
     * Deterministically generate a keypair for that scheme from a SEED_SIZE-byte
     * seed. This backs hierarchical derivation; it returns false, leaving the key
     * invalid, if the seed is the wrong length or unusable for the scheme.
     *
     * The seed means something different per scheme. For ML-DSA it is the FIPS
     * 204 KeyGen_internal(xi) seed and for Falcon it drives PQClean's keygen,
     * both through the entropy seam in randombytes.h, and every seed is usable.
     * For secp256k1 the seed IS the scalar, so one outside [1, n-1] has no key
     * and is rejected — with probability about 2^-128, which the caller must
     * still handle.
     */
    bool MakeKeyFromSeed(unsigned int secret_size, std::span<const unsigned char> seed);

    /**
     * Convert the private key to a CPrivKey (serialized OpenSSL private key data)
     * for secp256k1, or to the raw secret for either lattice scheme.
     * This is expensive.
     */
    CPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * Free here rather than expensive: it is stored, for the reason m_pubkey gives.
     */
    CPubKey GetPubKey() const;

    /**
     * Create a DER-serialized signature for secp256k1, or the scheme's own
     * fixed-length signature for Falcon-512 and ML-DSA-44.
     * The test_case parameter tweaks the deterministic nonce, and applies to
     * secp256k1 alone.
     *
     * Determinism differs by scheme and callers must not assume it: secp256k1
     * uses RFC6979 and ML-DSA-44 is hedged-but-fixed here, so both reproduce,
     * while Falcon salts every signature and does not.
     */
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig, bool grind = true, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     *
     * secp256k1 only: neither lattice scheme recovers a key from a signature.
     */
    bool SignCompact(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    /**
     * Create a BIP-340 Schnorr signature, for the xonly-pubkey corresponding to *this,
     * optionally tweaked by *merkle_root. Additional nonce entropy is provided through
     * aux.
     *
     * merkle_root is used to optionally perform tweaking of the private key, as specified
     * in BIP341:
     * - If merkle_root == nullptr: no tweaking is done, sign with key directly (this is
     *                              used for signatures in BIP342 script).
     * - If merkle_root->IsNull():  sign with key + H_TapTweak(pubkey) (this is used for
     *                              key path spending when no scripts are present).
     * - Otherwise:                 sign with key + H_TapTweak(pubkey || *merkle_root)
     *                              (this is used for key path spending, with specific
     *                              Merkle root of the script tree).
     *
     * secp256k1 only: a BIP-340 signature is a curve point and a scalar, and a key
     * of either lattice scheme returns false rather than being reinterpreted as one.
     */
    bool SignSchnorr(const uint256& hash, std::span<unsigned char> sig, const uint256* merkle_root, const uint256& aux) const;

    //! Derive BIP32 child key. secp256k1 only, being an additive scalar tweak.
    [[nodiscard]] bool Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     *
     * secp256k1 does regenerate and compare, being able to. Neither lattice
     * scheme can, for the reason m_pubkey exists, so both sign a random challenge
     * and check that it verifies under the candidate.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load private key and check that public key matches. The public key must be
    //! supplied: ML-DSA cannot recompute it from the secret alone.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);

    /** Compute a KeyPair
     *
     *  Wraps a `secp256k1_keypair` type.
     *
     *  `merkle_root` is used to optionally perform tweaking of
     *  the internal key, as specified in BIP341:
     *
     *  - If merkle_root == nullptr: no tweaking is done, use the internal key directly (this is
     *                               used for signatures in BIP342 script).
     *  - If merkle_root->IsNull():  tweak the internal key with H_TapTweak(pubkey) (this is used for
     *                               key path spending when no scripts are present).
     *  - Otherwise:                 tweak the internal key with H_TapTweak(pubkey || *merkle_root)
     *                               (this is used for key path spending with the
     *                               Merkle root of the script tree).
     *
     *  Invalid for a key of either lattice scheme.
     */
    KeyPair ComputeKeyPair(const uint256* merkle_root) const;

    // Core's EllSwiftCreate() and ComputeBIP324ECDHSecret() belong to the BIP-324
    // transport; this transport is ML-KEM-768, see v2cipher.h, and ECDH_SECRET_SIZE
    // and ECDHSecret go with them.
};

//! Produce a fresh random private key of that scheme, with its matching public key.
CKey GenerateRandomKey(unsigned int secret_size = CKey::MLDSA44_SIZE) noexcept;

struct CExtKey {
    unsigned char nDepth{0};
    KeyFingerprint fingerprint{};
    unsigned int nChild{0};
    ChainCode chaincode;
    //! The 32-byte key-generation seed a child is derived from, and the signing
    //! key expanded out of it. Core chains the secret itself, which only a scalar
    //! allows; every scheme here expands from the seed instead.
    uint256 nodeseed;
    //! The secret size of the scheme this tree carries, which is what names it.
    //! One tree is one scheme throughout: a child expands from its parent's seed
    //! under the same scheme, and the seed alone would not say which.
    unsigned int secret_size{CKey::MLDSA44_SIZE};
    CKey key;

    //! Serialized size: depth(1) + fingerprint(4) + child(4) + chaincode(32)
    //! + nodeseed(32) + secret size(2). Core's BIP32_EXTKEY_SIZE is 74 because
    //! its payload is a 33-byte key and it has one scheme to carry.
    static constexpr unsigned int SIZE = 1 + 4 + 4 + 32 + 32 + 2;

    friend bool operator==(const CExtKey& a, const CExtKey& b)
    {
        return a.nDepth == b.nDepth &&
            a.fingerprint == b.fingerprint &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.nodeseed == b.nodeseed &&
            a.secret_size == b.secret_size &&
            a.key == b.key;
    }

    CExtKey() = default;

    KeyFingerprint id_key_fingerprint() const
    {
        return key.GetPubKey().GetID().fingerprint();
    }

    void Encode(unsigned char code[SIZE]) const;
    void Decode(const unsigned char code[SIZE]);
    [[nodiscard]] bool Derive(CExtKey& out, unsigned int nChild) const;
    CExtPubKey Neuter() const;

    //! Make this the master node of a tree of that scheme. The scheme is part of
    //! the derivation, not a label on it: the same seed gives a different tree
    //! under each, and every key in a tree is the scheme the master names.
    void SetSeed(std::span<const unsigned char> seed, unsigned int secret_size = CKey::MLDSA44_SIZE);

    //! Compute the master node from a seed and a personalization tag.
    void SetSeedFromTag(std::span<const unsigned char> seed, const unsigned char* tag, size_t taglen, unsigned int secret_size);
};

//! Get extended key and origin info for a given path
//! @param[in] ext_key The extended private key to derive from
//! @param[in] path The BIP 32 path
//! @return the resulting extended private key and origin info
std::optional<std::pair<CExtKey, KeyOriginInfo>> DeriveExtKey(const CExtKey& ext_key, const std::vector<uint32_t>& path);

/** KeyPair
 *
 *  Wraps a `secp256k1_keypair` type, an opaque data structure for holding a secret and public key.
 *  This is intended for BIP340 keys and allows us to easily determine if the secret key needs to
 *  be negated by checking the parity of the public key. This class primarily intended for passing
 *  secret keys to libsecp256k1 functions expecting a `secp256k1_keypair`. For all other cases,
 *  CKey should be preferred.
 *
 *  A KeyPair can be created from a CKey with an optional merkle_root tweak (per BIP342). See
 *  CKey::ComputeKeyPair for more details.
 *
 *  Only a secp256k1 CKey yields a valid KeyPair. A lattice secret is not a scalar, and 32 bytes
 *  taken off one would very probably pass secp256k1_ec_seckey_verify and give a keypair unrelated
 *  to the key that was passed in, so the constructor refuses on length first.
 */
class KeyPair
{
public:
    KeyPair() noexcept = default;
    KeyPair(KeyPair&&) noexcept = default;
    KeyPair& operator=(KeyPair&&) noexcept = default;
    KeyPair& operator=(const KeyPair& other)
    {
        if (this != &other) {
            if (other.m_keypair) {
                MakeKeyPairData();
                *m_keypair = *other.m_keypair;
            } else {
                ClearKeyPairData();
            }
        }
        return *this;
    }

    KeyPair(const KeyPair& other) { *this = other; }

    friend KeyPair CKey::ComputeKeyPair(const uint256* merkle_root) const;
    [[nodiscard]] bool SignSchnorr(const uint256& hash, std::span<unsigned char> sig, const uint256& aux) const;

    //! Check whether this keypair is valid.
    bool IsValid() const { return !!m_keypair; }

private:
    KeyPair(const CKey& key, const uint256* merkle_root);

    using KeyType = std::array<unsigned char, 96>;
    secure_unique_ptr<KeyType> m_keypair;

    void MakeKeyPairData()
    {
        if (!m_keypair) m_keypair = make_secure_unique<KeyType>();
    }

    void ClearKeyPairData()
    {
        m_keypair.reset();
    }
};

/**
 * Check that required EC support is available at runtime, and that every
 * implemented scheme generates, signs and verifies: Core's ECC_InitSanityCheck()
 * with more than one primitive to get wrong.
 */
bool KeyCryptoSanityCheck();

/** Access the secp256k1 context used for signing. */
secp256k1_context* GetSecp256k1SignContext();

/**
 * RAII class initializing and deinitializing global state for elliptic curve support.
 * Only one instance may be initialized at a time.
 *
 * In the future global ECC state could be removed, and this class could contain
 * state and be passed as an argument to ECC key functions.
 */
class ECC_Context
{
public:
    ECC_Context();
    ~ECC_Context();
};

#endif // LATTICA_KEY_H
