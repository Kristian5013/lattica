// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Private key + signing, modeled on Bitcoin Core's key.h (CKey / CPrivKey).
//
// Core's CKey is a secp256k1 key. Not "a key class configured for secp256k1" —
// the curve is in its data layout and its return types: KeyType is a fixed
// 32-byte array, GetPubKey() recomputes the public key from the secret with no
// field to store one, GetPrivKey() emits DER (which is what its SIZE{279} and
// COMPRESSED_SIZE{214} actually measure), and fCompressed threads a
// point-serialization concern through Set() and the DER export. None of that
// survives a second scheme, so this class keeps Core's contract and skeleton
// while its interior is written for three:
//
//     scheme        secret  public  signature
//     secp256k1         32      33         64
//     Falcon-512      1281     897        666
//     ML-DSA-44       2560    1312       2420
//
// Nothing names the scheme. As in CPubKey, the length is the type information:
// a CKey holds one secret and the size of that secret says which algorithm it
// belongs to. The sizes are pairwise distinct and a static_assert holds them
// that way, which is the same rule CPubKey rests on.
//
// Three consequences are worth stating because they are not choices:
//
//   * A CKey carries its public key. Only secp256k1 can hand one back on
//     demand. ML-DSA cannot at all — its secret packs t0 while the public key
//     packs t1, and recovering t1 means re-expanding A and recomputing
//     t = A*s1 + s2. Falcon's is recomputable in principle (h = g/f mod q) but
//     PQClean exposes that only as an internal symbol over unpacked
//     polynomials. Rather than branch on storage, every scheme captures the
//     public key at generation time.
//
//   * There is no compression flag. Core's public-key header byte is the
//     compression marker and the source of its length; here the length is the
//     scheme, and one scheme cannot have two lengths, so secp256k1 keys are
//     compressed-only.
//
//   * A caller that wants a particular scheme names it by size —
//     GenerateRandomKey(CKey::FALCON512_SIZE). Passing the wrong constant is a
//     runtime rejection rather than a compile error; that is the cost of having
//     no tag type.
//
// Parts of Core's key.h with no analog here are enumerated with the reason at
// the bottom of the class, mirroring how pubkey.h documents what it omits.

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

struct secp256k1_context_struct;
typedef struct secp256k1_context_struct secp256k1_context;

/**
 * CPrivKey is a serialized private key.
 *
 * Core's is DER (SEC 1 ECPrivateKey, curve parameters and all). Here it is the
 * raw scheme secret: a lattice secret has no DER encoding, and inventing one so
 * that all three schemes could share a container would add a parser to the
 * wallet's load path for no gain.
 */
typedef std::vector<unsigned char, secure_allocator<unsigned char>> CPrivKey;

/** An encapsulated private key of one of the supported signature schemes. */
class CKey
{
public:
    /**
     * The size of a secret, per scheme. As in CPubKey these constants are the
     * whole of the type information: a key carries no tag, so the length of
     * the secret says which algorithm it belongs to, and a caller naming a
     * scheme names one of these.
     *
     * SIZE is the largest, the bound the secure allocation is sized to.
     */
    static constexpr unsigned int SECP256K1_SIZE = 32;
    static constexpr unsigned int FALCON512_SIZE = 1281;
    static constexpr unsigned int MLDSA44_SIZE   = 2560;
    static constexpr unsigned int SIZE           = MLDSA44_SIZE;

    static_assert(SIZE >= SECP256K1_SIZE && SIZE >= FALCON512_SIZE,
                  "SIZE must be the largest secret");
    static_assert(SECP256K1_SIZE != FALCON512_SIZE &&
                  FALCON512_SIZE != MLDSA44_SIZE &&
                  SECP256K1_SIZE != MLDSA44_SIZE,
                  "secret sizes must be pairwise distinct: the length is what names the scheme");

    /**
     * The key-generation seed size, and deliberately not per-scheme: ML-DSA's
     * FIPS 204 xi, Falcon's keygen seed and a secp256k1 scalar are all 32
     * bytes, which is what lets one hierarchical tree carry every scheme.
     */
    static constexpr unsigned int SEED_SIZE = 32;

    //! Whether this length is one an implemented scheme uses.
    static bool ValidSize(size_t len)
    {
        return len == SECP256K1_SIZE || len == FALCON512_SIZE || len == MLDSA44_SIZE;
    }

private:
    //! Per-scheme secret buffers.
    using SecpKey = std::array<unsigned char, SECP256K1_SIZE>;
    using FalconKey = std::array<unsigned char, FALCON512_SIZE>;
    using MLDSAKey = std::array<unsigned char, MLDSA44_SIZE>;
    using KeyVariant = std::variant<SecpKey, FalconKey, MLDSAKey>;

    //! secure_unique_ptr's deleter returns the storage to the locked pool
    //! without running a destructor, which is sound only while every
    //! alternative is trivially destructible. A non-trivial one added here
    //! would leak with no diagnostic at all.
    static_assert(std::is_trivially_destructible_v<KeyVariant>,
                  "CKey's secure storage is freed without running a destructor");

    /**
     * The secret material. Null means invalid.
     *
     * The variant lives INSIDE the secure allocation rather than beside it:
     * secure_allocator draws from the locked pool and memory_cleanse()s on
     * release, whereas a plain std::variant member would sit in ordinary
     * memory that can be paged to disk and is never wiped. The cost is that
     * the allocation is always SIZE, so a 32-byte scalar occupies an
     * ML-DSA-sized slot; locked-pool space is not the scarce resource here.
     */
    secure_unique_ptr<KeyVariant> m_keydata;

    //! The matching public key. See the header comment for why it is stored.
    CPubKey m_pubkey;

    //! Allocate if needed, then select and zero the alternative for `scheme`.
    //! Leaves the key invalid if the scheme is not one this build knows.
    //! Allocate if needed, then select and zero the alternative for a secret
    //! of `secret_size`. Leaves the key invalid if no scheme uses that size.
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
                m_keydata.reset();
            }
            m_pubkey = other.m_pubkey;
        }
        return *this;
    }

    CKey(const CKey& other) { *this = other; }

    friend bool operator==(const CKey& a, const CKey& b)
    {
        return a.size() == b.size() &&
               (a.size() == 0 || std::memcmp(a.data(), b.data(), a.size()) == 0);
    }

    /**
     * Initialize from a secret and its matching public key.
     *
     * The scheme comes from the public key, and the secret must be exactly that
     * scheme's secret length. This is Core's `Set(pbegin, pend, fCompressedIn)`
     * with the compression flag replaced by the public key: the flag has no
     * meaning here, and ML-DSA cannot recompute a public key from its secret,
     * so it has to be supplied rather than derived. The key is left invalid if
     * the length is wrong, the secret is structurally unacceptable, or the pair
     * does not match.
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
        std::memcpy(MutableData(), (const unsigned char*)&sk_begin[0], len);
        m_pubkey = pubkey;
        if (!VerifyPubKey(pubkey)) ClearKeyData();
    }

    //! Simple read-only vector-like interface over the active secret bytes.
    unsigned int size() const;
    const unsigned char* data() const;
    const unsigned char* begin() const { return data(); }
    const unsigned char* end() const { return data() + size(); }

    //! Check whether this private key is valid.
    bool IsValid() const { return !!m_keydata; }

    //! The secret size a scheme uses given its public key size, or 0 if that
    //! public key size belongs to no scheme. The one place the two size
    //! namespaces are bridged.
    static unsigned int SecretSizeForPubKey(unsigned int pubkey_size);

    /**
     * Whether a secret buffer is structurally acceptable for that size.
     *
     * Only secp256k1 has a real predicate: the scalar must lie in [1, n-1], and
     * secp256k1_ec_seckey_verify decides it. Neither lattice scheme has a cheap
     * equivalent — any buffer of the right length is structurally fine, and
     * semantic validity is what VerifyPubKey establishes.
     */
    static bool Check(unsigned int secret_size, const unsigned char* vch);

    //! Generate a fresh random keypair for the scheme of that secret size.
    //! secp256k1 and Falcon need a signing context (see ECC_Context).
    void MakeNewKey(unsigned int secret_size = MLDSA44_SIZE);

    /**
     * Deterministically generate a keypair for that scheme from a SEED_SIZE-byte
     * seed. This backs hierarchical derivation; it returns false, leaving the
     * key invalid, if the seed is the wrong length or unusable for the scheme.
     *
     * The seed means something different per scheme, and the difference is real
     * rather than cosmetic:
     *
     *   ML-DSA-44   the FIPS 204 KeyGen_internal(xi) seed, fed to the
     *               unmodified PQClean keypair through the entropy seam in
     *               randombytes.h. Every seed is usable.
     *   Falcon-512  the same seam drives PQClean's Falcon keygen, which also
     *               draws from randombytes. Every seed is usable, but keygen is
     *               far more expensive than the other two — an NTRU lattice
     *               with rejection sampling, not one hash.
     *   secp256k1   the seed IS the scalar. A seed outside [1, n-1] has no key
     *               and is rejected, which happens with probability about
     *               2^-128 and must still be handled by the caller.
     */
    bool MakeKeyFromSeed(unsigned int secret_size, std::span<const unsigned char> seed);

    //! Serialize the private key (the raw scheme secret; see CPrivKey).
    CPrivKey GetPrivKey() const;

    //! The public key matching this private key.
    CPubKey GetPubKey() const { return m_pubkey; }

    /**
     * Sign the 32-byte message `hash` (a sighash). The result is the bare scheme
     * signature; callers building a witness append the sighash-type byte.
     *
     * Determinism differs by scheme and callers must not assume it: secp256k1
     * uses RFC6979 and ML-DSA-44 is hedged-but-fixed here, so both reproduce,
     * while Falcon salts every signature and does not.
     *
     * Core's `grind` and `test_case` parameters are absent. They exist to shave
     * a byte off a DER ECDSA signature, and this chain has no DER: the script
     * engine implements no signature-encoding rules at all.
     */
    bool Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const;

    /**
     * Verify that a candidate public key is the one matching this private key.
     *
     * secp256k1 derives the public key and compares it. Neither lattice scheme
     * can: ML-DSA's secret packs t0 rather than t1, and while a Falcon public
     * key is recomputable from its secret, PQClean exposes that only as an
     * internal symbol over unpacked polynomials. Both therefore sign a random
     * challenge and check it verifies under the candidate.
     */
    bool VerifyPubKey(const CPubKey& vchPubKey) const;

    //! Load a private key and rebuild the CKey. The public key must be supplied
    //! because ML-DSA cannot recompute it from the secret alone.
    bool Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck);

    // --- Surface of Core's CKey not reproduced here ---------------------------
    //
    //   IsCompressed()                    secp256k1 keys are compressed-only;
    //                                     see the header comment for why the
    //                                     flag cannot coexist with a scheme tag.
    //   SignCompact()                     65-byte recoverable ECDSA for public-key
    //                                     recovery. The recovery module is not
    //                                     built (cmake/secp256k1.cmake) and
    //                                     neither lattice scheme recovers a key
    //                                     from a signature. Note the ordinary
    //                                     secp256k1 signature here is "compact"
    //                                     in libsecp256k1's sense — 64 bytes,
    //                                     r||s — which is a different thing.
    //   SignSchnorr() / ComputeKeyPair()  BIP-340 and Taproot key-path. There is
    //                                     no witness v1, and schnorrsig and
    //                                     extrakeys are not built.
    //   Derive()                          BIP32 child derivation by additive
    //                                     scalar tweak. Portable verbatim for
    //                                     secp256k1 and impossible for either
    //                                     lattice scheme, so it belongs to a
    //                                     scheme-aware CExtKey rather than here.
    //   EllSwiftCreate() /                BIP-324 transport. This transport is
    //   ComputeBIP324ECDHSecret()         ML-KEM-768; see v2cipher.h.
};

//! Produce a fresh random private key of that scheme, with its matching public key.
CKey GenerateRandomKey(unsigned int secret_size = CKey::MLDSA44_SIZE) noexcept;

/**
 * Self-test every implemented scheme at startup: generate, sign, verify, and
 * confirm the key agrees with its own public key. Core's ECC_InitSanityCheck()
 * with more than one primitive to get wrong.
 */
bool KeyCryptoSanityCheck();

/**
 * The secp256k1 signing context, or nullptr if none has been started.
 *
 * Only key generation and signing need it — secp256k1_ec_pubkey_create and
 * secp256k1_ecdsa_sign refuse the static context. Verification does not:
 * CPubKey::Verify uses secp256k1_context_static, so validating a block requires
 * no global setup at all and consensus code never touches this.
 */
secp256k1_context* GetSecp256k1SignContext();

/**
 * RAII class initializing and deinitializing global state for elliptic curve
 * support. Only one instance may be initialized at a time.
 *
 * A process that generates or signs with secp256k1 keys must hold one; a
 * process that only validates need not. The lattice schemes need no context.
 */
class ECC_Context
{
public:
    ECC_Context();
    ~ECC_Context();
};

//! A BIP32-style chain code: 256 bits of derivation entropy carried with a key.
using ChainCode = uint256;

/**
 * A hierarchical-deterministic extended private key, the Lattica analog of
 * Core's CExtKey (BIP32).
 *
 * Still ML-DSA-only, and still hardened-only with it. Because a lattice scheme
 * has no additive key tweak, the chainable secret is not the signing key but
 * the 32-byte seed that deterministically expands to one, and a child is
 * derived by mixing the parent's node seed into a SHA3-512 PRF keyed by the
 * chain code. A parent extended *public* key therefore cannot derive child
 * public keys, which is why there is no Neuter() / CExtPubKey.
 *
 * secp256k1 changes that: Core's BIP32 tweak is portable verbatim and would
 * give real non-hardened derivation and a working Neuter(). Making this
 * scheme-aware the way CKey now is, is the next step rather than this one.
 */
struct CExtKey {
    unsigned char nDepth{0};
    unsigned char vchFingerprint[4]{0, 0, 0, 0};
    unsigned int nChild{0};
    ChainCode chaincode;
    uint256 nodeseed;  //!< the 32-byte key-generation seed (the chainable secret)
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

    //! Compute the master node from a seed and a personalization tag.
    void SetSeedFromTag(std::span<const unsigned char> seed, const unsigned char* tag, size_t taglen);

    //! Derive the hardened child at index nChild. False if this key is invalid.
    [[nodiscard]] bool Derive(CExtKey& out, unsigned int nChild) const;

    //! Serialize / deserialize to a fixed SIZE-byte form. Decode re-expands the
    //! signing key from the stored node seed.
    void Encode(unsigned char code[SIZE]) const;
    void Decode(const unsigned char code[SIZE]);
};

#endif // LATTICA_KEY_H
