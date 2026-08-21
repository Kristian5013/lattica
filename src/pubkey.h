// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_PUBKEY_H
#define LATTICA_PUBKEY_H

#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <utility>
#include <vector>

inline constexpr unsigned int BIP32_EXTKEY_SIZE = 74;
inline constexpr unsigned int BIP32_EXTKEY_WITH_VERSION_SIZE = 78;

using KeyFingerprint = std::array<unsigned char, 4>;

/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    explicit CKeyID(const uint160& in) : uint160(in) {}
    KeyFingerprint fingerprint() const
    {
        KeyFingerprint ret;
        std::copy_n(begin(), ret.size(), ret.begin());
        return ret;
    }
};

/** An encapsulated public key. */
class CPubKey
{
public:
    /**
     * secp256k1, Falcon-512 (PQClean falcon-padded-512), ML-DSA-44 (FIPS 204),
     * and the signature each produces. Nothing tags the scheme: the length
     * names it, as in Bitcoin, where GetLen() turns a header byte into a length
     * and the length is what the rest of the code reasons about.
     *
     * SIZE and SIGNATURE_SIZE are the largest of each, the bound a caller uses
     * when it must allocate before knowing the scheme. A secp256k1 signature is
     * DER as in Bitcoin, so its size is a bound and not a length; the two
     * lattice signatures are fixed.
     */
    static constexpr unsigned int SECP256K1_SIZE = 33;
    static constexpr unsigned int FALCON512_SIZE = 897;
    static constexpr unsigned int MLDSA44_SIZE   = 1312;
    static constexpr unsigned int SIZE           = MLDSA44_SIZE;

    static constexpr unsigned int SECP256K1_SIGNATURE_SIZE = 72;
    static constexpr unsigned int SECP256K1_COMPACT_SIGNATURE_SIZE = 65;
    static constexpr unsigned int FALCON512_SIGNATURE_SIZE = 666;
    static constexpr unsigned int MLDSA44_SIGNATURE_SIZE   = 2420;
    static constexpr unsigned int SIGNATURE_SIZE           = MLDSA44_SIGNATURE_SIZE;

    static_assert(
        SIZE >= SECP256K1_SIZE && SIZE >= FALCON512_SIZE,
        "SIZE is not the largest public key");
    static_assert(
        SIGNATURE_SIZE >= SECP256K1_SIGNATURE_SIZE && SIGNATURE_SIZE >= FALCON512_SIGNATURE_SIZE,
        "SIGNATURE_SIZE is not the largest signature");
    static_assert(
        SECP256K1_SIZE != FALCON512_SIZE && FALCON512_SIZE != MLDSA44_SIZE && SECP256K1_SIZE != MLDSA44_SIZE,
        "public key sizes must be pairwise distinct: the length is what names the scheme");

private:

    /**
     * Just store the serialized data.
     * Core keeps it in an `unsigned char vch[SIZE]` and recovers the length from
     * the first byte. Neither half of that carries over: there is no header byte
     * to read a length out of, so the length must be stored, and SIZE here is
     * 1312 rather than 65.
     */
    std::vector<unsigned char> vch;

    //! Set this key data to be invalid
    void Invalidate()
    {
        vch.clear();
    }

public:

    //! Whether this length is one an implemented scheme uses.
    bool static ValidSize(size_t len) {
      return len == SECP256K1_SIZE || len == FALCON512_SIZE || len == MLDSA44_SIZE;
    }

    bool static ValidSize(const std::vector<unsigned char> &vch) {
      return ValidSize(vch.size());
    }

    //! Construct an invalid public key.
    CPubKey()
    {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (ValidSize(static_cast<size_t>(pend - pbegin)))
            vch.assign(pbegin, pend);
        else
            Invalidate();
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    explicit CPubKey(std::span<const uint8_t> _vch)
    {
        Set(_vch.begin(), _vch.end());
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return vch.size(); }
    const unsigned char* data() const { return vch.data(); }
    const unsigned char* begin() const { return vch.data(); }
    const unsigned char* end() const { return vch.data() + size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch == b.vch;
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return a.vch < b.vch;
    }
    friend bool operator>(const CPubKey& a, const CPubKey& b)
    {
        return a.vch > b.vch;
    }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        unsigned int len = size();
        ::WriteCompactSize(s, len);
        s << std::span{vch.data(), len};
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const unsigned int len(::ReadCompactSize(s));
        if (len <= SIZE) {
            vch.resize(len);
            if (len) s >> std::span{vch.data(), len};
            if (!ValidSize(vch)) {
                Invalidate();
            }
        } else {
            // invalid pubkey, skip available data
            s.ignore(len);
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const
    {
        return CKeyID(Hash160(vch));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        return Hash(vch);
    }

    /*
     * Check syntactic correctness.
     *
     * When setting a pubkey (Set()) or deserializing fails (the data is not the
     * length of any implemented scheme), the size is set to 0. Thus,
     * by checking size, one can observe whether Set() or deserialization has
     * failed.
     *
     * This does not check for more than that. In particular, it does not verify
     * that a secp256k1 key corresponds to a point on the curve (see
     * IsFullyValid() for that instead).
     *
     * Note that this is consensus critical as CheckSig() calls it!
     */
    bool IsValid() const
    {
        return size() > 0;
    }

    /**
     * Fully validate whether this is a valid public key (more expensive than
     * IsValid()).
     *
     * How much "fully" means differs by scheme. secp256k1 is a complete check:
     * the bytes must decode to a point on the curve. Falcon-512 is partial, the
     * degree being all the public API exposes. For ML-DSA-44 the length is the
     * whole of it, since any MLDSA44_SIZE bytes unpack to some (rho, t1). A
     * caller must therefore not read a true here as "a matching private key
     * exists" for the lattice schemes.
     */
    /** Check if a public key is a syntactically valid compressed secp256k1 key.
     *  Core also admits the uncompressed 0x04 form; one scheme cannot have two
     *  lengths here, so a secp256k1 key is compressed and nothing else. */
    bool IsValidNonHybrid() const noexcept
    {
        return size() == SECP256K1_SIZE && (vch[0] == 0x02 || vch[0] == 0x03);
    }

    bool IsFullyValid() const;

    //! Check whether this is a compressed public key. True exactly for secp256k1.
    bool IsCompressed() const
    {
        return size() == SECP256K1_SIZE;
    }

    /**
     * Verify a signature, of the scheme this key's length names.
     *
     * A secp256k1 signature is DER (~72 bytes), parsed as leniently as Core
     * parses it and normalized to low-S before verification, so the consensus
     * rules that make an encoding canonical are BIP66's and live in the script
     * interpreter rather than here. The two lattice signatures are their
     * schemes' own fixed-length forms.
     *
     * If this public key is not fully valid, the return value will be false.
     */
    bool Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const;

    /**
     * Check whether a signature is normalized (lower-S).
     */
    static bool CheckLowS(const std::vector<unsigned char>& vchSig);

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint256& hash, const std::vector<unsigned char>& vchSig);

    //! Derive BIP32 child pubkey.
    [[nodiscard]] bool Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc, uint256* bip32_tweak_out = nullptr) const;

    /**
     * The signature size this key's scheme produces, or 0 if the key is
     * invalid. For secp256k1 this is DER's upper bound rather than a length.
     */
    unsigned int SignatureSize() const;

    // Two of Core's members have no analogue. GetLen() reads a length off a
    // header byte, and there is no header byte; Decompress() needs an
    // uncompressed form, and one scheme cannot have two lengths here.
};

class XOnlyPubKey
{
private:
    uint256 m_keydata;

public:
    /** Nothing Up My Sleeve point H
     *  Used as an internal key for provably disabling the key path spend
     *  see BIP341 for more details
     *
     *  Kept at Bitcoin's value: H is a point whose discrete logarithm nobody
     *  knows, which is a fact about the curve and not about either chain's hash
     *  function. */
    static const XOnlyPubKey NUMS_H;

    /** Construct an empty x-only pubkey. */
    XOnlyPubKey() = default;

    XOnlyPubKey(const XOnlyPubKey&) = default;
    XOnlyPubKey& operator=(const XOnlyPubKey&) = default;

    /** Determine if this pubkey is fully valid. This is true for approximately 50% of all
     *  possible 32-byte arrays. If false, VerifySchnorr, CheckTapTweak and CreateTapTweak
     *  will always fail. */
    bool IsFullyValid() const;

    /** Test whether this is the 0 key (the result of default construction). This implies
     *  !IsFullyValid(). */
    bool IsNull() const { return m_keydata.IsNull(); }

    /** Construct an x-only pubkey from exactly 32 bytes. */
    constexpr explicit XOnlyPubKey(std::span<const unsigned char> bytes) : m_keydata{bytes} {}

    /** Construct an x-only pubkey from a normal pubkey.
     *
     *  Only a secp256k1 key has an x coordinate to take. Core cannot be handed
     *  anything else; here a lattice key leaves this null, which IsFullyValid()
     *  and VerifySchnorr() then refuse. */
    explicit XOnlyPubKey(const CPubKey& pubkey)
    {
        if (pubkey.size() == CPubKey::SECP256K1_SIZE) {
            m_keydata = uint256{std::span{pubkey.data() + 1, 32}};
        }
    }

    /** Verify a Schnorr signature against this public key.
     *
     * sigbytes must be exactly 64 bytes.
     */
    bool VerifySchnorr(const uint256& msg, std::span<const unsigned char> sigbytes) const;

    /** Compute the Taproot tweak as specified in BIP341, with *this as internal
     * key:
     *  - if merkle_root == nullptr: H_TapTweak(xonly_pubkey)
     *  - otherwise:                 H_TapTweak(xonly_pubkey || *merkle_root)
     *
     * Note that the behavior of this function with merkle_root != nullptr is
     * consensus critical.
     */
    uint256 ComputeTapTweakHash(const uint256* merkle_root) const;

    /** Verify that this is a Taproot tweaked output point, against a specified internal key,
     *  Merkle root, and parity. */
    bool CheckTapTweak(const XOnlyPubKey& internal, const uint256& merkle_root, bool parity) const;

    /** Construct a Taproot tweaked output point with this point as internal key. */
    std::optional<std::pair<XOnlyPubKey, bool>> CreateTapTweak(const uint256* merkle_root) const;

    /** Returns a list of CKeyIDs for the CPubKeys that could have been used to create this XOnlyPubKey.
     * As the CKeyID is the Hash160(full pubkey), the produced CKeyIDs are for the versions of this
     * XOnlyPubKey with 0x02 and 0x03 prefixes.
     * This is needed for key lookups since keys are indexed by CKeyID.
     */
    std::vector<CKeyID> GetKeyIDs() const;
    /** Returns this XOnlyPubKey with 0x02 and 0x03 prefixes */
    std::vector<CPubKey> GetCPubKeys() const;

    CPubKey GetEvenCorrespondingCPubKey() const;

    const unsigned char& operator[](int pos) const { return *(m_keydata.begin() + pos); }
    static constexpr size_t size() { return decltype(m_keydata)::size(); }
    const unsigned char* data() const { return m_keydata.begin(); }
    const unsigned char* begin() const { return m_keydata.begin(); }
    const unsigned char* end() const { return m_keydata.end(); }
    unsigned char* data() { return m_keydata.begin(); }
    unsigned char* begin() { return m_keydata.begin(); }
    unsigned char* end() { return m_keydata.end(); }
    bool operator==(const XOnlyPubKey& other) const { return m_keydata == other.m_keydata; }
    bool operator<(const XOnlyPubKey& other) const { return m_keydata < other.m_keydata; }

    //! Implement serialization without length prefixes since it is a fixed length
    SERIALIZE_METHODS(XOnlyPubKey, obj) { READWRITE(obj.m_keydata); }
};

// Core's EllSwiftPubKey belongs to the BIP324 transport; this transport is
// ML-KEM-768, see v2cipher.h.

struct CExtPubKey {
    unsigned char version[4];
    unsigned char nDepth;
    KeyFingerprint fingerprint;
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return a.nDepth == b.nDepth &&
            a.fingerprint == b.fingerprint &&
            a.nChild == b.nChild &&
            a.chaincode == b.chaincode &&
            a.pubkey == b.pubkey;
    }

    friend bool operator<(const CExtPubKey &a, const CExtPubKey &b)
    {
        if (a.pubkey < b.pubkey) {
            return true;
        } else if (a.pubkey > b.pubkey) {
            return false;
        }
        return a.chaincode < b.chaincode;
    }

    KeyFingerprint id_key_fingerprint() const
    {
        return pubkey.GetID().fingerprint();
    }

    //! Encode/Decode are BIP32's fixed 74 bytes and so are secp256k1's; Encode
    //! asserts a 33-byte key. They are the base58 form, which only that scheme
    //! has.
    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    void EncodeWithVersion(unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE]) const;
    void DecodeWithVersion(const unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE]);
    [[nodiscard]] bool Derive(CExtPubKey& out, unsigned int nChild, uint256* bip32_tweak_out = nullptr) const;

    //! Serialization, for records that hold a node of the key tree. Core has none
    //! and writes Encode()'s fixed 74 bytes instead, which it can because every
    //! key it caches is 33 bytes. A node here may hold a Falcon-512 or ML-DSA-44
    //! public key, so the key carries its own length. The version bytes are not
    //! part of a node and are left out.
    SERIALIZE_METHODS(CExtPubKey, obj)
    {
        READWRITE(obj.nDepth, obj.fingerprint, obj.nChild, obj.chaincode, obj.pubkey);
    }
};

#endif // LATTICA_PUBKEY_H
