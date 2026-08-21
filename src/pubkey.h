// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Public key + signature verification, modeled on Bitcoin Core's pubkey.h.
//
// Core's CPubKey is a secp256k1 point: a fixed 65-byte array whose length is
// read off the first byte (0x02/0x03 compressed, 0x04 uncompressed), with a
// surface of curve arithmetic around it — IsCompressed(), Decompress(),
// RecoverCompact(), Derive(). This class keeps Core's contract and member
// order while holding a key of any of three schemes:
//
//     scheme        public key  signature
//     secp256k1             33         64   compact r||s, low-S mandatory
//     Falcon-512           897        666   PQClean falcon-padded-512
//     ML-DSA-44           1312       2420   FIPS 204
//
// Nothing names the scheme. A key on the stack is the scheme's own bytes with
// nothing in front of them, exactly as in Bitcoin, and the length is the type
// information — which is also how Core works, since its GetLen() turns a header
// byte into a length and the length is what its code then reasons about.
// Bitcoin likewise disambiguates by length inside a witness version, a 20-byte
// program being P2WPKH and a 32-byte one P2WSH.
//
// The rule this rests on is enforced below by static_assert rather than left to
// a comment: no two schemes may share a public-key length. It binds every
// scheme added later.
//
// One structural difference from Core. The bytes live in a std::vector rather
// than an inline array: Core can afford `unsigned char vch[65]` in every
// CPubKey, whereas the same choice here would put 1312 bytes in every copy,
// including the ones that never hold a lattice key.
//
// Core's secp256k1-only types — XOnlyPubKey (Taproot/Schnorr), EllSwiftPubKey
// (BIP324 transport) and CExtPubKey (BIP32 public derivation) — are not
// reproduced. Lattica has no witness v1, its transport is ML-KEM-768, and a
// lattice scheme has no key homomorphism to derive a child public key with.

#ifndef LATTICA_PUBKEY_H
#define LATTICA_PUBKEY_H

#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using KeyFingerprint = std::array<unsigned char, 4>;

/** A reference to a CKey: the Hash160 of its public key */
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
     * The size of a public key, per scheme, and of the signature that scheme
     * produces. These constants are the whole of the type information: a key
     * carries no tag, so its length is what says which scheme it belongs to.
     *
     * SIZE and SIGNATURE_SIZE are the largest of each, the bound a caller uses
     * when it must allocate before knowing the scheme.
     */
    static constexpr unsigned int SECP256K1_SIZE = 33;
    static constexpr unsigned int FALCON512_SIZE = 897;
    static constexpr unsigned int MLDSA44_SIZE   = 1312;
    static constexpr unsigned int SIZE           = MLDSA44_SIZE;

    static constexpr unsigned int SECP256K1_SIGNATURE_SIZE = 64;
    static constexpr unsigned int FALCON512_SIGNATURE_SIZE = 666;
    static constexpr unsigned int MLDSA44_SIGNATURE_SIZE   = 2420;
    static constexpr unsigned int SIGNATURE_SIZE           = MLDSA44_SIGNATURE_SIZE;

    static_assert(SIZE >= SECP256K1_SIZE && SIZE >= FALCON512_SIZE,
                  "SIZE must be the largest public key");
    static_assert(SIGNATURE_SIZE >= SECP256K1_SIGNATURE_SIZE && SIGNATURE_SIZE >= FALCON512_SIGNATURE_SIZE,
                  "SIGNATURE_SIZE must be the largest signature");
    static_assert(SECP256K1_SIZE != FALCON512_SIZE &&
                  FALCON512_SIZE != MLDSA44_SIZE &&
                  SECP256K1_SIZE != MLDSA44_SIZE,
                  "public key sizes must be pairwise distinct: the length is what names the scheme");

private:
    //! Just store the key. Its length is what says which scheme it belongs to.
    std::vector<unsigned char> vch;

    //! Set this key data to be invalid
    void Invalidate() { vch.clear(); }

public:
    //! Whether this length is one an implemented scheme uses.
    static bool ValidSize(size_t len)
    {
        return len == SECP256K1_SIZE || len == FALCON512_SIZE || len == MLDSA44_SIZE;
    }

    bool static ValidSize(const std::vector<unsigned char>& vch)
    {
        return ValidSize(vch.size());
    }

    //! Construct an invalid public key.
    CPubKey() { Invalidate(); }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (ValidSize(static_cast<size_t>(pend - pbegin))) {
            vch.assign(pbegin, pend);
        } else {
            Invalidate();
        }
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend) { Set(pbegin, pend); }

    //! Construct a public key from a byte vector.
    explicit CPubKey(std::span<const uint8_t> _vch) { Set(_vch.begin(), _vch.end()); }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return static_cast<unsigned int>(vch.size()); }
    const unsigned char* data() const { return vch.data(); }
    const unsigned char* begin() const { return vch.data(); }
    const unsigned char* end() const { return vch.data() + vch.size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b) { return a.vch == b.vch; }
    friend bool operator!=(const CPubKey& a, const CPubKey& b) { return a.vch != b.vch; }
    friend bool operator<(const CPubKey& a, const CPubKey& b) { return a.vch < b.vch; }
    friend bool operator>(const CPubKey& a, const CPubKey& b) { return a.vch > b.vch; }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const unsigned int len = size();
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

    //! Get the KeyID of this public key (its Hash160)
    CKeyID GetID() const
    {
        return CKeyID(Hash160(std::span{vch.data(), size()}));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        return Hash(std::span{vch.data(), size()});
    }

    /*
     * Check syntactic correctness.
     *
     * When setting a pubkey (Set()) or deserializing fails — the data is not
     * the length of any implemented scheme — the size is set to 0. Thus, by
     * checking size, one can observe whether Set() or deserialization failed.
     *
     * This does not check for more than that. In particular it does not verify
     * that a secp256k1 key is a point on the curve (see IsFullyValid() for that
     * instead).
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
     * How much "fully" means differs by scheme, and the difference is real:
     *
     *   secp256k1   a complete check. The bytes must decode to a point on the
     *               curve, which secp256k1_ec_pubkey_parse decides.
     *   Falcon-512  partial. The header byte must announce degree n = 512;
     *               whether every coefficient is in range is decided inside
     *               PQClean, which does not expose its decoder.
     *   ML-DSA-44   the length is the whole of it. Any MLDSA44_SIZE bytes
     *               unpack to some (rho, t1), so there is no key to reject.
     *
     * A caller must therefore not read a true here as "this key has a matching
     * private key" for the lattice schemes — only that nothing is detectably
     * wrong with it.
     */
    bool IsFullyValid() const;

    /**
     * Verify a signature over `hash` under this key, using the scheme its
     * length names.
     *
     * secp256k1 signatures are a fixed 64-byte compact r||s and low-S is
     * mandatory: a high-S signature is rejected rather than normalized, so the
     * encoding is unique and a third party cannot rewrite a txid by flipping s
     * to n-s. Core needs CheckLowS() as a separate policy rule because its
     * consensus rules accept both; here the rule is in the verifier, so there
     * is nothing left for policy to add.
     *
     * If this public key is not fully valid, the return value will be false.
     */
    bool Verify(const uint256& hash, std::span<const unsigned char> sig) const;

    //! The signature size this key's scheme produces, or 0 if the key is invalid.
    unsigned int SignatureSize() const;
};

#endif // LATTICA_PUBKEY_H
