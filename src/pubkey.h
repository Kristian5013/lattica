// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Public key + signature verification, modeled on Bitcoin Core's pubkey.h
// (CKeyID / CPubKey). Lattica is crypto-agile and post-quantum: where Core's
// CPubKey wraps a secp256k1 point (a header byte then the curve point), ours
// wraps a one-byte scheme tag then the raw scheme public key — the math is the
// vendored ML-DSA-44 (PQClean / FIPS 204, the standardized Dilithium2), the
// analog of Core's secp256k1 subtree. The serialized form a CPubKey stores is
// exactly the byte string a transaction pushes (scheme byte || key), so its
// size is recoverable from the first byte just like Core's.
//
// Core's secp256k1-only types — XOnlyPubKey (Taproot/Schnorr), EllSwiftPubKey
// (BIP324 transport), and CExtPubKey (BIP32 HD derivation) — are intentionally
// not ported: Lattica's design (option A) has no Taproot, and EC-style key
// tweaking/derivation does not carry over to ML-DSA.

#ifndef LATTICA_PUBKEY_H
#define LATTICA_PUBKEY_H

#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <cstring>
#include <vector>

/** Crypto-agile signature scheme ids. The id is the leading byte of a serialized
 *  public key (and of a transaction input's pushed key); new schemes are a soft
 *  consensus upgrade. */
enum class SigScheme : uint8_t {
    ML_DSA_44 = 0x01,
    FALCON_512 = 0x02,
    SECP256K1 = 0x03,
};

[[nodiscard]] bool IsKnownScheme(SigScheme s);
[[nodiscard]] size_t SchemePublicKeySize(SigScheme s);
[[nodiscard]] size_t SchemeSignatureSize(SigScheme s);
[[nodiscard]] size_t SchemeSecretKeySize(SigScheme s);

/** The per-signature verification cost (sig-op weight) of a scheme, used to
 *  bound a block's total PQC-verification work (see MAX_BLOCK_SIGOPS_COST).
 *  ML-DSA-44 is the unit (1); a heavier future scheme would cost proportionally
 *  more; an unknown scheme is 0 (it is rejected without a verify). */
[[nodiscard]] int64_t SchemeSigOpCost(SigScheme s);

/** A reference to a CPubKey: the Hash160 of its serialized public key. */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    explicit CKeyID(const uint160& in) : uint160(in) {}
};

/** An encapsulated crypto-agile public key (scheme byte || raw key). */
class CPubKey
{
public:
    //! Maximum serialized size of any supported scheme (scheme byte + key). Sized
    //! for ML-DSA-44 (1 + 1312); grow as heavier schemes are added.
    static constexpr unsigned int SIZE = 1 + 1312;

private:
    //! The serialized public key: scheme byte at [0], raw key after. Empty == invalid.
    std::vector<unsigned char> vch;

    //! Length of a serialized pubkey with the given leading (scheme) byte, or 0
    //! if the scheme is unknown.
    static unsigned int GetLen(unsigned char chHeader)
    {
        const size_t n = SchemePublicKeySize(static_cast<SigScheme>(chHeader));
        return n == 0 ? 0 : static_cast<unsigned int>(1 + n);
    }

    //! Set this key to be invalid.
    void Invalidate() { vch.clear(); }

public:
    //! Whether a byte vector is a syntactically valid serialized pubkey.
    static bool ValidSize(const std::vector<unsigned char>& vch)
    {
        return vch.size() > 0 && GetLen(vch[0]) == vch.size();
    }

    //! Construct an invalid public key.
    CPubKey() { Invalidate(); }

    //! Initialize from begin/end iterators over the serialized (scheme || key) bytes.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        const int len = pend == pbegin ? 0 : GetLen((unsigned char)pbegin[0]);
        if (len && len == (pend - pbegin))
            vch.assign(pbegin, pend);
        else
            Invalidate();
    }

    //! Construct from begin/end iterators over the serialized bytes.
    template <typename T>
    CPubKey(const T pbegin, const T pend) { Set(pbegin, pend); }

    //! Construct from a serialized (scheme || key) byte span.
    explicit CPubKey(std::span<const unsigned char> _vch) { Set(_vch.begin(), _vch.end()); }

    //! Convenience: assemble from a scheme tag and the raw key bytes.
    CPubKey(SigScheme scheme, std::span<const unsigned char> rawkey)
    {
        std::vector<unsigned char> ser;
        ser.reserve(1 + rawkey.size());
        ser.push_back(static_cast<unsigned char>(scheme));
        ser.insert(ser.end(), rawkey.begin(), rawkey.end());
        Set(ser.begin(), ser.end());
    }

    //! Simple read-only vector-like interface to the serialized data.
    unsigned int size() const { return static_cast<unsigned int>(vch.size()); }
    const unsigned char* data() const { return vch.data(); }
    const unsigned char* begin() const { return vch.data(); }
    const unsigned char* end() const { return vch.data() + vch.size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! The scheme tag (leading byte). Meaningful only for a valid key.
    SigScheme GetScheme() const { return static_cast<SigScheme>(vch[0]); }
    //! The raw scheme key (the serialization minus the leading scheme byte).
    std::span<const unsigned char> RawKey() const { return std::span<const unsigned char>(vch.data() + 1, vch.size() - 1); }

    //! Comparators.
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

    //! Get the KeyID of this public key (Hash160 of its serialization).
    CKeyID GetID() const
    {
        return CKeyID(Hash160(std::span{vch.data(), size()}));
    }

    //! Get the 256-bit hash of this public key's serialization.
    uint256 GetHash() const
    {
        return Hash(std::span{vch.data(), size()});
    }

    /**
     * Check syntactic correctness.
     *
     * Note that this is consensus critical as CheckSig() calls it: an invalid
     * key (wrong scheme or wrong length) must never verify.
     */
    bool IsValid() const { return size() > 0; }

    /**
     * Verify `sig` over `hash` (the sighash) under this key. Returns false if
     * the key is not syntactically valid.
     */
    bool Verify(const uint256& hash, std::span<const unsigned char> sig) const;
};

#endif // LATTICA_PUBKEY_H
