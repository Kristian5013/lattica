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

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

/** Crypto-agile signature scheme ids.
 *
 * These are internal identifiers and are NOT serialized. A public key on the
 * stack is the bare scheme key with nothing in front of it, exactly as in
 * Bitcoin, and the scheme is recovered from its length — the three sizes are
 * pairwise distinct. Bitcoin already disambiguates by length inside a witness
 * version (a 20-byte program is P2WPKH, a 32-byte one P2WSH), so this is its
 * habit rather than a new trick.
 *
 * The rule that follows, and it binds every scheme added later: a new scheme
 * must not share a public-key length with one already accepted, or the two
 * become indistinguishable on the stack. Current sizes are 33, 897 and 1312;
 * the obvious candidates are clear of them (ML-DSA-65 is 1952, Falcon-1024 is
 * 1793, SLH-DSA is 32).
 */
enum class SigScheme : uint8_t {
    ML_DSA_44 = 0x01,
    FALCON_512 = 0x02,
    SECP256K1 = 0x03,
};

//! Every scheme this build implements, for callers that must try each in turn.
inline constexpr std::array<SigScheme, 3> ALL_SIG_SCHEMES{
    SigScheme::SECP256K1, SigScheme::FALCON_512, SigScheme::ML_DSA_44};

//! The scheme a public key of this length belongs to, or nullopt if no scheme
//! uses that length. This is how a key on the stack is identified.
[[nodiscard]] std::optional<SigScheme> SchemeFromPubKeySize(size_t len);

[[nodiscard]] bool IsKnownScheme(SigScheme s);
[[nodiscard]] size_t SchemePublicKeySize(SigScheme s);
[[nodiscard]] size_t SchemeSignatureSize(SigScheme s);
[[nodiscard]] size_t SchemeSecretKeySize(SigScheme s);

/** The per-signature verification cost (sig-op weight) of a scheme, used to
 *  bound a block's total PQC-verification work (see MAX_BLOCK_SIGOPS_COST).
 *  ML-DSA-44 is the unit (1); a heavier future scheme would cost proportionally
 *  more; an unknown scheme is 0 (it is rejected without a verify). */
[[nodiscard]] int64_t SchemeSigOpCost(SigScheme s);

/** A reference to a CPubKey: the Hash160 of the public key. */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    explicit CKeyID(const uint160& in) : uint160(in) {}
};

/** An encapsulated public key. The bytes are the scheme's own key and nothing
 *  else; which scheme that is follows from the length. */
class CPubKey
{
public:
    //! Largest public key of any implemented scheme (ML-DSA-44's 1312). A bound
    //! for deserialization, not the size of every key.
    static constexpr unsigned int SIZE = 1312;

private:
    //! The public key bytes. Empty == invalid.
    std::vector<unsigned char> vch;

    //! Set this key to be invalid.
    void Invalidate() { vch.clear(); }

public:
    //! Whether a byte vector is the right length for some implemented scheme.
    static bool ValidSize(const std::vector<unsigned char>& vch)
    {
        return SchemeFromPubKeySize(vch.size()).has_value();
    }

    //! Construct an invalid public key.
    CPubKey() { Invalidate(); }

    //! Initialize from begin/end iterators over the public key bytes.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        if (SchemeFromPubKeySize(static_cast<size_t>(pend - pbegin))) {
            vch.assign(pbegin, pend);
        } else {
            Invalidate();
        }
    }

    //! Construct from begin/end iterators over the serialized bytes.
    template <typename T>
    CPubKey(const T pbegin, const T pend) { Set(pbegin, pend); }

    //! Construct from a public key byte span.
    explicit CPubKey(std::span<const unsigned char> _vch) { Set(_vch.begin(), _vch.end()); }

    //! Construct a key of a named scheme. The scheme is only checked against the
    //! length here; it is not stored, because the length is what carries it.
    CPubKey(SigScheme scheme, std::span<const unsigned char> rawkey)
    {
        if (rawkey.size() == SchemePublicKeySize(scheme)) {
            Set(rawkey.begin(), rawkey.end());
        } else {
            Invalidate();
        }
    }

    //! Simple read-only vector-like interface to the serialized data.
    unsigned int size() const { return static_cast<unsigned int>(vch.size()); }
    const unsigned char* data() const { return vch.data(); }
    const unsigned char* begin() const { return vch.data(); }
    const unsigned char* end() const { return vch.data() + vch.size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! The scheme, read off the length. Meaningful only for a valid key.
    SigScheme GetScheme() const { return *SchemeFromPubKeySize(vch.size()); }

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

    //! Get the KeyID of this public key (its Hash160).
    CKeyID GetID() const
    {
        return CKeyID(Hash160(std::span{vch.data(), size()}));
    }

    //! Get the 256-bit hash of this public key.
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
