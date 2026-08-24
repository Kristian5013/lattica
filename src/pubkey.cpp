// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Verification for the three schemes, and the curve operations Taproot needs.
//
// Every entry point that has to know which scheme it is holding switches on
// size(): the length names the scheme, and the three lengths are pairwise
// distinct (see pubkey.h). The secp256k1 arms are Bitcoin's own code, vendored
// libsecp256k1 and all; the lattice arms hand the bytes to PQClean, which
// enforces its own lengths internally.

#include <pubkey.h>

#include <crypto/common.h>
#include <hash.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <span.h>
#include <uint256.h>
#include <util/strencodings.h>

extern "C" {
// ML-DSA-44 (PQClean). Reached through the vendored api.h, which is the one on
// this target's include path.
#include "api.h"

// Falcon-512 (PQClean falcon-padded-512). Declared rather than included, for
// the reason crypto/mlkem.cpp gives: three PQClean trees ship an "api.h", so a
// quoted include would resolve by link order.
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
    const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
}

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

using namespace util::hex_literals;

namespace {

struct Secp256k1SelfTester
{
    Secp256k1SelfTester() {
        /* Run libsecp256k1 self-test before using the secp256k1_context_static. */
        secp256k1_selftest();
    }
} SECP256K1_SELFTESTER;

} // namespace

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
int ecdsa_signature_parse_der_lax(secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, sig, tmpsig);
    }
    return 1;
}

// The vendored constants and the ones this class advertises must agree, or a
// key would be accepted at one length and verified at another.
static_assert(CPubKey::MLDSA44_SIZE == PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
              "ML-DSA-44 public key size disagrees with the vendored library");
static_assert(CPubKey::MLDSA44_SIGNATURE_SIZE == PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
              "ML-DSA-44 signature size disagrees with the vendored library");

/** Nothing Up My Sleeve (NUMS) point
 *
 *  NUMS_H is a point with an unknown discrete logarithm, constructed by taking the sha256 of 'g'
 *  (uncompressed encoding), which happens to be a point on the curve.
 *
 *  For an example script for calculating H, refer to the unit tests in
 *  ./test/functional/test_framework/crypto/secp256k1.py
 */
constexpr XOnlyPubKey XOnlyPubKey::NUMS_H{
    // Use immediate lambda to work around GCC-14 bug https://gcc.gnu.org/bugzilla/show_bug.cgi?id=117966
    []() consteval { return XOnlyPubKey{"50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"_hex_u8}; }(),
};

std::vector<CPubKey> XOnlyPubKey::GetCPubKeys() const
{
    std::vector<CPubKey> out;
    unsigned char b[33] = {0x02};
    std::copy(m_keydata.begin(), m_keydata.end(), b + 1);
    CPubKey fullpubkey;
    fullpubkey.Set(b, b + 33);
    out.push_back(fullpubkey);
    b[0] = 0x03;
    fullpubkey.Set(b, b + 33);
    out.push_back(fullpubkey);
    return out;
}

std::vector<CKeyID> XOnlyPubKey::GetKeyIDs() const
{
    std::vector<CKeyID> out;
    for (const CPubKey& pk : GetCPubKeys()) {
        out.push_back(pk.GetID());
    }
    return out;
}

CPubKey XOnlyPubKey::GetEvenCorrespondingCPubKey() const
{
    unsigned char full_key[CPubKey::SECP256K1_SIZE] = {0x02};
    std::copy(begin(), end(), full_key + 1);
    return CPubKey{full_key};
}

bool XOnlyPubKey::IsFullyValid() const
{
    secp256k1_xonly_pubkey pubkey;
    return secp256k1_xonly_pubkey_parse(secp256k1_context_static, &pubkey, m_keydata.data());
}

bool XOnlyPubKey::VerifySchnorr(const uint256& msg, std::span<const unsigned char> sigbytes) const
{
    assert(sigbytes.size() == 64);
    secp256k1_xonly_pubkey pubkey;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &pubkey, m_keydata.data())) return false;
    return secp256k1_schnorrsig_verify(secp256k1_context_static, sigbytes.data(), msg.begin(), 32, &pubkey);
}

static const HashWriter HASHER_TAPTWEAK{TaggedHash("TapTweak")};

uint256 XOnlyPubKey::ComputeTapTweakHash(const uint256* merkle_root) const
{
    if (merkle_root == nullptr) {
        // We have no scripts. The actual tweak does not matter, but follow BIP341 here to
        // allow for reproducible tweaking.
        return (HashWriter{HASHER_TAPTWEAK} << m_keydata).GetSHA256();
    } else {
        return (HashWriter{HASHER_TAPTWEAK} << m_keydata << *merkle_root).GetSHA256();
    }
}

bool XOnlyPubKey::CheckTapTweak(const XOnlyPubKey& internal, const uint256& merkle_root, bool parity) const
{
    secp256k1_xonly_pubkey internal_key;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &internal_key, internal.data())) return false;
    uint256 tweak = internal.ComputeTapTweakHash(&merkle_root);
    return secp256k1_xonly_pubkey_tweak_add_check(secp256k1_context_static, m_keydata.begin(), parity, &internal_key, tweak.begin());
}

std::optional<std::pair<XOnlyPubKey, bool>> XOnlyPubKey::CreateTapTweak(const uint256* merkle_root) const
{
    secp256k1_xonly_pubkey base_point;
    if (!secp256k1_xonly_pubkey_parse(secp256k1_context_static, &base_point, data())) return std::nullopt;
    secp256k1_pubkey out;
    uint256 tweak = ComputeTapTweakHash(merkle_root);
    if (!secp256k1_xonly_pubkey_tweak_add(secp256k1_context_static, &out, &base_point, tweak.data())) return std::nullopt;
    int parity = -1;
    std::pair<XOnlyPubKey, bool> ret;
    secp256k1_xonly_pubkey out_xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_static, &out_xonly, &parity, &out)) return std::nullopt;
    secp256k1_xonly_pubkey_serialize(secp256k1_context_static, ret.first.begin(), &out_xonly);
    assert(parity == 0 || parity == 1);
    ret.second = parity;
    return ret;
}


bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    switch (size()) {
    case MLDSA44_SIZE:
        // PQClean enforces the exact signature length internally and returns 0
        // on a valid signature.
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
                   vchSig.data(), vchSig.size(), hash.begin(), hash.size(), data()) == 0;
    case FALCON512_SIZE:
        // Likewise, and the padded variant accepts only its own fixed length,
        // which the vendored library's own test pins.
        return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                   vchSig.data(), vchSig.size(), hash.begin(), hash.size(), data()) == 0;
    case SECP256K1_SIZE: {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, data(), size())) {
            return false;
        }
        if (!ecdsa_signature_parse_der_lax(&sig, vchSig.data(), vchSig.size())) {
            return false;
        }
        /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
         * not historically been enforced in Bitcoin, so normalize them first. */
        secp256k1_ecdsa_signature_normalize(secp256k1_context_static, &sig, &sig);
        return secp256k1_ecdsa_verify(secp256k1_context_static, &sig, hash.begin(), &pubkey);
    }
    }
    return false;
}

bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() != SECP256K1_COMPACT_SIGNATURE_SIZE)
        return false;
    int recid = (vchSig[0] - 27) & 3;
    bool fComp = ((vchSig[0] - 27) & 4) != 0;
    // The header byte also says whether the signer used an uncompressed key,
    // and this chain has no uncompressed form: ValidSize admits 33, 897 and
    // 1312, so a 65-byte serialization could not become a CPubKey even if it
    // were produced. Bitcoin gives the buffer below its own SIZE, which is the
    // uncompressed 65; SIZE here is ML-DSA-44's 1312 and the buffer is the
    // curve's 33, so asking libsecp256k1 for the uncompressed form asks it to
    // write 65 bytes into 33 -- which it answers by calling its illegal-argument
    // callback, and that aborts the process. A recovery that names no key this
    // chain can hold is refused before it can do that.
    if (!fComp) return false;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_static, &sig, &vchSig[1], recid)) {
        return false;
    }
    if (!secp256k1_ecdsa_recover(secp256k1_context_static, &pubkey, &sig, hash.begin())) {
        return false;
    }
    unsigned char pub[SECP256K1_SIZE];
    size_t publen = SECP256K1_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, pub, &publen, &pubkey, fComp ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    Set(pub, pub + publen);
    return true;
}

bool CPubKey::IsFullyValid() const {
    switch (size()) {
    case SECP256K1_SIZE: {
        secp256k1_pubkey pubkey;
        return secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, data(), size());
    }
    case FALCON512_SIZE:
        // As far as the public API goes. The header byte carries the degree as
        // 0x00 | logn, so n = 512 is 0x09; whether every coefficient is below q
        // is decided by PQClean's decoder, which is not exposed.
        return data()[0] == 0x09;
    case MLDSA44_SIZE:
        // Any MLDSA44_SIZE bytes unpack to some (rho, t1), so the length is the
        // whole of the check and it has already been made.
        return true;
    }
    return false;
}

unsigned int CPubKey::SignatureSize() const {
    switch (size()) {
    case SECP256K1_SIZE: return SECP256K1_SIGNATURE_SIZE;
    case FALCON512_SIZE: return FALCON512_SIGNATURE_SIZE;
    case MLDSA44_SIZE:   return MLDSA44_SIGNATURE_SIZE;
    }
    return 0;
}

bool CPubKey::Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc, uint256* bip32_tweak_out) const {
    assert(IsValid());
    assert((nChild >> 31) == 0);
    assert(size() == SECP256K1_SIZE);
    unsigned char out[64];
    BIP32Hash(cc, nChild, *begin(), begin()+1, out);
    memcpy(ccChild.begin(), out+32, 32);
    if (bip32_tweak_out) {
        memcpy(bip32_tweak_out->begin(), out, 32);
    }
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, data(), size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &pubkey, out)) {
        return false;
    }
    unsigned char pub[SECP256K1_SIZE];
    size_t publen = SECP256K1_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, pub, &publen, &pubkey, SECP256K1_EC_COMPRESSED);
    pubkeyChild.Set(pub, pub + publen);
    return true;
}

void CExtPubKey::Encode(std::span<unsigned char> code) const {
    assert(code.size() == GetSerializedSize());
    code[0] = nDepth;
    std::ranges::copy(fingerprint, code.data() + 1);
    WriteBE32(code.data() + 5, nChild);
    memcpy(code.data() + 9, chaincode.begin(), 32);
    memcpy(code.data() + HEADER_SIZE, pubkey.begin(), pubkey.size());
}

bool CExtPubKey::Decode(std::span<const unsigned char> code) {
    // Everything past the header is the key, and only three lengths are keys, so
    // the size of what was handed over decides the scheme. Core reads a fixed 33
    // bytes and cannot be given the wrong length in the first place.
    if (code.size() <= HEADER_SIZE) {
        pubkey = CPubKey();
        return false;
    }
    nDepth = code[0];
    std::copy_n(code.data() + 1, fingerprint.size(), fingerprint.begin());
    nChild = ReadBE32(code.data() + 5);
    memcpy(chaincode.begin(), code.data() + 9, 32);
    pubkey.Set(code.data() + HEADER_SIZE, code.data() + code.size());
    if ((nDepth == 0 && (nChild != 0 || ReadLE32(fingerprint.data()) != 0)) || !pubkey.IsFullyValid()) {
        pubkey = CPubKey();
        return false;
    }
    return true;
}

void CExtPubKey::EncodeWithVersion(std::span<unsigned char> code) const
{
    assert(code.size() == GetSerializedSizeWithVersion());
    memcpy(code.data(), version, 4);
    Encode(code.subspan(4));
}

bool CExtPubKey::DecodeWithVersion(std::span<const unsigned char> code)
{
    if (code.size() <= 4) {
        pubkey = CPubKey();
        return false;
    }
    memcpy(version, code.data(), 4);
    return Decode(code.subspan(4));
}

//! BIP32 public derivation: tweak the point by a hash of the chain code, the
//! child number and the key. It is BIP328's, and the MuSig2 synthetic xpub is
//! what it is here for.
//!
//! It is NOT the inverse of CExtKey::Derive. That one puts the parent's secret
//! node seed in the child's preimage — for every scheme, secp256k1 included —
//! so a node's public half cannot continue the tree, and
//!
//!     xprv.Neuter().Derive(i)  !=  xprv.Derive(i).Neuter()
//!
//! Deriving addresses from an extended key therefore always needs the secret;
//! a watch-only wallet works from a cache of already-derived public keys, not
//! from an xpub. test_hdkey pins this.
bool CExtPubKey::Derive(CExtPubKey &out, unsigned int _nChild, uint256* bip32_tweak_out) const {
    if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
    out.nDepth = nDepth + 1;
    out.fingerprint = id_key_fingerprint();
    out.nChild = _nChild;
    return pubkey.Derive(out.pubkey, out.chaincode, _nChild, chaincode, bip32_tweak_out);
}

/* static */ bool CPubKey::CheckLowS(const std::vector<unsigned char>& vchSig) {
    secp256k1_ecdsa_signature sig;
    if (!ecdsa_signature_parse_der_lax(&sig, vchSig.data(), vchSig.size())) {
        return false;
    }
    return (!secp256k1_ecdsa_signature_normalize(secp256k1_context_static, nullptr, &sig));
}
