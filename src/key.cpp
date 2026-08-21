// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <key.h>

#include <crypto/common.h>
#include <crypto/sha3_512.h>
#include <hash.h>
#include <random.h>
#include <support/allocators/secure.h>
#include <support/cleanse.h>
#include <util/check.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>

extern "C" {
// ML-DSA-44 (PQClean). Reached through the vendored api.h, which is the one on
// this target's include path.
#include "api.h"
#include "randombytes.h"

// Falcon-512 (PQClean falcon-padded-512). Declared rather than included: three
// PQClean trees ship an "api.h", so which one a quoted include resolves to would
// depend on link order. crypto/mlkem.cpp established this approach.
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(uint8_t* pk, uint8_t* sk);
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
    uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
}

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

static secp256k1_context* secp256k1_context_sign = nullptr;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */

/**
 * This parses a format loosely based on a DER encoding of the ECPrivateKey type from
 * section C.4 of SEC 1 <https://www.secg.org/sec1-v2.pdf>, with the following caveats:
 *
 * * The octet-length of the SEQUENCE must be encoded as 1 or 2 octets. It is not
 *   required to be encoded as one octet if it is less than 256, as DER would require.
 * * The octet-length of the SEQUENCE must not be greater than the remaining
 *   length of the key encoding, but need not match it (i.e. the encoding may contain
 *   junk after the encoded SEQUENCE).
 * * The privateKey OCTET STRING is zero-filled on the left to 32 octets.
 * * Anything after the encoding of the privateKey OCTET STRING is ignored, whether
 *   or not it is validly encoded DER.
 *
 * out32 must point to an output buffer of length at least 32 bytes.
 */
int ec_seckey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *seckey, size_t seckeylen) {
    const unsigned char *end = seckey + seckeylen;
    memset(out32, 0, 32);
    /* sequence header */
    if (end - seckey < 1 || *seckey != 0x30u) {
        return 0;
    }
    seckey++;
    /* sequence length constructor */
    if (end - seckey < 1 || !(*seckey & 0x80u)) {
        return 0;
    }
    ptrdiff_t lenb = *seckey & ~0x80u; seckey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end - seckey < lenb) {
        return 0;
    }
    /* sequence length */
    ptrdiff_t len = seckey[lenb-1] | (lenb > 1 ? seckey[lenb-2] << 8 : 0u);
    seckey += lenb;
    if (end - seckey < len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end - seckey < 3 || seckey[0] != 0x02u || seckey[1] != 0x01u || seckey[2] != 0x01u) {
        return 0;
    }
    seckey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end - seckey < 2 || seckey[0] != 0x04u) {
        return 0;
    }
    ptrdiff_t oslen = seckey[1];
    seckey += 2;
    if (oslen > 32 || end - seckey < oslen) {
        return 0;
    }
    memcpy(out32 + (32 - oslen), seckey, oslen);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

/**
 * This serializes to a DER encoding of the ECPrivateKey type from section C.4 of SEC 1
 * <https://www.secg.org/sec1-v2.pdf>. The optional parameters and publicKey fields are
 * included.
 *
 * seckey must point to an output buffer of length at least CKey::DER_SIZE bytes.
 * seckeylen must initially be set to the size of the seckey buffer. Upon return it
 * will be set to the number of bytes used in the buffer.
 * key32 must point to a 32-byte raw private key.
 */
int ec_seckey_export_der(const secp256k1_context *ctx, unsigned char *seckey, size_t *seckeylen, const unsigned char *key32, bool compressed) {
    assert(*seckeylen >= CKey::DER_SIZE);
    secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        *seckeylen = 0;
        return 0;
    }
    if (compressed) {
        static const unsigned char begin[] = {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };
        unsigned char *ptr = seckey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::SECP256K1_SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        ptr += pubkeylen;
        *seckeylen = ptr - seckey;
        assert(*seckeylen == CKey::DER_COMPRESSED_SIZE);
    } else {
        static const unsigned char begin[] = {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };
        unsigned char *ptr = seckey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = CPubKey::SECP256K1_SIZE;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ptr += pubkeylen;
        *seckeylen = ptr - seckey;
        assert(*seckeylen == CKey::DER_SIZE);
    }
    return 1;
}

/** These are what a second and a third scheme need where Core needs nothing:
 *  the signing context by name, secp256k1 public key derivation, and the entropy
 *  seam the two PQClean keygens are driven through. */

namespace {

const secp256k1_context* SigningContext()
{
    secp256k1_context* ctx = secp256k1_context_sign;
    assert(ctx != nullptr &&
           "an ECC_Context must be alive before generating or signing with a secp256k1 key");
    return ctx;
}

std::array<unsigned char, CPubKey::SECP256K1_SIZE> SerializeCompressed(const secp256k1_pubkey& pubkey)
{
    std::array<unsigned char, CPubKey::SECP256K1_SIZE> out;
    size_t len = out.size();
    int ret = secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(ret);
    assert(len == out.size());
    return out;
}

bool DeriveSecpPubKey(const unsigned char* seckey, std::array<unsigned char, CPubKey::SECP256K1_SIZE>& out)
{
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(SigningContext(), &pubkey, seckey)) return false;
    out = SerializeCompressed(pubkey);
    return true;
}

/** Run an UNMODIFIED PQClean keypair with the shared randombytes seam pinned to
 *  `seed`. Clearing it again is load-bearing: Falcon draws its per-signature salt
 *  from the same seam, and a salt fixed by a leftover seed would be a weakening. */
template <typename KeypairFn>
int SeededKeypair(const unsigned char* seed, KeypairFn&& keypair)
{
    mldsa_set_deterministic_seed(seed);
    const int ret = keypair();
    mldsa_clear_deterministic_seed();
    return ret;
}

} // namespace

unsigned int CKey::SecretSizeForPubKey(unsigned int pubkey_size) {
    switch (pubkey_size) {
    case CPubKey::SECP256K1_SIZE: return SECP256K1_SIZE;
    case CPubKey::FALCON512_SIZE: return FALCON512_SIZE;
    case CPubKey::MLDSA44_SIZE:   return MLDSA44_SIZE;
    }
    return 0;
}

void CKey::MakeKeyData(unsigned int secret_size) {
    if (!ValidSize(secret_size)) {
        ClearKeyData();
        return;
    }
    if (!m_keydata) m_keydata = make_secure_unique<KeyVariant>();
    switch (secret_size) {
    case SECP256K1_SIZE: m_keydata->emplace<SecpKey>(); break;
    case FALCON512_SIZE: m_keydata->emplace<FalconKey>(); break;
    case MLDSA44_SIZE:   m_keydata->emplace<MLDSAKey>(); break;
    }
}

unsigned char* CKey::MutableData() {
    assert(m_keydata);
    return std::visit([](auto& k) { return k.data(); }, *m_keydata);
}

unsigned int CKey::size() const {
    if (!m_keydata) return 0;
    return std::visit([](const auto& k) { return static_cast<unsigned int>(k.size()); }, *m_keydata);
}

const unsigned char* CKey::data() const {
    if (!m_keydata) return nullptr;
    return std::visit([](const auto& k) -> const unsigned char* { return k.data(); }, *m_keydata);
}

bool CKey::Check(unsigned int secret_size, const unsigned char *vch) {
    if (vch == nullptr) return false;
    switch (secret_size) {
    case SECP256K1_SIZE:
        return secp256k1_ec_seckey_verify(secp256k1_context_static, vch);
    case FALCON512_SIZE:
    case MLDSA44_SIZE:
        // No cheap predicate for either; VerifyPubKey establishes the rest.
        return true;
    }
    return false;
}

void CKey::MakeNewKey(unsigned int secret_size) {
    MakeKeyData(secret_size);
    if (!m_keydata) return;
    switch (secret_size) {
    case SECP256K1_SIZE: {
        do {
            GetStrongRandBytes(std::span{MutableData(), size()});
        } while (!Check(secret_size, data()));
        std::array<unsigned char, CPubKey::SECP256K1_SIZE> pk;
        bool ret = DeriveSecpPubKey(data(), pk);
        assert(ret);
        m_pubkey = CPubKey(pk);
        break;
    }
    case FALCON512_SIZE: {
        std::array<unsigned char, CPubKey::FALCON512_SIZE> pk;
        int ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk.data(), MutableData());
        assert(ret == 0);
        m_pubkey = CPubKey(pk);
        break;
    }
    case MLDSA44_SIZE: {
        std::array<unsigned char, CPubKey::MLDSA44_SIZE> pk;
        int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), MutableData());
        assert(ret == 0);
        m_pubkey = CPubKey(pk);
        break;
    }
    }
    assert(m_pubkey.IsValid());
}

bool CKey::MakeKeyFromSeed(unsigned int secret_size, std::span<const unsigned char> seed) {
    if (seed.size() != SEED_SIZE) {
        ClearKeyData();
        return false;
    }
    MakeKeyData(secret_size);
    if (!m_keydata) return false;
    switch (secret_size) {
    case SECP256K1_SIZE: {
        // The seed is the scalar; one in ~2^128 is out of range and has no key.
        if (!Check(secret_size, seed.data())) {
            ClearKeyData();
            return false;
        }
        memcpy(MutableData(), seed.data(), seed.size());
        std::array<unsigned char, CPubKey::SECP256K1_SIZE> pk;
        if (!DeriveSecpPubKey(data(), pk)) {
            ClearKeyData();
            return false;
        }
        m_pubkey = CPubKey(pk);
        break;
    }
    case FALCON512_SIZE: {
        std::array<unsigned char, CPubKey::FALCON512_SIZE> pk;
        unsigned char* sk = MutableData();
        int ret = SeededKeypair(seed.data(), [&] {
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk.data(), sk);
        });
        if (ret != 0) {
            ClearKeyData();
            return false;
        }
        m_pubkey = CPubKey(pk);
        break;
    }
    case MLDSA44_SIZE: {
        std::array<unsigned char, CPubKey::MLDSA44_SIZE> pk;
        unsigned char* sk = MutableData();
        int ret = SeededKeypair(seed.data(), [&] {
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), sk);
        });
        if (ret != 0) {
            ClearKeyData();
            return false;
        }
        m_pubkey = CPubKey(pk);
        break;
    }
    }
    return m_pubkey.IsValid();
}

CPrivKey CKey::GetPrivKey() const {
    assert(m_keydata);
    if (size() != SECP256K1_SIZE) {
        // A lattice secret has no DER encoding; CPrivKey is the secret itself.
        return CPrivKey(data(), data() + size());
    }
    CPrivKey seckey;
    int ret;
    size_t seckeylen;
    seckey.resize(DER_SIZE);
    seckeylen = DER_SIZE;
    ret = ec_seckey_export_der(SigningContext(), seckey.data(), &seckeylen, data(), /*compressed=*/true);
    assert(ret);
    seckey.resize(seckeylen);
    return seckey;
}

CPubKey CKey::GetPubKey() const {
    assert(m_keydata);
    assert(m_pubkey.IsValid());
    return m_pubkey;
}

// Check that the sig has a low R value and will be less than 71 bytes
bool SigHasLowR(const secp256k1_ecdsa_signature* sig)
{
    unsigned char compact_sig[64];
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static, compact_sig, sig);

    // In DER serialization, all values are interpreted as big-endian, signed integers. The highest bit in the integer indicates
    // its signed-ness; 0 is positive, 1 is negative. When the value is interpreted as a negative integer, it must be converted
    // to a positive value by prepending a 0x00 byte so that the highest bit is 0. We can avoid this prepending by ensuring that
    // our highest bit is always 0, and thus we must check that the first byte is less than 0x80.
    return compact_sig[0] < 0x80;
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) const {
    if (!m_keydata)
        return false;
    switch (size()) {
    case SECP256K1_SIZE: {
        vchSig.resize(CPubKey::SECP256K1_SIGNATURE_SIZE);
        size_t nSigLen = CPubKey::SECP256K1_SIGNATURE_SIZE;
        unsigned char extra_entropy[32] = {0};
        WriteLE32(extra_entropy, test_case);
        secp256k1_ecdsa_signature sig;
        uint32_t counter = 0;
        int ret = secp256k1_ecdsa_sign(SigningContext(), &sig, hash.begin(), data(), secp256k1_nonce_function_rfc6979, (!grind && test_case) ? extra_entropy : nullptr);

        // Grind for low R
        while (ret && !SigHasLowR(&sig) && grind) {
            WriteLE32(extra_entropy, ++counter);
            ret = secp256k1_ecdsa_sign(SigningContext(), &sig, hash.begin(), data(), secp256k1_nonce_function_rfc6979, extra_entropy);
        }
        assert(ret);
        secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static, vchSig.data(), &nSigLen, &sig);
        vchSig.resize(nSigLen);
        break;
    }
    case FALCON512_SIZE: {
        // Randomized: a fresh salt per signature, so two over one message differ.
        vchSig.resize(CPubKey::FALCON512_SIGNATURE_SIZE);
        size_t nSigLen = 0;
        int ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(vchSig.data(), &nSigLen, hash.begin(), hash.size(), data());
        if (ret != 0 || nSigLen != vchSig.size()) {
            // The padded variant is fixed-length; a short one means the wrong sources.
            vchSig.clear();
            return false;
        }
        break;
    }
    case MLDSA44_SIZE: {
        vchSig.resize(CPubKey::MLDSA44_SIGNATURE_SIZE);
        size_t nSigLen = 0;
        int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(vchSig.data(), &nSigLen, hash.begin(), hash.size(), data());
        if (ret != 0) {
            vchSig.clear();
            return false;
        }
        vchSig.resize(nSigLen);
        break;
    }
    default:
        return false;
    }
    // Additional verification step to prevent using a potentially corrupted signature
    if (!m_pubkey.Verify(hash, vchSig)) {
        vchSig.clear();
        return false;
    }
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    if (SecretSizeForPubKey(pubkey.size()) != size()) {
        return false;
    }
    if (size() == SECP256K1_SIZE) {
        std::array<unsigned char, CPubKey::SECP256K1_SIZE> pk;
        if (!DeriveSecpPubKey(data(), pk)) return false;
        return memcmp(pk.data(), pubkey.data(), pk.size()) == 0;
    }
    // A lattice key hands nothing back, so prove the pairing instead.
    unsigned char rnd[8];
    std::string str = "Lattica key verification\n";
    GetRandBytes(rnd);
    uint256 hash{Hash(str, rnd)};
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (size() != SECP256K1_SIZE)
        return false;
    vchSig.resize(CPubKey::SECP256K1_COMPACT_SIGNATURE_SIZE);
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature rsig;
    int ret = secp256k1_ecdsa_sign_recoverable(SigningContext(), &rsig, hash.begin(), data(), secp256k1_nonce_function_rfc6979, nullptr);
    assert(ret);
    ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_static, &vchSig[1], &rec, &rsig);
    assert(ret);
    assert(rec != -1);
    // Core adds 4 for a compressed key. Every secp256k1 key here is compressed.
    vchSig[0] = 27 + rec + 4;
    // Additional verification step to prevent using a potentially corrupted signature
    secp256k1_pubkey epk, rpk;
    ret = secp256k1_ec_pubkey_create(SigningContext(), &epk, data());
    assert(ret);
    ret = secp256k1_ecdsa_recover(secp256k1_context_static, &rpk, &rsig, hash.begin());
    assert(ret);
    ret = secp256k1_ec_pubkey_cmp(secp256k1_context_static, &epk, &rpk);
    assert(ret == 0);
    return true;
}

bool CKey::SignSchnorr(const uint256& hash, std::span<unsigned char> sig, const uint256* merkle_root, const uint256& aux) const
{
    KeyPair kp = ComputeKeyPair(merkle_root);
    return kp.SignSchnorr(hash, sig, aux);
}

bool CKey::Load(const CPrivKey &seckey, const CPubKey &vchPubKey, bool fSkipCheck) {
    // The scheme comes from the public key, which is also why one must be given.
    if (!vchPubKey.IsValid()) return false;
    unsigned int secret_size = SecretSizeForPubKey(vchPubKey.size());
    if (secret_size == 0) return false;
    MakeKeyData(secret_size);
    if (!m_keydata) return false;
    if (secret_size == SECP256K1_SIZE) {
        if (!ec_seckey_import_der(secp256k1_context_static, MutableData(), seckey.data(), seckey.size())) {
            ClearKeyData();
            return false;
        }
    } else {
        // A lattice CPrivKey is the secret itself, so there is nothing to parse.
        if (seckey.size() != secret_size || !Check(secret_size, seckey.data())) {
            ClearKeyData();
            return false;
        }
        memcpy(MutableData(), seckey.data(), seckey.size());
    }
    m_pubkey = vchPubKey;

    if (fSkipCheck)
        return true;

    if (!VerifyPubKey(vchPubKey)) {
        ClearKeyData();
        return false;
    }
    return true;
}

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    assert(IsCompressed());
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.size() == CPubKey::SECP256K1_SIZE);
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        assert(size() == 32);
        BIP32Hash(cc, nChild, 0, data(), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    keyChild.MakeKeyData(SECP256K1_SIZE);
    if (!keyChild.m_keydata) return false;
    memcpy(keyChild.MutableData(), data(), 32);
    bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_context_static, keyChild.MutableData(), vout.data());
    if (!ret) {
        keyChild.ClearKeyData();
        return false;
    }
    // Core recomputes the child public key on demand; here it is stored, so the
    // tweaked secret has to hand its own back before the child is valid.
    std::array<unsigned char, CPubKey::SECP256K1_SIZE> pk;
    if (!DeriveSecpPubKey(keyChild.data(), pk)) {
        keyChild.ClearKeyData();
        return false;
    }
    keyChild.m_pubkey = CPubKey(pk);
    return true;
}

KeyPair CKey::ComputeKeyPair(const uint256* merkle_root) const
{
    return KeyPair(*this, merkle_root);
}

CKey GenerateRandomKey(unsigned int secret_size) noexcept
{
    CKey key;
    key.MakeNewKey(/*secret_size=*/secret_size);
    return key;
}

/* CExtKey is hardened-only and still ML-DSA-only. Core chains the secret itself,
   which only a scalar allows; here the chained thing is the 32-byte node seed. */

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    if (nDepth == std::numeric_limits<unsigned char>::max()) return false;
    if (!key.IsValid()) return false;
    out.nDepth = nDepth + 1;
    out.fingerprint = id_key_fingerprint();
    out.nChild = _nChild;
    // Hardened-only: the parent's secret node seed is always in the preimage.
    unsigned char data[32 + CKey::SEED_SIZE + 4];
    memcpy(data, chaincode.begin(), 32);
    memcpy(data + 32, nodeseed.begin(), CKey::SEED_SIZE);
    WriteBE32(data + 32 + CKey::SEED_SIZE, _nChild);
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    SHA3_512().Write(data, sizeof(data)).Finalize(vout.data());
    out.nodeseed = uint256(std::span{vout.data(), CKey::SEED_SIZE});
    memcpy(out.chaincode.begin(), vout.data() + 32, 32);
    return out.key.MakeKeyFromSeed(CKey::MLDSA44_SIZE, std::span{out.nodeseed.begin(), CKey::SEED_SIZE});
}

std::optional<std::pair<CExtKey, KeyOriginInfo>> DeriveExtKey(const CExtKey& ext_key, const std::vector<uint32_t>& path)
{
    CExtKey descendant = ext_key;
    KeyOriginInfo origin;
    // KeyOriginInfo here still carries raw bytes, the older Core shape.
    const KeyFingerprint fingerprint = ext_key.id_key_fingerprint();
    std::copy(fingerprint.begin(), fingerprint.end(), origin.fingerprint);
    origin.path = path;
    for (uint32_t i : path) {
        if (!descendant.Derive(descendant, i)) return std::nullopt;
    }
    return std::make_pair(descendant, origin);
}

void CExtKey::SetSeedFromTag(std::span<const unsigned char> seed, const unsigned char* tag, size_t taglen)
{
    Assert(16 <= seed.size() && seed.size() <= 64);
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    SHA3_512().Write(tag, taglen).Write(seed.data(), seed.size()).Finalize(vout.data());
    nodeseed = uint256(std::span{vout.data(), CKey::SEED_SIZE});
    key.MakeKeyFromSeed(CKey::MLDSA44_SIZE, std::span{nodeseed.begin(), CKey::SEED_SIZE});
    memcpy(chaincode.begin(), vout.data() + 32, 32);
    nDepth = 0;
    nChild = 0;
    fingerprint.fill(0);
}

void CExtKey::SetSeed(std::span<const unsigned char> seed)
{
    // Part of the derivation: changing it invalidates every wallet derived before.
    static const unsigned char hashkey[] = {'L','a','t','t','i','c','a',' ','H','D',' ','m','a','s','t','e','r'};
    SetSeedFromTag(seed, hashkey, sizeof(hashkey));
}

CExtPubKey CExtKey::Neuter() const {
    // secp256k1's: CExtPubKey carries a 33-byte key, and public derivation is
    // the scalar homomorphism a lattice scheme does not have.
    assert(key.size() == CKey::SECP256K1_SIZE);
    CExtPubKey ret;
    ret.nDepth = nDepth;
    ret.fingerprint = fingerprint;
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[SIZE]) const {
    code[0] = nDepth;
    std::ranges::copy(fingerprint, code+1);
    WriteBE32(code+5, nChild);
    memcpy(code+9, chaincode.begin(), 32);
    memcpy(code+41, nodeseed.begin(), CKey::SEED_SIZE);
}

void CExtKey::Decode(const unsigned char code[SIZE]) {
    nDepth = code[0];
    std::copy_n(code + 1, fingerprint.size(), fingerprint.begin());
    nChild = ReadBE32(code+5);
    memcpy(chaincode.begin(), code+9, 32);
    nodeseed = uint256(std::span{code + 41, CKey::SEED_SIZE});
    key.MakeKeyFromSeed(CKey::MLDSA44_SIZE, std::span{nodeseed.begin(), CKey::SEED_SIZE});
    if (nDepth == 0 && (nChild != 0 || ReadLE32(fingerprint.data()) != 0)) key = CKey();
}

KeyPair::KeyPair(const CKey& key, const uint256* merkle_root)
{
    static_assert(std::tuple_size<KeyType>() == sizeof(secp256k1_keypair));
    // Checked before libsecp256k1 sees it: 32 bytes out of a lattice secret would
    // pass secp256k1_ec_seckey_verify and give a keypair for a key nobody holds.
    if (key.size() != CKey::SECP256K1_SIZE) return;
    MakeKeyPairData();
    auto keypair = reinterpret_cast<secp256k1_keypair*>(m_keypair->data());
    bool success = secp256k1_keypair_create(secp256k1_context_sign, keypair, key.data());
    if (success && merkle_root) {
        secp256k1_xonly_pubkey pubkey;
        unsigned char pubkey_bytes[32];
        assert(secp256k1_keypair_xonly_pub(secp256k1_context_static, &pubkey, nullptr, keypair));
        assert(secp256k1_xonly_pubkey_serialize(secp256k1_context_static, pubkey_bytes, &pubkey));
        uint256 tweak = XOnlyPubKey(pubkey_bytes).ComputeTapTweakHash(merkle_root->IsNull() ? nullptr : merkle_root);
        success = secp256k1_keypair_xonly_tweak_add(secp256k1_context_static, keypair, tweak.data());
    }
    if (!success) ClearKeyPairData();
}

bool KeyPair::SignSchnorr(const uint256& hash, std::span<unsigned char> sig, const uint256& aux) const
{
    assert(sig.size() == 64);
    if (!IsValid()) return false;
    auto keypair = reinterpret_cast<const secp256k1_keypair*>(m_keypair->data());
    bool ret = secp256k1_schnorrsig_sign32(secp256k1_context_sign, sig.data(), hash.data(), keypair, aux.data());
    if (ret) {
        // Additional verification step to prevent using a potentially corrupted signature
        secp256k1_xonly_pubkey pubkey_verify;
        ret = secp256k1_keypair_xonly_pub(secp256k1_context_static, &pubkey_verify, nullptr, keypair);
        ret &= secp256k1_schnorrsig_verify(secp256k1_context_static, sig.data(), hash.begin(), 32, &pubkey_verify);
    }
    if (!ret) memory_cleanse(sig.data(), sig.size());
    return ret;
}

bool KeyCryptoSanityCheck() {
    for (unsigned int secret_size : {CKey::SECP256K1_SIZE, CKey::FALCON512_SIZE, CKey::MLDSA44_SIZE}) {
        CKey key = GenerateRandomKey(secret_size);
        if (!key.IsValid()) return false;
        CPubKey pubkey = key.GetPubKey();
        if (!pubkey.IsValid() || !pubkey.IsFullyValid()) return false;
        if (!key.VerifyPubKey(pubkey)) return false;
        uint256 hash = GetRandHash();
        std::vector<unsigned char> vchSig;
        if (!key.Sign(hash, vchSig)) return false;
        // A DER signature has an upper bound, not a length; the other two are fixed.
        if (vchSig.size() > pubkey.SignatureSize()) return false;
        if (!pubkey.Verify(hash, vchSig)) return false;
    }
    return true;
}

secp256k1_context* GetSecp256k1SignContext()
{
    return secp256k1_context_sign;
}

/** Initialize the elliptic curve support. May not be called twice without calling ECC_Stop first. */
static void ECC_Start() {
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

/** Deinitialize the elliptic curve support. No-op if ECC_Start wasn't called first. */
static void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}

ECC_Context::ECC_Context()
{
    ECC_Start();
}

ECC_Context::~ECC_Context()
{
    ECC_Stop();
}
