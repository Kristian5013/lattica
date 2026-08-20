// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <key.h>

#include <crypto/sha3_512.h>
#include <hash.h>
#include <random.h>
#include <support/allocators/secure.h>
#include <util/check.h>

#include <secp256k1.h>

extern "C" {
#include "api.h"
#include "randombytes.h"
}

#include <array>
#include <cassert>
#include <span>
#include <string>
#include <vector>

namespace {
/**
 * The secp256k1 signing context.
 *
 * Verification needs no context state at all — CPubKey::Verify uses
 * secp256k1_context_static, so consensus code stays free of global setup. But
 * secp256k1_ec_pubkey_create and secp256k1_ecdsa_sign explicitly refuse the
 * static context, so key generation and signing need a real one.
 *
 * Core solves this with an ECC_Context RAII object built in init and in every
 * test fixture. That shape does not fit here: each of the fifty-odd test
 * binaries has its own main(), and threading an init through all of them buys
 * nothing but the chance to forget one. A function-local static is initialized
 * thread-safely on first use and cannot be skipped; the trade is that there is
 * no explicit teardown, which matters only for leak-checker output.
 */
const secp256k1_context* SigningContext()
{
    static secp256k1_context* const ctx = [] {
        secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        assert(c != nullptr);
        // Blind the context so a side channel cannot recover secrets from the
        // multiplication, exactly as Core does after creating its context.
        std::vector<unsigned char, secure_allocator<unsigned char>> seed(32);
        GetRandBytes(seed);
        const int ok = secp256k1_context_randomize(c, seed.data());
        assert(ok);
        (void)ok;
        return c;
    }();
    return ctx;
}

//! Serialize a secp256k1 public key in compressed form. Serialization takes the
//! static context; only creation needs the signing one.
std::array<unsigned char, 33> SerializeCompressed(const secp256k1_pubkey& pubkey)
{
    std::array<unsigned char, 33> out;
    size_t len = out.size();
    const int ok = secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &len,
                                                 &pubkey, SECP256K1_EC_COMPRESSED);
    assert(ok && len == out.size());
    (void)ok;
    return out;
}
} // namespace

void CKey::MakeKeyData(SigScheme scheme)
{
    if (!IsKnownScheme(scheme)) {
        ClearKeyData();
        return;
    }
    if (!m_keydata) m_keydata = make_secure_unique<KeyVariant>();
    switch (scheme) {
    case SigScheme::SECP256K1:
        m_keydata->emplace<SecpKey>();
        break;
    case SigScheme::ML_DSA_44:
        m_keydata->emplace<MLDSAKey>();
        break;
    }
    m_scheme = scheme;
}

unsigned char* CKey::MutableData()
{
    assert(m_keydata);
    return std::visit([](auto& k) { return k.data(); }, *m_keydata);
}

unsigned int CKey::size() const
{
    if (!m_keydata) return 0;
    return std::visit([](const auto& k) { return static_cast<unsigned int>(k.size()); }, *m_keydata);
}

const unsigned char* CKey::data() const
{
    if (!m_keydata) return nullptr;
    return std::visit([](const auto& k) -> const unsigned char* { return k.data(); }, *m_keydata);
}

bool CKey::Check(SigScheme scheme, const unsigned char* vch)
{
    if (vch == nullptr) return false;
    switch (scheme) {
    case SigScheme::SECP256K1:
        // A real predicate: the scalar must lie in [1, n-1]. Takes the static
        // context — this is arithmetic on the secret, not a multiplication by G.
        return secp256k1_ec_seckey_verify(secp256k1_context_static, vch) == 1;
    case SigScheme::ML_DSA_44:
        // No cheap validity predicate exists. Any buffer of the right length
        // (checked by the caller) is structurally acceptable; semantic validity
        // is what VerifyPubKey's sign+verify round-trip establishes.
        return true;
    }
    return false;
}

void CKey::MakeNewKey(SigScheme scheme)
{
    MakeKeyData(scheme);
    if (!m_keydata) return;

    switch (scheme) {
    case SigScheme::SECP256K1: {
        // Rejection-sample until the scalar is in range. A draw fails with
        // probability around 2^-128, so this never loops in practice; it loops
        // in code because "never in practice" is not "never".
        do {
            GetStrongRandBytes(std::span<unsigned char>(MutableData(), size()));
        } while (!Check(scheme, data()));

        secp256k1_pubkey pubkey;
        const int ok = secp256k1_ec_pubkey_create(SigningContext(), &pubkey, data());
        assert(ok);
        (void)ok;
        m_pubkey = CPubKey(SigScheme::SECP256K1, SerializeCompressed(pubkey));
        assert(m_pubkey.IsValid());
        return;
    }
    case SigScheme::ML_DSA_44: {
        std::array<unsigned char, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES> pk;
        // PQClean draws its own OS entropy (randombytes); on failure it aborts,
        // so a return here is always success. The secret lands directly in the
        // locked buffer; the public key is captured alongside it because it
        // cannot be recomputed.
        const int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), MutableData());
        assert(ret == 0);
        (void)ret;
        m_pubkey = CPubKey(SigScheme::ML_DSA_44, pk);
        assert(m_pubkey.IsValid());
        return;
    }
    }
}

bool CKey::MakeKeyFromSeed(std::span<const unsigned char> seed)
{
    if (seed.size() != SEED_SIZE) {
        ClearKeyData();
        return false;
    }
    MakeKeyData(SigScheme::ML_DSA_44);
    std::array<unsigned char, PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES> pk;
    // Drive the UNMODIFIED crypto_sign_keypair from a fixed seed by switching the
    // ML-DSA entropy source into deterministic mode for the duration of this one
    // call (see randombytes.h). The lattice crypto is byte-for-byte verbatim.
    mldsa_set_deterministic_seed(seed.data());
    const int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), MutableData());
    mldsa_clear_deterministic_seed();
    assert(ret == 0);
    (void)ret;
    m_pubkey = CPubKey(SigScheme::ML_DSA_44, pk);
    return m_pubkey.IsValid();
}

CPrivKey CKey::GetPrivKey() const
{
    assert(m_keydata);
    return CPrivKey(data(), data() + size());
}

bool CKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const
{
    if (!m_keydata) return false;
    switch (m_scheme) {
    case SigScheme::ML_DSA_44: {
        vchSig.resize(SchemeSignatureSize(SigScheme::ML_DSA_44));
        size_t siglen = 0;
        const int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(
            vchSig.data(), &siglen, hash.begin(), hash.size(), data());
        if (ret != 0) {
            vchSig.clear();
            return false;
        }
        vchSig.resize(siglen);
        return true;
    }
    case SigScheme::SECP256K1:
        // Not yet implemented. Signing lands with the wallet changes that follow;
        // failing here rather than asserting keeps a wallet holding a secp key
        // usable for everything except spending from it.
        vchSig.clear();
        return false;
    }
    return false;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const
{
    if (!IsValid() || !pubkey.IsValid()) return false;
    if (pubkey.GetScheme() != m_scheme) return false;

    switch (m_scheme) {
    case SigScheme::SECP256K1: {
        // Derivable, so this is an equality test rather than a proof: recompute
        // the public key and compare.
        secp256k1_pubkey derived;
        if (!secp256k1_ec_pubkey_create(SigningContext(), &derived, data())) return false;
        const auto ser = SerializeCompressed(derived);
        const auto raw = pubkey.RawKey();
        return raw.size() == ser.size() && std::memcmp(ser.data(), raw.data(), ser.size()) == 0;
    }
    case SigScheme::ML_DSA_44: {
        // Not derivable: sign a random challenge and check it verifies under the
        // candidate. That is the available equality test.
        const uint256 hash = GetRandHash();
        std::vector<unsigned char> vchSig;
        if (!Sign(hash, vchSig)) return false;
        return pubkey.Verify(hash, vchSig);
    }
    }
    return false;
}

bool CKey::Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck)
{
    if (!vchPubKey.IsValid()) return false;
    const SigScheme scheme{vchPubKey.GetScheme()};
    if (privkey.size() != SchemeSecretKeySize(scheme)) return false;
    if (fSkipCheck) {
        MakeKeyData(scheme);
        if (!m_keydata) return false;
        std::memcpy(MutableData(), privkey.data(), privkey.size());
        m_pubkey = vchPubKey;
        return true;
    }
    Set(privkey.begin(), privkey.end(), vchPubKey);
    return IsValid();
}

CKey GenerateRandomKey(SigScheme scheme) noexcept
{
    CKey key;
    key.MakeNewKey(scheme);
    return key;
}

bool KeyCryptoSanityCheck()
{
    // ML-DSA-44: full generate / sign / verify round-trip.
    {
        const CKey key = GenerateRandomKey(SigScheme::ML_DSA_44);
        if (!key.IsValid()) return false;
        const CPubKey pubkey = key.GetPubKey();
        if (!pubkey.IsValid() || pubkey.GetScheme() != SigScheme::ML_DSA_44) return false;

        static const std::string test{"Lattica ML-DSA sanity check"};
        const uint256 hash = Hash(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(test.data()), test.size()));
        std::vector<unsigned char> sig;
        if (!key.Sign(hash, sig)) return false;
        if (!pubkey.Verify(hash, sig) || !key.VerifyPubKey(pubkey)) return false;
    }

    // secp256k1: generate, derive, and confirm the serialized key round-trips
    // through the library's own parser. There is no signing to check yet.
    {
        const CKey key = GenerateRandomKey(SigScheme::SECP256K1);
        if (!key.IsValid() || key.size() != SchemeSecretKeySize(SigScheme::SECP256K1)) return false;
        const CPubKey pubkey = key.GetPubKey();
        if (!pubkey.IsValid() || pubkey.GetScheme() != SigScheme::SECP256K1) return false;
        if (!key.VerifyPubKey(pubkey)) return false;

        secp256k1_pubkey parsed;
        if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed,
                                       pubkey.RawKey().data(), pubkey.RawKey().size())) {
            return false;
        }
    }
    return true;
}

// --- CExtKey: hardened-only hierarchical-deterministic derivation ------------

void CExtKey::SetSeedFromTag(std::span<const unsigned char> seed, const unsigned char* tag, size_t taglen)
{
    // BIP32 requires a seed of 128 to 512 bits, and the bound is not decoration: a
    // short seed yields a master key with only as much entropy as was fed in, and
    // nothing downstream would report it. Enforced as a programming invariant --
    // every caller in this tree passes a fixed-width seed, so a violation is a bug
    // rather than bad input.
    Assert(16 <= seed.size() && seed.size() <= 64);

    // Master node: I = SHA3-512(tag || seed); the first 32 bytes are the master node seed
    // (the ML-DSA KeyGen seed), the rest the chain code.
    unsigned char out[SHA3_512::OUTPUT_SIZE];
    SHA3_512().Write(tag, taglen).Write(seed.data(), seed.size()).Finalize(out);

    nDepth = 0;
    nChild = 0;
    std::memset(vchFingerprint, 0, sizeof(vchFingerprint));
    nodeseed = uint256(std::span<const unsigned char>(out, CKey::SEED_SIZE));
    chaincode = ChainCode(std::span<const unsigned char>(out + CKey::SEED_SIZE, 32));
    key.MakeKeyFromSeed(std::span<const unsigned char>(nodeseed.begin(), CKey::SEED_SIZE));
}

void CExtKey::SetSeed(std::span<const unsigned char> seed)
{
    static const unsigned char hashkey[] = {
        'T', 'e', 's', 's', 'e', 'r', 'a', ' ',
        'H', 'D', ' ', 'm', 'a', 's', 't', 'e', 'r'};
    SetSeedFromTag(seed, hashkey, sizeof(hashkey));
}


bool CExtKey::Derive(CExtKey& out, unsigned int _nChild) const
{
    if (!key.IsValid()) return false;

    out.nDepth = nDepth + 1;
    const CKeyID id = key.GetPubKey().GetID();
    std::memcpy(out.vchFingerprint, id.begin(), sizeof(out.vchFingerprint));
    out.nChild = _nChild;

    // Hardened-only: I = SHA3-512(chaincode || nodeseed || ser32BE(nChild)). The
    // parent's secret node seed is always part of the preimage, so a child cannot
    // be derived from public material alone.
    unsigned char data[32 + CKey::SEED_SIZE + 4];
    std::memcpy(data, chaincode.begin(), 32);
    std::memcpy(data + 32, nodeseed.begin(), CKey::SEED_SIZE);
    data[64] = static_cast<unsigned char>(_nChild >> 24);
    data[65] = static_cast<unsigned char>(_nChild >> 16);
    data[66] = static_cast<unsigned char>(_nChild >> 8);
    data[67] = static_cast<unsigned char>(_nChild);

    unsigned char out64[SHA3_512::OUTPUT_SIZE];
    SHA3_512().Write(data, sizeof(data)).Finalize(out64);
    out.nodeseed = uint256(std::span<const unsigned char>(out64, CKey::SEED_SIZE));
    out.chaincode = ChainCode(std::span<const unsigned char>(out64 + CKey::SEED_SIZE, 32));
    return out.key.MakeKeyFromSeed(std::span<const unsigned char>(out.nodeseed.begin(), CKey::SEED_SIZE));
}

void CExtKey::Encode(unsigned char code[SIZE]) const
{
    code[0] = nDepth;
    std::memcpy(code + 1, vchFingerprint, 4);
    code[5] = static_cast<unsigned char>(nChild >> 24);
    code[6] = static_cast<unsigned char>(nChild >> 16);
    code[7] = static_cast<unsigned char>(nChild >> 8);
    code[8] = static_cast<unsigned char>(nChild);
    std::memcpy(code + 9, chaincode.begin(), 32);
    std::memcpy(code + 41, nodeseed.begin(), CKey::SEED_SIZE);
}

void CExtKey::Decode(const unsigned char code[SIZE])
{
    nDepth = code[0];
    std::memcpy(vchFingerprint, code + 1, 4);
    nChild = (static_cast<unsigned int>(code[5]) << 24) | (static_cast<unsigned int>(code[6]) << 16) |
             (static_cast<unsigned int>(code[7]) << 8) | static_cast<unsigned int>(code[8]);
    chaincode = ChainCode(std::span<const unsigned char>(code + 9, 32));
    nodeseed = uint256(std::span<const unsigned char>(code + 41, CKey::SEED_SIZE));
    key.MakeKeyFromSeed(std::span<const unsigned char>(nodeseed.begin(), CKey::SEED_SIZE));
}
