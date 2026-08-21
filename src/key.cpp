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
// ML-DSA-44 (PQClean). Reached through the vendored api.h, which is the one on
// this target's include path.
#include "api.h"
#include "randombytes.h"

// Falcon-512 (PQClean falcon-padded-512). Declared rather than included: three
// PQClean trees ship an "api.h", so which one a quoted include resolves to
// would depend on link order. crypto/mlkem.cpp established this approach.
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(uint8_t* pk, uint8_t* sk);
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
    uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
}

#include <array>
#include <cassert>
#include <cstring>
#include <span>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// secp256k1 global signing context
//
// Only key generation and signing need it; secp256k1_ec_pubkey_create and
// secp256k1_ecdsa_sign refuse the static context, while everything on the
// verification path accepts it. That split is what keeps consensus code free of
// global initialisation: a node that only validates never starts one.
// ---------------------------------------------------------------------------

static secp256k1_context* secp256k1_context_sign = nullptr;

secp256k1_context* GetSecp256k1SignContext()
{
    return secp256k1_context_sign;
}

static void ECC_Start()
{
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    assert(ctx != nullptr);

    {
        // Blind the context so a side channel cannot recover the secret from
        // the multiplication.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed);
        const bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

static void ECC_Stop()
{
    secp256k1_context* ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;
    if (ctx) secp256k1_context_destroy(ctx);
}

ECC_Context::ECC_Context() { ECC_Start(); }
ECC_Context::~ECC_Context() { ECC_Stop(); }

namespace {

//! The signing context, with a legible failure instead of a null dereference.
const secp256k1_context* SigningContext()
{
    secp256k1_context* ctx = GetSecp256k1SignContext();
    assert(ctx != nullptr &&
           "an ECC_Context must be alive before generating or signing with a secp256k1 key");
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

//! Derive and serialize the public key for a secp256k1 secret.
bool DeriveSecpPubKey(const unsigned char* seckey, std::array<unsigned char, 33>& out)
{
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(SigningContext(), &pubkey, seckey)) return false;
    out = SerializeCompressed(pubkey);
    return true;
}

/**
 * Run a PQClean keypair with the entropy seam pinned to `seed`.
 *
 * Both lattice schemes draw their key material from the shared randombytes, so
 * one seam serves both: set the deterministic seed, call the UNMODIFIED
 * upstream keypair, clear it again. The algorithms stay byte-for-byte verbatim;
 * only the entropy source is redirected, and only for the duration of the call.
 *
 * Clearing on the way out is not tidiness. Falcon also draws from randombytes
 * while signing, for the per-signature salt, and a salt fixed by a leftover
 * deterministic seed would be a real weakening.
 */
template <typename KeypairFn>
int SeededKeypair(const unsigned char* seed, KeypairFn&& keypair)
{
    mldsa_set_deterministic_seed(seed);
    const int ret = keypair();
    mldsa_clear_deterministic_seed();
    return ret;
}

} // namespace

// ---------------------------------------------------------------------------
// CKey
// ---------------------------------------------------------------------------

unsigned int CKey::SecretSizeForPubKey(unsigned int pubkey_size)
{
    switch (pubkey_size) {
    case CPubKey::SECP256K1_SIZE: return SECP256K1_SIZE;
    case CPubKey::FALCON512_SIZE: return FALCON512_SIZE;
    case CPubKey::MLDSA44_SIZE:   return MLDSA44_SIZE;
    }
    return 0;
}

void CKey::MakeKeyData(unsigned int secret_size)
{
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

bool CKey::Check(unsigned int secret_size, const unsigned char* vch)
{
    if (vch == nullptr) return false;
    switch (secret_size) {
    case SECP256K1_SIZE:
        // A real predicate: the scalar must lie in [1, n-1]. The static context
        // suffices — this is arithmetic on the secret, not a multiplication by G.
        return secp256k1_ec_seckey_verify(secp256k1_context_static, vch) == 1;
    case FALCON512_SIZE:
    case MLDSA44_SIZE:
        // Neither lattice scheme has a cheap validity predicate. Any buffer of
        // the right length is structurally acceptable; semantic validity is
        // what VerifyPubKey establishes.
        return true;
    }
    return false;
}

void CKey::MakeNewKey(unsigned int secret_size)
{
    MakeKeyData(secret_size);
    if (!m_keydata) return;

    switch (secret_size) {
    case SECP256K1_SIZE: {
        // Rejection-sample until the scalar is in range. A draw fails with
        // probability around 2^-128, so this never loops in practice; it loops
        // in code because "never in practice" is not "never".
        do {
            GetStrongRandBytes(std::span<unsigned char>(MutableData(), size()));
        } while (!Check(secret_size, data()));

        std::array<unsigned char, CPubKey::SECP256K1_SIZE> pk;
        const bool ok = DeriveSecpPubKey(data(), pk);
        assert(ok);
        (void)ok;
        m_pubkey = CPubKey(pk);
        break;
    }
    case FALCON512_SIZE: {
        std::array<unsigned char, CPubKey::FALCON512_SIZE> pk;
        // PQClean draws its own OS entropy and aborts on failure, so a return
        // here is always success.
        const int ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk.data(), MutableData());
        assert(ret == 0);
        (void)ret;
        m_pubkey = CPubKey(pk);
        break;
    }
    case MLDSA44_SIZE: {
        std::array<unsigned char, CPubKey::MLDSA44_SIZE> pk;
        const int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), MutableData());
        assert(ret == 0);
        (void)ret;
        m_pubkey = CPubKey(pk);
        break;
    }
    }
    assert(m_pubkey.IsValid());
}

bool CKey::MakeKeyFromSeed(unsigned int secret_size, std::span<const unsigned char> seed)
{
    if (seed.size() != SEED_SIZE) {
        ClearKeyData();
        return false;
    }
    MakeKeyData(secret_size);
    if (!m_keydata) return false;

    switch (secret_size) {
    case SECP256K1_SIZE: {
        // The seed is the scalar. One in roughly 2^128 seeds lies outside
        // [1, n-1] and simply has no key; the caller has to cope, which for a
        // derivation path means moving to the next index as BIP32 does.
        if (!Check(secret_size, seed.data())) {
            ClearKeyData();
            return false;
        }
        std::memcpy(MutableData(), seed.data(), seed.size());
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
        const int ret = SeededKeypair(seed.data(), [&] {
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
        const int ret = SeededKeypair(seed.data(), [&] {
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

CPrivKey CKey::GetPrivKey() const
{
    assert(m_keydata);
    return CPrivKey(data(), data() + size());
}

bool CKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig) const
{
    if (!m_keydata) return false;

    switch (size()) {
    case SECP256K1_SIZE: {
        secp256k1_ecdsa_signature sig;
        // Nonces are libsecp256k1's default RFC6979: derived from the secret and
        // the message, so signing is deterministic and needs no entropy. Core's
        // low-R grinding exists to save a DER byte, and there is no DER here.
        if (!secp256k1_ecdsa_sign(SigningContext(), &sig, hash.begin(), data(),
                                  nullptr, nullptr)) {
            vchSig.clear();
            return false;
        }
        // libsecp256k1 already returns low-S. Normalizing anyway makes the
        // invariant something this function enforces rather than inherits, and
        // CPubKey::Verify refuses a high-S signature outright.
        secp256k1_ecdsa_signature_normalize(secp256k1_context_static, &sig, &sig);
        vchSig.resize(CPubKey::SECP256K1_SIGNATURE_SIZE);
        const int ok = secp256k1_ecdsa_signature_serialize_compact(
            secp256k1_context_static, vchSig.data(), &sig);
        assert(ok);
        (void)ok;
        return true;
    }
    case FALCON512_SIZE: {
        // Randomized: a fresh salt per signature, so two signatures over the
        // same message differ. Nothing here may assume otherwise.
        vchSig.resize(CPubKey::FALCON512_SIGNATURE_SIZE);
        size_t siglen = 0;
        const int ret = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(
            vchSig.data(), &siglen, hash.begin(), hash.size(), data());
        if (ret != 0 || siglen != vchSig.size()) {
            // The padded variant is fixed-length by construction; a short one
            // would mean the plain falcon-512 sources had been swapped in, and
            // every size estimate downstream would be wrong.
            vchSig.clear();
            return false;
        }
        return true;
    }
    case MLDSA44_SIZE: {
        vchSig.resize(CPubKey::MLDSA44_SIGNATURE_SIZE);
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
    }
    return false;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const
{
    if (!IsValid() || !pubkey.IsValid()) return false;
    if (SecretSizeForPubKey(pubkey.size()) != size()) return false;

    if (size() == SECP256K1_SIZE) {
        // Derivable, so this is an equality test rather than a proof.
        std::array<unsigned char, CPubKey::SECP256K1_SIZE> pk;
        if (!DeriveSecpPubKey(data(), pk)) return false;
        return std::memcmp(pk.data(), pubkey.data(), pk.size()) == 0;
    }

    // Neither lattice scheme hands back a public key, so prove the pairing
    // instead: sign a random challenge and check it verifies under the candidate.
    const uint256 hash = GetRandHash();
    std::vector<unsigned char> vchSig;
    if (!Sign(hash, vchSig)) return false;
    return pubkey.Verify(hash, vchSig);
}

bool CKey::Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck)
{
    if (!vchPubKey.IsValid()) return false;
    const unsigned int secret_size{SecretSizeForPubKey(vchPubKey.size())};
    if (secret_size == 0 || privkey.size() != secret_size) return false;

    if (fSkipCheck) {
        MakeKeyData(secret_size);
        if (!m_keydata) return false;
        std::memcpy(MutableData(), privkey.data(), privkey.size());
        m_pubkey = vchPubKey;
        return true;
    }
    Set(privkey.begin(), privkey.end(), vchPubKey);
    return IsValid();
}

CKey GenerateRandomKey(unsigned int secret_size) noexcept
{
    CKey key;
    key.MakeNewKey(secret_size);
    return key;
}

bool KeyCryptoSanityCheck()
{
    static const std::string test{"Lattica key sanity check"};
    const uint256 hash = Hash(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(test.data()), test.size()));

    for (const unsigned int secret_size : {CKey::SECP256K1_SIZE, CKey::FALCON512_SIZE, CKey::MLDSA44_SIZE}) {
        const CKey key = GenerateRandomKey(secret_size);
        if (!key.IsValid() || key.size() != secret_size) return false;

        const CPubKey pubkey = key.GetPubKey();
        if (!pubkey.IsValid() || !pubkey.IsFullyValid()) return false;
        if (CKey::SecretSizeForPubKey(pubkey.size()) != secret_size) return false;
        if (!key.VerifyPubKey(pubkey)) return false;

        std::vector<unsigned char> sig;
        if (!key.Sign(hash, sig)) return false;
        if (sig.size() != pubkey.SignatureSize()) return false;
        if (!pubkey.Verify(hash, sig)) return false;
    }
    return true;
}

// --- CExtKey: hardened-only hierarchical-deterministic derivation ------------
//
// Still ML-DSA-only. Making it carry a scheme the way CKey now does is the next
// step: secp256k1 would get Core's BIP32 tweak verbatim, along with the
// non-hardened derivation and the Neuter() that a lattice scheme cannot have.

void CExtKey::SetSeedFromTag(std::span<const unsigned char> seed, const unsigned char* tag, size_t taglen)
{
    // BIP32 requires a seed of 128 to 512 bits, and the bound is not decoration: a
    // short seed yields a master key with only as much entropy as was fed in, and
    // nothing downstream would report it. Enforced as a programming invariant --
    // every caller in this tree passes a fixed-width seed, so a violation is a bug
    // rather than bad input.
    Assert(16 <= seed.size() && seed.size() <= 64);

    // Master node: I = SHA3-512(tag || seed); the first 32 bytes are the master node seed
    // (the key-generation seed), the rest the chain code.
    unsigned char out[SHA3_512::OUTPUT_SIZE];
    SHA3_512().Write(tag, taglen).Write(seed.data(), seed.size()).Finalize(out);

    nDepth = 0;
    nChild = 0;
    std::memset(vchFingerprint, 0, sizeof(vchFingerprint));
    nodeseed = uint256(std::span<const unsigned char>(out, CKey::SEED_SIZE));
    chaincode = ChainCode(std::span<const unsigned char>(out + CKey::SEED_SIZE, 32));
    key.MakeKeyFromSeed(CKey::MLDSA44_SIZE,
                        std::span<const unsigned char>(nodeseed.begin(), CKey::SEED_SIZE));
}

void CExtKey::SetSeed(std::span<const unsigned char> seed)
{
    // The domain-separation tag for the master node. It is part of the
    // derivation, so a seed produces different keys under a different tag: this
    // is the project's name, not a label, and changing it invalidates every
    // wallet derived under the old one.
    static const unsigned char hashkey[] = {
        'L', 'a', 't', 't', 'i', 'c', 'a', ' ',
        'H', 'D', ' ', 'm', 'a', 's', 't', 'e', 'r'};
    SetSeedFromTag(seed, hashkey, sizeof(hashkey));
}

bool CExtKey::Derive(CExtKey& out, unsigned int _nChild) const
{
    if (!key.IsValid()) return false;

    out.nDepth = nDepth + 1;
    const KeyFingerprint fp = key.GetPubKey().GetID().fingerprint();
    std::memcpy(out.vchFingerprint, fp.data(), sizeof(out.vchFingerprint));
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
    return out.key.MakeKeyFromSeed(CKey::MLDSA44_SIZE,
                                   std::span<const unsigned char>(out.nodeseed.begin(), CKey::SEED_SIZE));
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
    key.MakeKeyFromSeed(CKey::MLDSA44_SIZE,
                        std::span<const unsigned char>(nodeseed.begin(), CKey::SEED_SIZE));
}
