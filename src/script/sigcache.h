// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_SCRIPT_SIGCACHE_H
#define LATTICA_SCRIPT_SIGCACHE_H

#include <consensus/amount.h>
#include <crypto/sha3.h>
#include <cuckoocache.h>
#include <script/interpreter.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/hasher.h>

#include <cstddef>
#include <shared_mutex>
#include <span>
#include <vector>

class CPubKey;
class CTransaction;

// DoS prevention: limit cache size to 32MiB (over 1000000 entries on 64-bit
// systems). Due to how we count cache size, actual memory usage is slightly
// more (~32.25 MiB)
static constexpr size_t DEFAULT_VALIDATION_CACHE_BYTES{32_MiB};
static constexpr size_t DEFAULT_SIGNATURE_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static constexpr size_t DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static_assert(DEFAULT_VALIDATION_CACHE_BYTES == DEFAULT_SIGNATURE_CACHE_BYTES + DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES);

/**
 * Valid signature cache, to avoid doing expensive ML-DSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain).
 *
 * Lattica has a single signature scheme (ML-DSA), so there is one salted
 * hasher and one entry computation (Core splits ECDSA/Schnorr); the salt is
 * mixed with SHA3-256 (Lattica's consensus hash), not SHA-256.
 */
class SignatureCache
{
private:
    //! Entries are SHA3-256(nonce || 'M' || 31 zero bytes || signature hash || public key || signature):
    SHA3_256 m_salted_hasher;
    typedef CuckooCache::cache<uint256, SignatureCacheHasher> map_type;
    map_type setValid;
    std::shared_mutex cs_sigcache;

public:
    SignatureCache(size_t max_size_bytes);

    SignatureCache(const SignatureCache&) = delete;
    SignatureCache& operator=(const SignatureCache&) = delete;

    void ComputeEntry(uint256& entry, const uint256& hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey) const;

    bool Get(const uint256& entry, bool erase);

    void Set(const uint256& entry);
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    bool store;
    SignatureCache& m_signature_cache;

public:
    CachingTransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, bool storeIn, SignatureCache& signature_cache, PrecomputedTransactionData& txdataIn) : TransactionSignatureChecker(txToIn, nInIn, amountIn, txdataIn, MissingDataBehavior::ASSERT_FAIL), store(storeIn), m_signature_cache(signature_cache)  {}

    bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const override;
};

#endif // LATTICA_SCRIPT_SIGCACHE_H
