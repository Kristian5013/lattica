// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <script/sigcache.h>

#include <crypto/sha3.h>
#include <logging.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <uint256.h>

#include <mutex>
#include <shared_mutex>
#include <span>
#include <utility>
#include <vector>

SignatureCache::SignatureCache(const size_t max_size_bytes)
{
    uint256 nonce = GetRandHash();
    // We want the nonce to be 64 bytes long to force the hasher to process
    // this chunk, which makes later hash computations more efficient. We just
    // write our 32-byte entropy, and then pad with 'M' (ML-DSA, Lattica's only
    // signature scheme) followed by 0 bytes.
    static constexpr unsigned char PADDING[32] = {'M'};
    m_salted_hasher.Write(std::span<const unsigned char>(nonce.begin(), 32));
    m_salted_hasher.Write(std::span<const unsigned char>(PADDING, 32));

    const auto [num_elems, approx_size_bytes] = setValid.setup_bytes(max_size_bytes);
    LogInfo("Using %zu MiB out of %zu MiB requested for signature cache, able to store %zu elements",
              approx_size_bytes >> 20, max_size_bytes >> 20, num_elems);
}

void SignatureCache::ComputeEntry(uint256& entry, const uint256& hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey) const
{
    SHA3_256 hasher = m_salted_hasher;
    hasher.Write(std::span<const unsigned char>(hash.begin(), 32))
          .Write(std::span<const unsigned char>(pubkey.data(), pubkey.size()))
          .Write(std::span<const unsigned char>(vchSig.data(), vchSig.size()))
          .Finalize(std::span<unsigned char>(entry.begin(), 32));
}

bool SignatureCache::Get(const uint256& entry, const bool erase)
{
    std::shared_lock<std::shared_mutex> lock(cs_sigcache);
    return setValid.contains(entry, erase);
}

void SignatureCache::Set(const uint256& entry)
{
    std::unique_lock<std::shared_mutex> lock(cs_sigcache);
    setValid.insert(entry);
}

bool CachingTransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    uint256 entry;
    m_signature_cache.ComputeEntry(entry, sighash, vchSig, pubkey);
    if (m_signature_cache.Get(entry, !store))
        return true;
    if (!TransactionSignatureChecker::VerifySignature(vchSig, pubkey, sighash))
        return false;
    if (store)
        m_signature_cache.Set(entry);
    return true;
}
