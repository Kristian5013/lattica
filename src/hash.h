// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Lattica's consensus hash is SHA3-256 (FIPS 202), not Bitcoin's double
// SHA-256. SHA3 is a length-extension-safe sponge, so a single pass suffices —
// there is no second hashing round. CHash256 keeps Bitcoin Core's interface so
// downstream code (e.g. the Merkle tree) ports unchanged, but computes
// SHA3-256 underneath.

#ifndef LATTICA_HASH_H
#define LATTICA_HASH_H

#include <attributes.h>
#include <crypto/common.h>
#include <crypto/ripemd160.h>
#include <crypto/sha3.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>

/** A hasher class for Lattica's 256-bit consensus hash (SHA3-256, FIPS 202). */
class CHash256 {
private:
    SHA3_256 sha;
public:
    static const size_t OUTPUT_SIZE = SHA3_256::OUTPUT_SIZE;

    void Finalize(std::span<unsigned char> output) {
        assert(output.size() == OUTPUT_SIZE);
        sha.Finalize(output);
    }

    CHash256& Write(std::span<const unsigned char> input) {
        sha.Write(input);
        return *this;
    }

    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};

/** Compute the 256-bit hash of an object. */
template<typename T>
inline uint256 Hash(const T& in1)
{
    uint256 result;
    CHash256().Write(MakeUCharSpan(in1)).Finalize(result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template<typename T1, typename T2>
inline uint256 Hash(const T1& in1, const T2& in2) {
    uint256 result;
    CHash256().Write(MakeUCharSpan(in1)).Write(MakeUCharSpan(in2)).Finalize(result);
    return result;
}

/** Compute the 160-bit hash of an object: RIPEMD-160 over its SHA3-256.
 *
 * Hash160 = RIPEMD160(SHA3-256(x)). Structurally this is Bitcoin's two-stage
 * Hash160, which is what lets address and script-hash code keep Core's shape,
 * but the inner digest is Lattica's consensus hash rather than SHA-256, so no
 * value here matches Bitcoin's encoding of the same key or script.
 *
 * The second stage is a hash and not a truncation on purpose. Truncating would
 * make the 160-bit value a literal prefix of the 256-bit hash of the same
 * preimage, so a script's P2SH hash would be the first 20 bytes of its P2WSH
 * commitment (script/interpreter.cpp hashes witnessScript with SHA3-256).
 * RIPEMD-160 makes the two commitments independent.
 */
template<typename T1>
inline uint160 Hash160(const T1& in1)
{
    uint256 full;
    CHash256().Write(MakeUCharSpan(in1)).Finalize(full);
    uint160 result;
    CRIPEMD160().Write(full.begin(), full.size()).Finalize(result.begin());
    return result;
}

/** A writer stream (for serialization) that computes a 256-bit hash. */
class HashWriter
{
private:
    SHA3_256 ctx;

public:
    void write(std::span<const std::byte> src)
    {
        ctx.Write(UCharSpanCast(src));
    }

    /** Compute the SHA3-256 hash of all data written to this object.
     *
     * Invalidates this object.
     */
    uint256 GetHash() {
        uint256 result;
        ctx.Finalize(result);
        return result;
    }

    /**
     * Returns the first 64 bits from the resulting hash.
     */
    inline uint64_t GetCheapHash() {
        uint256 result = GetHash();
        return ReadLE64(result.begin());
    }

    template <typename T>
    HashWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

/** Reads data from an underlying stream, while hashing the read data. */
template <typename Source>
class HashVerifier : public HashWriter
{
private:
    Source& m_source;

public:
    explicit HashVerifier(Source& source LIFETIMEBOUND) : m_source{source} {}

    void read(std::span<std::byte> dst)
    {
        m_source.read(dst);
        this->write(dst);
    }

    void ignore(size_t num_bytes)
    {
        std::byte data[1024];
        while (num_bytes > 0) {
            size_t now = std::min<size_t>(num_bytes, 1024);
            read({data, now});
            num_bytes -= now;
        }
    }

    template <typename T>
    HashVerifier<Source>& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }
};

/** Writes data to an underlying source stream, while hashing the written data. */
template <typename Source>
class HashedSourceWriter : public HashWriter
{
private:
    Source& m_source;

public:
    explicit HashedSourceWriter(Source& source LIFETIMEBOUND) : HashWriter{}, m_source{source} {}

    void write(std::span<const std::byte> src)
    {
        m_source.write(src);
        HashWriter::write(src);
    }

    template <typename T>
    HashedSourceWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }
};

unsigned int MurmurHash3(unsigned int nHashSeed, std::span<const unsigned char> vDataToHash);

#endif // LATTICA_HASH_H
