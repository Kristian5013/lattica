// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_HASH_H
#define LATTICA_HASH_H

#include <attributes.h>
#include <crypto/common.h>
#include <crypto/ripemd160.h>
#include <crypto/sha3.h>
#include <prevector.h>
#include <serialize.h>
#include <span.h>
#include <support/cleanse.h>
#include <uint256.h>

#include <string>
#include <vector>

/** A BIP32 chain code. Cleansed on destruction. */
class ChainCode : public base_blob<256> {
public:
    constexpr ChainCode() = default;
    constexpr explicit ChainCode(std::span<const unsigned char> vch) : base_blob<256>(vch) {}
    constexpr explicit ChainCode(const base_blob<256>& b) : base_blob<256>(b) {}
    ~ChainCode() { memory_cleanse(data(), size()); }
};

/** A hasher class for Lattica's 256-bit hash (SHA3-256). */
class CHash256 {
private:
    SHA3_256 sha;
public:
    static constexpr size_t OUTPUT_SIZE{SHA3_256::OUTPUT_SIZE};

    void Finalize(std::span<unsigned char> output) {
        assert(output.size() == OUTPUT_SIZE);
        // Core hashes a second time here, against length extension. A sponge
        // does not extend, so this is one pass.
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

/** A hasher class for Lattica's 160-bit hash (SHA3-256 + RIPEMD-160). */
class CHash160 {
private:
    SHA3_256 sha;
public:
    static constexpr size_t OUTPUT_SIZE{CRIPEMD160::OUTPUT_SIZE};

    void Finalize(std::span<unsigned char> output) {
        assert(output.size() == OUTPUT_SIZE);
        unsigned char buf[SHA3_256::OUTPUT_SIZE];
        sha.Finalize(buf);
        CRIPEMD160().Write(buf, SHA3_256::OUTPUT_SIZE).Finalize(output.data());
    }

    CHash160& Write(std::span<const unsigned char> input) {
        sha.Write(input);
        return *this;
    }

    CHash160& Reset() {
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

/** Compute the 160-bit hash an object. */
template<typename T1>
inline uint160 Hash160(const T1& in1)
{
    uint160 result;
    CHash160().Write(MakeUCharSpan(in1)).Finalize(result);
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

    /** Compute the SHA3-256 hash of all data written to this object.
     *
     * Invalidates this object.
     *
     * Core's two differ, a double pass against a single one. Here they are the
     * same value; both names are kept so its callers port unchanged.
     */
    uint256 GetSHA256() {
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

/** Single-SHA3-256 a 32-byte input (represented as uint256). */
[[nodiscard]] uint256 SHA256Uint256(const uint256& input);

unsigned int MurmurHash3(unsigned int nHashSeed, std::span<const unsigned char> vDataToHash);

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);

/** Return a HashWriter primed for tagged hashes (as specified in BIP 340).
 *
 * The returned object will have SHA3-256(tag) written to it once. Core writes
 * its tag hash twice (= 64 bytes) to fill a SHA-256 block, leaving nothing to
 * extend; a sponge needs no such fill.
 * A tagged hash can be computed by feeding the message into this object, and
 * then calling HashWriter::GetSHA256().
 */
HashWriter TaggedHash(const std::string& tag);

/** Compute the 160-bit RIPEMD-160 hash of an array. */
inline uint160 RIPEMD160(std::span<const unsigned char> data)
{
    uint160 result;
    CRIPEMD160().Write(data.data(), data.size()).Finalize(result.begin());
    return result;
}

#endif // LATTICA_HASH_H
