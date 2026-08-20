// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// SHA3-512 (FIPS 202, Keccak-f[1600]) for Lattica's RNG entropy pool.
//
// Kept in its own file, deliberately separate from:
//  - the consensus hash crypto/sha3.h (SHA3-256, block/tx identity + PoW), and
//  - Bitcoin Core's SHA-2 hashers crypto/sha512.h / crypto/sha256.h, which
//    Lattica does not use (Lattica is Keccak/SHA3-only).
// Self-contained: it carries its own Keccak-f permutation, so the RNG's hashing
// has no dependency on the consensus crypto. The interface mirrors CSHA512
// (64-byte output, pointer/length Write, void Finalize, Reset, Size, and a
// copyable midstate) so the SHA3-adapted random.cpp uses it as a drop-in.

#ifndef LATTICA_CRYPTO_SHA3_512_H
#define LATTICA_CRYPTO_SHA3_512_H

#include <cstdint>
#include <cstdlib>

/** A hasher class for SHA3-512 (FIPS 202). */
class SHA3_512
{
private:
    uint64_t m_state[25] = {0};
    unsigned char m_buffer[8];
    unsigned m_bufsize = 0;
    unsigned m_pos = 0;
    uint64_t m_bytes = 0;

    //! Sponge rate in bits (1600 state - 1024 capacity for the 512-bit output).
    static constexpr unsigned RATE_BITS = 576;
    static constexpr unsigned RATE_BUFFERS = RATE_BITS / (8 * sizeof(m_buffer));
    static_assert(RATE_BITS % (8 * sizeof(m_buffer)) == 0, "Rate must be a multiple of 8 bytes");

public:
    static constexpr size_t OUTPUT_SIZE = 64;

    SHA3_512() = default;
    SHA3_512& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    SHA3_512& Reset();
    uint64_t Size() const { return m_bytes; }
};

#endif // LATTICA_CRYPTO_SHA3_512_H
