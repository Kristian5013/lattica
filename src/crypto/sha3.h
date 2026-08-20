// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Lattica — SHA3-256 (FIPS 202, Keccak-f[1600]).
//
// The consensus hash: block/tx identity, the Merkle root, and the SHA3-256d
// proof of work all use it. One sponge primitive, length-extension safe. The
// domain padding is SHA3's 0x06 (FIPS 202), NOT original Keccak's 0x01.

#ifndef LATTICA_CRYPTO_SHA3_H
#define LATTICA_CRYPTO_SHA3_H

#include <cstdint>
#include <cstdlib>
#include <span>

//! The Keccak-f[1600] permutation, in place over the 25-lane state.
void KeccakF(uint64_t (&st)[25]);

/** A hasher class for SHA3-256 (FIPS 202). */
class SHA3_256
{
private:
    uint64_t m_state[25] = {0};
    unsigned char m_buffer[8];
    unsigned m_bufsize = 0;
    unsigned m_pos = 0;

    //! Sponge rate in bits (1600 state - 512 capacity for the 256-bit output).
    static constexpr unsigned RATE_BITS = 1088;

    //! Sponge rate expressed as a multiple of the 8-byte buffer (one lane).
    static constexpr unsigned RATE_BUFFERS = RATE_BITS / (8 * sizeof(m_buffer));

    static_assert(RATE_BITS % (8 * sizeof(m_buffer)) == 0, "Rate must be a multiple of 8 bytes");

public:
    static constexpr size_t OUTPUT_SIZE = 32;

    SHA3_256() = default;
    SHA3_256& Write(std::span<const unsigned char> data);
    SHA3_256& Finalize(std::span<unsigned char> output);
    SHA3_256& Reset();
};

#endif // LATTICA_CRYPTO_SHA3_H
