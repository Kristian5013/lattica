// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Lattica — RIPEMD-160, the outer stage of Hash160. The implementation is kept
// unchanged from Bitcoin Core's src/crypto/ripemd160.{h,cpp} so upstream fixes
// apply directly; only the include guard is renamed.
//
// Lattica composes it as Hash160 = RIPEMD160(SHA3-256(x)) — structurally
// Bitcoin's two-stage Hash160, but with a SHA3-256 inner digest, so the values
// are not Bitcoin's and no address derived here matches Bitcoin's encoding of
// the same key. Hashing the digest rather than truncating it also keeps the
// 160-bit script hash independent of the 256-bit commitment to the same script;
// a truncated one would simply be its prefix. See hash.h.

#ifndef LATTICA_CRYPTO_RIPEMD160_H
#define LATTICA_CRYPTO_RIPEMD160_H

#include <cstdint>
#include <cstdlib>

/** A hasher class for RIPEMD-160. */
class CRIPEMD160
{
private:
    uint32_t s[5];
    unsigned char buf[64];
    uint64_t bytes{0};

public:
    static constexpr size_t OUTPUT_SIZE{20};

    CRIPEMD160();
    CRIPEMD160& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CRIPEMD160& Reset();
};

#endif // LATTICA_CRYPTO_RIPEMD160_H
