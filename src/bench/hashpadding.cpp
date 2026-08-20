// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <bench/bench.h>
#include <crypto/sha256.h>
#include <random.h>
#include <uint256.h>


static void PrePadded(benchmark::Bench& bench)
{

    CSHA256 hasher;

    // Setup the salted hasher
    uint256 nonce = GetRandHash();
    hasher.Write(nonce.begin(), 32);
    hasher.Write(nonce.begin(), 32);
    uint256 data = GetRandHash();
    bench.run([&] {
        unsigned char out[32];
        CSHA256 h = hasher;
        h.Write(data.begin(), 32);
        h.Finalize(out);
    });
}

BENCHMARK(PrePadded);

static void RegularPadded(benchmark::Bench& bench)
{
    CSHA256 hasher;

    // Setup the salted hasher
    uint256 nonce = GetRandHash();
    uint256 data = GetRandHash();
    bench.run([&] {
        unsigned char out[32];
        CSHA256 h = hasher;
        h.Write(nonce.begin(), 32);
        h.Write(data.begin(), 32);
        h.Finalize(out);
    });
}

BENCHMARK(RegularPadded);
