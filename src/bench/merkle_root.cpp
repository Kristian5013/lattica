// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <bench/bench.h>
#include <consensus/merkle.h>
#include <random.h>
#include <uint256.h>
#include <util/check.h>

#include <initializer_list>
#include <utility>
#include <vector>

static void MerkleRoot(benchmark::Bench& bench)
{
    FastRandomContext rng{/*fDeterministic=*/true};

    std::vector<uint256> hashes{};
    hashes.resize(9001);
    for (auto& item : hashes) {
        item = rng.rand256();
    }

    for (bool mutate : {false, true}) {
        bench.name(mutate ? "MerkleRootWithMutation" : "MerkleRoot").batch(hashes.size()).unit("leaf").run([&] {
            std::vector<uint256> leaves;
            leaves.reserve((hashes.size() + 1) & ~1ULL); // capacity rounded up to even
            for (const auto& hash : hashes) {
                leaves.push_back(hash);
            }

            bool mutated{false};
            const uint256 root{ComputeMerkleRoot(std::move(leaves), mutate ? &mutated : nullptr)};
        });
    }
}

BENCHMARK(MerkleRoot);
