// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <bench/bench.h>
#include <consensus/consensus.h>
#include <crypto/hex_base.h>
#include <random.h>

#include <cstddef>
#include <span>
#include <string>
#include <vector>

static void HexStrBench(benchmark::Bench& bench)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    auto data{rng.randbytes<std::byte>(MAX_BLOCK_WEIGHT)};
    bench.batch(data.size()).unit("byte").run([&] {
        auto hex = HexStr(data);
        ankerl::nanobench::doNotOptimizeAway(hex);
    });
}

BENCHMARK(HexStrBench);
