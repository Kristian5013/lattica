// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <bench/bench.h>
#include <test/util/time.h>
#include <util/time.h>

static void BenchTimeDeprecated(benchmark::Bench& bench)
{
    bench.run([&] {
        (void)GetTime();
    });
}

static void BenchTimeMock(benchmark::Bench& bench)
{
    FakeNodeClock clock{111s};
    bench.run([&] {
        (void)GetTime<std::chrono::seconds>();
    });
}

static void BenchTimeMillis(benchmark::Bench& bench)
{
    bench.run([&] {
        (void)GetTime<std::chrono::milliseconds>();
    });
}

static void BenchTimeMillisSys(benchmark::Bench& bench)
{
    bench.run([&] {
        (void)TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());
    });
}

BENCHMARK(BenchTimeDeprecated);
BENCHMARK(BenchTimeMillis);
BENCHMARK(BenchTimeMillisSys);
BENCHMARK(BenchTimeMock);
