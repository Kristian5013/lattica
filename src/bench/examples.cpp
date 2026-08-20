// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <bench/bench.h>

// Extremely fast-running benchmark:
#include <cmath>

volatile double sum = 0.0; // volatile, global so not optimized away

static void Trig(benchmark::Bench& bench)
{
    double d = 0.01;
    bench.run([&] {
        sum = sum + sin(d);
        d += 0.000001;
    });
}

BENCHMARK(Trig);
