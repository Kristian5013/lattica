// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <bench/bench.h>

#include <test/util/setup_common.h>

#include <util/check.h>
#include <util/fs.h>
#include <util/time.h>

#include <compare>
#include <fstream>
#include <functional>
#include <iostream>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// setup_common's TestingSetup reads these to name each benchmark's datadir and
// to forward command-line args; benches pass no extra setup args.
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    return std::vector<const char*>{};
};
static std::string g_running_benchmark_name;
const std::function<std::string()> G_TEST_GET_FULL_NAME = []() {
    return g_running_benchmark_name;
};

namespace {

void GenerateTemplateResults(const std::vector<ankerl::nanobench::Result>& benchmarkResults, const fs::path& file, const char* tpl)
{
    if (benchmarkResults.empty() || file.empty()) {
        // nothing to write, bail out
        return;
    }
    std::ofstream fout{file.std_path()};
    if (fout.is_open()) {
        ankerl::nanobench::render(tpl, benchmarkResults, fout);
        std::cout << "Created " << file << std::endl;
    } else {
        std::cout << "Could not write to file " << file << std::endl;
    }
}

} // namespace

namespace benchmark {

BenchRunner::BenchmarkMap& BenchRunner::benchmarks()
{
    static BenchmarkMap benchmarks_map;
    return benchmarks_map;
}

BenchRunner::BenchRunner(std::string_view name, BenchFunction func)
{
    Assert(benchmarks().try_emplace(std::string{name}, std::move(func)).second);
}

void BenchRunner::RunAll(const Args& args)
{
    std::regex reFilter(args.regex_filter);
    std::smatch baseMatch;

    if (args.sanity_check) {
        std::cout << "Running with -sanity-check option, output is being suppressed as benchmark results will be useless." << std::endl;
    }

    std::vector<ankerl::nanobench::Result> benchmarkResults;
    for (const auto& [name, func] : benchmarks()) {

        if (!std::regex_match(name, baseMatch, reFilter)) {
            continue;
        }

        if (args.is_list_only) {
            std::cout << name << std::endl;
            continue;
        }

        Bench bench;
        if (args.sanity_check) {
            bench.epochs(1).epochIterations(1);
            bench.output(nullptr);
        }
        bench.name(name);
        g_running_benchmark_name = name;
        if (args.min_time > 0ms) {
            // convert to nanos before dividing to reduce rounding errors
            std::chrono::nanoseconds min_time_ns = args.min_time;
            bench.minEpochTime(min_time_ns / bench.epochs());
        }

        if (args.asymptote.empty()) {
            func(bench);
        } else {
            for (auto n : args.asymptote) {
                bench.complexityN(n);
                func(bench);
            }
            std::cout << bench.complexityBigO() << std::endl;
        }

        if (!bench.results().empty()) {
            benchmarkResults.push_back(bench.results().back());
        }
    }

    GenerateTemplateResults(benchmarkResults, args.output_csv, "# Benchmark, evals, iterations, total, min, max, median\n"
                                                               "{{#result}}{{name}}, {{epochs}}, {{average(iterations)}}, {{sumProduct(iterations, elapsed)}}, {{minimum(elapsed)}}, {{maximum(elapsed)}}, {{median(elapsed)}}\n"
                                                               "{{/result}}");
    GenerateTemplateResults(benchmarkResults, args.output_json, ankerl::nanobench::templates::json());
}

} // namespace benchmark
