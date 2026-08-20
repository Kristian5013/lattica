// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Smoke tests for the cluster-mempool graph engine (txgraph / cluster_linearize):
// build a small TxGraph, add transactions with a parent/child dependency, and
// check counts, existence, per-transaction feerate, and that a dependency links
// two transactions into one cluster.

#include <txgraph.h>
#include <util/feefrac.h>

#include <compare>
#include <cstdio>
#include <functional>
#include <memory>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}
} // namespace

int main()
{
    const std::function<std::strong_ordering(const TxGraph::Ref&, const TxGraph::Ref&)> fallback =
        [](const TxGraph::Ref&, const TxGraph::Ref&) { return std::strong_ordering::equal; };

    auto graph = MakeTxGraph(/*max_cluster_count=*/100, /*max_cluster_size=*/1'000'000, /*acceptable_cost=*/1'000'000, fallback);

    TxGraph::Ref a, b, c;
    graph->AddTransaction(a, FeePerWeight{1000, 100});
    graph->AddTransaction(b, FeePerWeight{500, 100});
    graph->AddTransaction(c, FeePerWeight{2000, 100});

    Check("count == 3", graph->GetTransactionCount(TxGraph::Level::MAIN) == 3);
    Check("a exists", graph->Exists(a, TxGraph::Level::MAIN));

    // Individual feerate is preserved.
    {
        FeePerWeight fr = graph->GetIndividualFeerate(c);
        Check("c individual feerate", fr.fee == 2000 && fr.size == 100);
    }

    // Before any dependency: a is in its own cluster.
    Check("a alone in cluster", graph->GetCluster(a, TxGraph::Level::MAIN).size() == 1);

    // b depends on a -> they share a cluster.
    graph->AddDependency(a, b);
    {
        auto cluster = graph->GetCluster(a, TxGraph::Level::MAIN);
        Check("a+b share a cluster after dependency", cluster.size() == 2);
    }

    // c is still independent.
    Check("c alone in cluster", graph->GetCluster(c, TxGraph::Level::MAIN).size() == 1);

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
