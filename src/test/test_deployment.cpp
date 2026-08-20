// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the deployment-status helpers (deploymentstatus/versionbits): with
// Lattica's buried soft-fork heights set to 0 (every fork active from genesis),
// DeploymentActiveAfter is true at every height; a height of INT_MAX disables a
// deployment (DeploymentEnabled false).

#include <deploymentstatus.h>
#include <versionbits.h>
#include <consensus/params.h>
#include <chain.h>

#include <cstdio>
#include <limits>

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
    Consensus::Params params{};
    params.BIP34Height = 0;
    params.BIP65Height = 0;
    params.BIP66Height = 0;
    params.CSVHeight = 0;
    params.SegwitHeight = 0;

    VersionBitsCache cache;

    // Genesis (pindexPrev == nullptr -> height 0): all forks active.
    Check("segwit active at genesis", DeploymentActiveAfter(nullptr, params, Consensus::DEPLOYMENT_SEGWIT, cache));
    Check("csv active at genesis", DeploymentActiveAfter(nullptr, params, Consensus::DEPLOYMENT_CSV, cache));

    // An arbitrary block: still active.
    CBlockIndex idx;
    idx.nHeight = 1000;
    Check("segwit active at height 1001", DeploymentActiveAfter(&idx, params, Consensus::DEPLOYMENT_SEGWIT, cache));
    Check("bip34 active-at height 1000", DeploymentActiveAt(idx, params, Consensus::DEPLOYMENT_HEIGHTINCB, cache));

    // DeploymentEnabled: a 0-height deployment is enabled; INT_MAX disables it.
    Check("segwit enabled", DeploymentEnabled(params, Consensus::DEPLOYMENT_SEGWIT));
    params.BIP34Height = std::numeric_limits<int>::max();
    Check("disabled (INT_MAX) deployment not enabled", !DeploymentEnabled(params, Consensus::DEPLOYMENT_HEIGHTINCB));

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
