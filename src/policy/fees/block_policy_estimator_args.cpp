// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <policy/fees/block_policy_estimator_args.h>

#include <common/args.h>

namespace {
const char* FEE_ESTIMATES_FILENAME = "fee_estimates.dat";
} // namespace

fs::path FeeestPath(const ArgsManager& argsman)
{
    return argsman.GetDataDirNet() / FEE_ESTIMATES_FILENAME;
}