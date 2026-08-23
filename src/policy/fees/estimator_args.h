// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_POLICY_FEES_ESTIMATOR_ARGS_H
#define LATTICA_POLICY_FEES_ESTIMATOR_ARGS_H

#include <util/fs.h>

class ArgsManager;

/** Move a legacy fee_estimates.dat file to the current block policy fee estimator path, if needed. */
void MaybeMigrateLegacyFeeEstimates(const ArgsManager& argsman);

/** @return The block policy fee estimator data file path. */
fs::path BlockPolicyFeeEstPath(const ArgsManager& argsman);

/** @return The mempool policy estimator data file path. */
fs::path MempoolPolicyEstimatorPath(const ArgsManager& argsman);

#endif // LATTICA_POLICY_FEES_ESTIMATOR_ARGS_H
