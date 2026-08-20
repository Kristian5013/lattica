// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_POLICY_FEES_BLOCK_POLICY_ESTIMATOR_ARGS_H
#define LATTICA_POLICY_FEES_BLOCK_POLICY_ESTIMATOR_ARGS_H

#include <util/fs.h>

class ArgsManager;

/** @return The fee estimates data file path. */
fs::path FeeestPath(const ArgsManager& argsman);

#endif // LATTICA_POLICY_FEES_BLOCK_POLICY_ESTIMATOR_ARGS_H