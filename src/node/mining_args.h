// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_NODE_MINING_ARGS_H
#define LATTICA_NODE_MINING_ARGS_H

#include <node/mining_types.h>
#include <util/result.h>

class ArgsManager;

namespace node {

static const bool DEFAULT_PRINT_MODIFIED_FEE = false;

/**
 * Read the mining options set in \p args. Returns an error if one was
 * encountered.
 */
[[nodiscard]] util::Result<BlockCreateOptions> ReadMiningArgs(const ArgsManager& args);

/** Check option values for validity. Returns an error for invalid values. */
[[nodiscard]] util::Result<void> CheckMiningOptions(BlockCreateOptions options, bool use_argnames);

/** Replace null optional values with their hardcoded defaults. */
[[nodiscard]] BlockCreateOptions FlattenMiningOptions(BlockCreateOptions options);

/**
 * Merge two BlockCreateOptions structs, replacing null values in \p x with
 * non-null values from \p y.
 */
[[nodiscard]] BlockCreateOptions MergeMiningOptions(BlockCreateOptions x, const BlockCreateOptions& y);

} // namespace node

#endif // LATTICA_NODE_MINING_ARGS_H