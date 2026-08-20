// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_NODE_MEMPOOL_PERSIST_ARGS_H
#define LATTICA_NODE_MEMPOOL_PERSIST_ARGS_H

#include <util/fs.h>

class ArgsManager;

namespace node {

/**
 * Default for -persistmempool, indicating whether the node should attempt to
 * automatically load the mempool on start and save to disk on shutdown
 */
static constexpr bool DEFAULT_PERSIST_MEMPOOL{true};

bool ShouldPersistMempool(const ArgsManager& argsman);
fs::path MempoolPath(const ArgsManager& argsman);

} // namespace node

#endif // LATTICA_NODE_MEMPOOL_PERSIST_ARGS_H