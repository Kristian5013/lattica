// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_NODE_DATABASE_ARGS_H
#define LATTICA_NODE_DATABASE_ARGS_H

class ArgsManager;
struct DBOptions;

namespace node {
void ReadDatabaseArgs(const ArgsManager& args, DBOptions& options);
} // namespace node

#endif // LATTICA_NODE_DATABASE_ARGS_H
