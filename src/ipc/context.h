// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_IPC_CONTEXT_H
#define LATTICA_IPC_CONTEXT_H

namespace ipc {
//! Context struct used to give IPC protocol implementations or implementation
//! hooks access to application state, in case they need to run extra code that
//! isn't needed within a single process, like code copying global state from an
//! existing process to a new process when it's initialized, or code dealing
//! with shared objects that are created or destroyed remotely.
struct Context
{
};
} // namespace ipc

#endif // LATTICA_IPC_CONTEXT_H
