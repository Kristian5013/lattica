// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_KERNEL_CONTEXT_H
#define LATTICA_KERNEL_CONTEXT_H

namespace kernel {
//! Context struct holding the kernel library's logically global state, and
//! passed to external libbitcoin_kernel functions which need access to this
//! state. The kernel library API is a work in progress, so state organization
//! and member list will evolve over time.
//!
//! State stored directly in this struct should be simple. More complex state
//! should be stored to std::unique_ptr members pointing to opaque types.
struct Context {
    Context();
};
} // namespace kernel

#endif // LATTICA_KERNEL_CONTEXT_H
