// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_KERNEL_CONTEXT_H
#define LATTICA_KERNEL_CONTEXT_H

#include <key.h>

namespace kernel {
//! Context struct holding the kernel library's logically global state, and
//! passed to external libbitcoin_kernel functions which need access to this
//! state. The kernel library API is a work in progress, so state organization
//! and member list will evolve over time.
//!
//! State stored directly in this struct should be simple. More complex state
//! should be stored to std::unique_ptr members pointing to opaque types.
struct Context {
    //! The secp256k1 signing context, alive for as long as the kernel is.
    //!
    //! Only key generation and signing need it — verification runs on the
    //! static context, so validating a block never touches this. It lives here
    //! rather than in the wallet because the node's own miner signs too, and
    //! because "only one instance may be initialized at a time" is easiest to
    //! honour when there is exactly one owner.
    ECC_Context ecc_context{};

    Context();
};
} // namespace kernel

#endif // LATTICA_KERNEL_CONTEXT_H
