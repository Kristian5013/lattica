// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

//! @file kernel/types.h is a home for simple enum and struct type definitions
//! that can be used internally by functions in the libbitcoin_kernel library,
//! but also used externally by node, wallet, and GUI code.
//!
//! This file is intended to define only simple types that do not have external
//! dependencies. More complicated types should be defined in dedicated header
//! files.

#ifndef LATTICA_KERNEL_TYPES_H
#define LATTICA_KERNEL_TYPES_H

namespace kernel {
//! Information about chainstate that notifications are sent from.
struct ChainstateRole {
    //! Whether this is a notification from a chainstate that's been fully
    //! validated starting from the genesis block. False if it is from an
    //! assumeutxo snapshot chainstate that has not been validated yet.
    bool validated{true};

    //! Whether this is a historical chainstate downloading old blocks to
    //! validate an assumeutxo snapshot, not syncing to the network tip.
    bool historical{false};
};
} // namespace kernel

#endif // LATTICA_KERNEL_TYPES_H
