// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_KERNEL_MEMPOOL_REMOVAL_REASON_H
#define LATTICA_KERNEL_MEMPOOL_REMOVAL_REASON_H

#include <string>

/** Reason why a transaction was removed from the mempool,
 * this is passed to the notification signal.
 */
enum class MemPoolRemovalReason {
    EXPIRY,      //!< Expired from mempool
    SIZELIMIT,   //!< Removed in size limiting
    REORG,       //!< Removed for reorganization
    BLOCK,       //!< Removed for block
    CONFLICT,    //!< Removed for conflict with in-block transaction
    REPLACED,    //!< Removed for replacement
};

std::string RemovalReasonToString(const MemPoolRemovalReason& r) noexcept;

#endif // LATTICA_KERNEL_MEMPOOL_REMOVAL_REASON_H
