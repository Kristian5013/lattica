// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_KERNEL_CS_MAIN_H
#define LATTICA_KERNEL_CS_MAIN_H

#include <sync.h>

/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
extern RecursiveMutex cs_main;

#endif // LATTICA_KERNEL_CS_MAIN_H
