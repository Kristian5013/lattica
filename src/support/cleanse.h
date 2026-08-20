// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_SUPPORT_CLEANSE_H
#define LATTICA_SUPPORT_CLEANSE_H

#include <cstdlib>

/** Secure overwrite a buffer (possibly containing secret data) with zero-bytes. The write
 * operation will not be optimized out by the compiler. */
void memory_cleanse(void *ptr, size_t len);

#endif // LATTICA_SUPPORT_CLEANSE_H
