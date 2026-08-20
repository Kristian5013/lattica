// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_UTIL_THREADNAMES_H
#define LATTICA_UTIL_THREADNAMES_H

#include <string>

namespace util {
//! Rename a thread both in terms of an internal (in-memory) name as well
//! as its system thread name.
//! @note Do not call this for the main thread, as this will interfere with
//! UNIX utilities such as top and killall. Use ThreadSetInternalName instead.
void ThreadRename(const std::string&);

//! Set the internal (in-memory) name of the current thread only.
void ThreadSetInternalName(const std::string&);

//! Get the thread's internal (in-memory) name; used e.g. for identification in
//! logging.
std::string ThreadGetInternalName();

} // namespace util

#endif // LATTICA_UTIL_THREADNAMES_H
