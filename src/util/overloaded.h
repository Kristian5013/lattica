// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_UTIL_OVERLOADED_H
#define LATTICA_UTIL_OVERLOADED_H

namespace util {
//! Overloaded helper for std::visit. This helper and std::visit in general are
//! useful to write code that switches on a variant type. Unlike if/else-if and
//! switch/case statements, std::visit will trigger compile errors if there are
//! unhandled cases.
//!
//! Implementation comes from and example usage can be found at
//! https://en.cppreference.com/w/cpp/utility/variant/visit#Example
template<class... Ts> struct Overloaded : Ts... { using Ts::operator()...; };
} // namespace util

#endif // LATTICA_UTIL_OVERLOADED_H
