// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_UTIL_BYTE_UNITS_H
#define LATTICA_UTIL_BYTE_UNITS_H

#include <util/overflow.h>

#include <limits>
#include <stdexcept>

namespace util::detail {
template <unsigned SHIFT>
consteval uint64_t ByteUnitsToBytes(unsigned long long units)
{
    const auto bytes{CheckedLeftShift(units, SHIFT)};
    if (!bytes || *bytes > std::numeric_limits<uint64_t>::max()) {
        throw std::overflow_error("Too large");
    }
    return *bytes;
}
} // namespace util::detail

/// Conversion of MiB to bytes.
consteval uint64_t operator""_MiB(unsigned long long mebibytes)
{
    return util::detail::ByteUnitsToBytes<20>(mebibytes);
}

/// Conversion of GiB to bytes.
consteval uint64_t operator""_GiB(unsigned long long gibibytes)
{
    return util::detail::ByteUnitsToBytes<30>(gibibytes);
}

#endif // LATTICA_UTIL_BYTE_UNITS_H
