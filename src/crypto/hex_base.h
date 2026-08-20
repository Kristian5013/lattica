// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_CRYPTO_HEX_BASE_H
#define LATTICA_CRYPTO_HEX_BASE_H

#include <span.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

/**
 * Convert a span of bytes to a lower-case hexadecimal string.
 */
std::string HexStr(std::span<const uint8_t> s);
inline std::string HexStr(std::span<const char> s) { return HexStr(MakeUCharSpan(s)); }
inline std::string HexStr(std::span<const std::byte> s) { return HexStr(MakeUCharSpan(s)); }

signed char HexDigit(char c);

#endif // LATTICA_CRYPTO_HEX_BASE_H
