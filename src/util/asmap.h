// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_UTIL_ASMAP_H
#define LATTICA_UTIL_ASMAP_H

#include <uint256.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

uint32_t Interpret(std::span<const std::byte> asmap, std::span<const std::byte> ip);

bool SanityCheckAsmap(std::span<const std::byte> asmap, int bits);
/** Check standard asmap data (128 bits for IPv6) */
bool CheckStandardAsmap(std::span<const std::byte> data);

/** Read and check asmap from provided binary file */
std::vector<std::byte> DecodeAsmap(fs::path path);
/** Calculate the asmap version, a checksum identifying the asmap being used. */
uint256 AsmapVersion(std::span<const std::byte> data);

#endif // LATTICA_UTIL_ASMAP_H
