// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_TEST_UTIL_SCRIPT_H
#define LATTICA_TEST_UTIL_SCRIPT_H

#include <crypto/sha3.h>
#include <script/script.h>
#include <script/verify_flags.h>

static const std::vector<uint8_t> WITNESS_STACK_ELEM_OP_TRUE{uint8_t{OP_TRUE}};
static const CScript P2WSH_OP_TRUE{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           SHA3_256().Write(WITNESS_STACK_ELEM_OP_TRUE).Finalize(std::span<unsigned char>(hash.begin(), SHA3_256::OUTPUT_SIZE));
           return hash;
       }())};

static const std::vector<uint8_t> EMPTY{};
static const CScript P2WSH_EMPTY{
    CScript{}
    << OP_0
    << ToByteVector([] {
           uint256 hash;
           SHA3_256().Write(EMPTY).Finalize(std::span<unsigned char>(hash.begin(), SHA3_256::OUTPUT_SIZE));
           return hash;
       }())};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TRUE_STACK{{static_cast<uint8_t>(OP_TRUE)}, {}};
static const std::vector<std::vector<uint8_t>> P2WSH_EMPTY_TWO_STACK{{static_cast<uint8_t>(OP_2)}, {}};

/** Flags that are not forbidden by an assert in script validation */
bool IsValidFlagCombination(script_verify_flags flags);

#endif // LATTICA_TEST_UTIL_SCRIPT_H
