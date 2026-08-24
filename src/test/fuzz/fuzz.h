// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_TEST_FUZZ_FUZZ_H
#define LATTICA_TEST_FUZZ_FUZZ_H

#include <cstdint>
#include <functional>
#include <span>
#include <string_view>

/**
 * The registration side of the fuzz harness.
 *
 * One binary holds every target and the FUZZ environment variable names which
 * one runs, as in Bitcoin Core: linking the node stack once instead of once per
 * target is the difference between a build that is run and a build that is not.
 *
 * A target is a function from arbitrary bytes to nothing. It may reject its
 * input, and usually does -- what it may not do is read out of bounds, leak, or
 * abort. Everything reachable from a peer belongs here, and on this chain that
 * reaches further than it does on Bitcoin's: verifying a signature runs fifteen
 * thousand lines of vendored C on bytes a stranger chose.
 */
using FuzzBufferType = std::span<const uint8_t>;
using TypeTestOneInput = std::function<void(FuzzBufferType)>;

void FuzzFrameworkRegisterTarget(std::string_view name, TypeTestOneInput target);

#define FUZZ_TARGET(name)                                        \
    void name##_fuzz_target(FuzzBufferType);                     \
    namespace {                                                  \
    struct name##_Registration {                                 \
        name##_Registration()                                    \
        {                                                        \
            FuzzFrameworkRegisterTarget(#name, name##_fuzz_target); \
        }                                                        \
    } const g_##name##_registration;                             \
    }                                                            \
    void name##_fuzz_target(FuzzBufferType buffer)

#endif // LATTICA_TEST_FUZZ_FUZZ_H
