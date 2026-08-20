// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <kernel/context.h>

#include <random.h>

#include <mutex>

namespace kernel {
Context::Context()
{
    static std::once_flag globals_initialized{};
    std::call_once(globals_initialized, []() {
        // A single SHA3 implementation, so no SHA256 auto-detection to do. The
        // secp256k1 signing context is not started here either: it is the
        // ecc_context member, so its lifetime is the Context's rather than a
        // once-per-process flag.
        RandomInit();
    });
}
} // namespace kernel
