// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <kernel/checks.h>

#include <random.h>
#include <util/result.h>
#include <util/translation.h>

#include <string>

namespace kernel {

util::Result<void> SanityChecks(const Context&)
{
    if (!Random_SanityCheck()) {
        return util::Error{Untranslated("OS cryptographic RNG sanity check failure. Aborting.")};
    }

    return {};
}

}