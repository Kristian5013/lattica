// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <script/interpreter.h>
#include <test/util/script.h>

bool IsValidFlagCombination(script_verify_flags flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}
