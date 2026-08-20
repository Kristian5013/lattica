// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Smoke tests for the foundational engine utilities ported for validation:
// util::Result, bilingual_str/Untranslated, FeeFrac, and FastRange. Including
// cuckoocache.h and checkqueue.h here also compile-checks those headers.

#include <util/translation.h>
#include <util/result.h>
#include <util/fastrange.h>
#include <util/feefrac.h>
#include <cuckoocache.h>
#include <checkqueue.h>

#include <cstdint>
#include <cstdio>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}
} // namespace

int main()
{
    // util::Result carries either a value or an error string.
    {
        util::Result<int> ok = 7;
        util::Result<int> err = util::Error{Untranslated("boom")};
        Check("Result has_value", ok.has_value() && ok.value() == 7);
        Check("Result error", !err.has_value() && util::ErrorString(err).original == "boom");
    }

    // bilingual_str (Untranslated does not touch G_TRANSLATION_FUN).
    {
        bilingual_str s = Untranslated("hello");
        Check("Untranslated mirrors original", s.original == "hello" && s.translated == "hello" && !s.empty());
    }

    // FeeFrac arithmetic: (10/5) + (10/5) == (20/10).
    {
        FeeFrac a{10, 5}, b{10, 5};
        Check("FeeFrac fields", a.fee == 10 && a.size == 5);
        Check("FeeFrac ==", a == b);
        Check("FeeFrac +", (a + b) == FeeFrac{20, 10});
    }

    // FastRange32 maps a 32-bit hash into [0, n).
    {
        bool inrange = true;
        for (uint32_t i = 0; i < 1000; ++i) {
            if (FastRange32(i * 2654435761u, 100) >= 100) inrange = false;
        }
        Check("FastRange32 in [0,100)", inrange);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
