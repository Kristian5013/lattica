// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// util/check.h (Assert / Assume / CHECK_NONFATAL) tests.
// Standalone for now (own main); folds into the test framework when it lands.

#include <util/check.h>

#include <cstdio>
#include <stdexcept>

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
    // Assert / Assume / CHECK_NONFATAL are identity functions on truthy values.
    Check("Assert identity", Assert(42) == 42);
    Check("Assume identity", Assume(7) == 7);
    Check("CHECK_NONFATAL identity", CHECK_NONFATAL(99) == 99);

    // CHECK_NONFATAL throws (not aborts) on a false condition.
    {
        bool threw = false;
        try {
            CHECK_NONFATAL(false);
        } catch (const NonFatalCheckError&) {
            threw = true;
        }
        Check("CHECK_NONFATAL throws on false", threw);
    }

    // Under the test-only flag, a failing Assert throws instead of aborting.
    {
        test_only_CheckFailuresAreExceptionsNotAborts guard;
        bool threw = false;
        try {
            Assert(false);
        } catch (const NonFatalCheckError&) {
            threw = true;
        }
        Check("Assert throws under test flag", threw);
    }

    // The error message mentions the failed assertion text.
    {
        std::string what;
        try {
            CHECK_NONFATAL(1 == 2);
        } catch (const NonFatalCheckError& e) {
            what = e.what();
        }
        Check("error message names the assertion", what.find("1 == 2") != std::string::npos);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
