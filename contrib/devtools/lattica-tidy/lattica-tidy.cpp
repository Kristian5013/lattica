// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include "nontrivial-threadlocal.h"

#include <clang-tidy/ClangTidyModule.h>

class LatticaModule final : public clang::tidy::ClangTidyModule
{
public:
    void addCheckFactories(clang::tidy::ClangTidyCheckFactories& CheckFactories) override
    {
        CheckFactories.registerCheck<lattica::NonTrivialThreadLocal>("lattica-nontrivial-threadlocal");
    }
};

static clang::tidy::ClangTidyModuleRegistry::Add<LatticaModule>
    X("lattica-module", "Adds lattica checks.");

volatile int LatticaModuleAnchorSource = 0;
