// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef NONTRIVIAL_THREADLOCAL_CHECK_H
#define NONTRIVIAL_THREADLOCAL_CHECK_H

#include <clang-tidy/ClangTidyCheck.h>

namespace lattica {

// Warn about any thread_local variable with a non-trivial destructor.
class NonTrivialThreadLocal final : public clang::tidy::ClangTidyCheck
{
public:
    NonTrivialThreadLocal(clang::StringRef Name, clang::tidy::ClangTidyContext* Context)
        : clang::tidy::ClangTidyCheck(Name, Context) {}

    bool isLanguageVersionSupported(const clang::LangOptions& LangOpts) const override
    {
        return LangOpts.CPlusPlus;
    }
    void registerMatchers(clang::ast_matchers::MatchFinder* Finder) override;
    void check(const clang::ast_matchers::MatchFinder::MatchResult& Result) override;
};

} // namespace lattica

#endif // NONTRIVIAL_THREADLOCAL_CHECK_H
