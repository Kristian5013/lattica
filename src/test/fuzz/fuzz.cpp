// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <test/fuzz/fuzz.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <key.h>
#include <util/translation.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
using TargetMap = std::map<std::string, TypeTestOneInput, std::less<>>;

//! Constructed on first use: the registrations run before main and before any
//! other file-scope object of this binary is guaranteed to exist.
TargetMap& Targets()
{
    static TargetMap g_targets;
    return g_targets;
}

TypeTestOneInput* g_selected{nullptr};

//! Everything a target may need but must not set up itself, since libFuzzer
//! calls the target millions of times and initialisation is not free.
struct Environment {
    ECC_Context ecc;
    Environment() { SelectParams(ChainType::REGTEST); }
};
} // namespace

void FuzzFrameworkRegisterTarget(std::string_view name, TypeTestOneInput target)
{
    const auto [_, inserted] = Targets().try_emplace(std::string{name}, std::move(target));
    if (!inserted) {
        std::fprintf(stderr, "fuzz: target '%.*s' is registered twice\n", (int)name.size(), name.data());
        std::abort();
    }
}

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    static const Environment env;

    const char* name = std::getenv("FUZZ");
    if (name == nullptr) {
        std::fprintf(stderr, "fuzz: set FUZZ to the target to run. Available:\n");
        for (const auto& [target_name, _] : Targets()) {
            std::fprintf(stderr, "  %s\n", target_name.c_str());
        }
        std::exit(1);
    }

    const auto it = Targets().find(name);
    if (it == Targets().end()) {
        std::fprintf(stderr, "fuzz: no target named '%s'. Available:\n", name);
        for (const auto& [target_name, _] : Targets()) {
            std::fprintf(stderr, "  %s\n", target_name.c_str());
        }
        std::exit(1);
    }
    g_selected = &it->second;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    (*g_selected)({data, size});
    return 0;
}
