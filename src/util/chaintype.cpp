// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <util/chaintype.h>

#include <util/check.h>

#include <optional>
#include <string>

std::string ChainTypeToString(ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return "main";
    case ChainType::TESTNET:
        return "test";
    case ChainType::REGTEST:
        return "regtest";
    }
    assert(false);
}

std::optional<ChainType> ChainTypeFromString(std::string_view chain)
{
    if (chain == "main") {
        return ChainType::MAIN;
    } else if (chain == "test") {
        return ChainType::TESTNET;
    } else if (chain == "regtest") {
        return ChainType::REGTEST;
    } else {
        return std::nullopt;
    }
}
