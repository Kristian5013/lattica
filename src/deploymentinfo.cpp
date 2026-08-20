// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <deploymentinfo.h>

#include <consensus/params.h>

#include <array>
#include <string_view>

namespace {
constexpr std::array<VBDeploymentInfo, Consensus::MAX_VERSION_BITS_DEPLOYMENTS> g_deployment_info{
    VBDeploymentInfo{
        .name = "testdummy",
        .gbt_optional_rule = true,
    },
};

// A DeploymentPos added without a matching entry here leaves the array element
// value-initialised, so .name is nullptr — and chainparams.cpp:73 compares it
// against a std::string, which reads through the null pointer. That happens on
// any -vbparams, on any chain, before the node is up. The comment in params.h
// asks for this entry; this turns the request into something the compiler
// enforces.
static_assert([] {
    for (const auto& d : g_deployment_info) {
        if (d.name == nullptr) return false;
    }
    return true;
}(), "every DeploymentPos needs an entry in VersionBitsDeploymentInfo");
} // namespace

const std::array<VBDeploymentInfo,Consensus::MAX_VERSION_BITS_DEPLOYMENTS>
    VersionBitsDeploymentInfo{g_deployment_info};

std::string DeploymentName(Consensus::BuriedDeployment dep)
{
    assert(ValidDeployment(dep));
    switch (dep) {
    case Consensus::DEPLOYMENT_HEIGHTINCB:
        return "bip34";
    case Consensus::DEPLOYMENT_CLTV:
        return "bip65";
    case Consensus::DEPLOYMENT_DERSIG:
        return "bip66";
    case Consensus::DEPLOYMENT_CSV:
        return "csv";
    case Consensus::DEPLOYMENT_SEGWIT:
        return "segwit";
    } // no default case, so the compiler can warn about missing cases
    return "";
}

std::optional<Consensus::BuriedDeployment> GetBuriedDeployment(const std::string_view name)
{
    if (name == "segwit") {
        return Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT;
    } else if (name == "bip34") {
        return Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB;
    } else if (name == "dersig") {
        return Consensus::BuriedDeployment::DEPLOYMENT_DERSIG;
    } else if (name == "cltv") {
        return Consensus::BuriedDeployment::DEPLOYMENT_CLTV;
    } else if (name == "csv") {
        return Consensus::BuriedDeployment::DEPLOYMENT_CSV;
    }
    return std::nullopt;
}
