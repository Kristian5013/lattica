// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <key_io.h>

#include <bech32.h>
#include <script/script.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/overflow.h>
#include <util/strencodings.h>

#include <algorithm>
#include <string_view>
#include <variant>
#include <vector>

/// Maximum witness length for Bech32 addresses.
static constexpr std::size_t BECH32_WITNESS_PROG_MAX_LEN = 40;

namespace {
class DestinationEncoder
{
private:
    const CChainParams& m_params;

public:
    explicit DestinationEncoder(const CChainParams& params) : m_params(params) {}

    std::string operator()(const WitnessV0KeyHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(33);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV0ScriptHash& id) const
    {
        std::vector<unsigned char> data = {0};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32, m_params.Bech32HRP(), data);
    }

    // Handles WitnessUnknown and, by base binding, PayToAnchor: witness versions 1..16.
    std::string operator()(const WitnessUnknown& id) const
    {
        const std::vector<unsigned char>& program = id.GetWitnessProgram();
        if (id.GetWitnessVersion() < 1 || id.GetWitnessVersion() > 16 || program.size() < 2 || program.size() > 40) {
            return {};
        }
        std::vector<unsigned char> data = {(unsigned char)id.GetWitnessVersion()};
        data.reserve(1 + CeilDiv(program.size() * 8, 5u));
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, program.begin(), program.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    // Lattica is witness-only and SHA3-based: Core's base58 P2PKH/P2SH branches
    // (EncodeBase58Check, double-SHA256) and Taproot (WitnessV1Taproot) are absent.
    std::string operator()(const PKHash& id) const { return {}; }
    std::string operator()(const ScriptHash& id) const { return {}; }
    std::string operator()(const CNoDestination& no) const { return {}; }
    std::string operator()(const PubKeyDestination& pk) const { return {}; }
};
} // namespace

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations)
{
    std::vector<unsigned char> data;
    error_str = "";

    // Lattica addresses are bech32/bech32m exclusively (witness-only). Core's
    // base58 P2PKH/P2SH path is omitted: no legacy outputs, and EncodeBase58Check
    // is double-SHA256 while Lattica hashes with SHA3.
    const auto dec = bech32::Decode(str);
    if (dec.encoding == bech32::Encoding::BECH32 || dec.encoding == bech32::Encoding::BECH32M) {
        if (dec.data.empty()) {
            error_str = "Empty Bech32 data section";
            return CNoDestination();
        }
        // Bech32 decoding
        if (dec.hrp != params.Bech32HRP()) {
            error_str = strprintf("Invalid or unsupported prefix for Segwit (Bech32) address (expected %s, got %s).", params.Bech32HRP(), dec.hrp);
            return CNoDestination();
        }
        int version = dec.data[0]; // The first 5 bit symbol is the witness version (0-16)
        if (version == 0 && dec.encoding != bech32::Encoding::BECH32) {
            error_str = "Version 0 witness address must use Bech32 checksum";
            return CNoDestination();
        }
        if (version != 0 && dec.encoding != bech32::Encoding::BECH32M) {
            error_str = "Version 1+ witness address must use Bech32m checksum";
            return CNoDestination();
        }
        // The rest of the symbols are converted witness program bytes.
        data.reserve(((dec.data.size() - 1) * 5) / 8);
        if (ConvertBits<5, 8, false>([&](unsigned char c) { data.push_back(c); }, dec.data.begin() + 1, dec.data.end())) {
            std::string_view byte_str{data.size() == 1 ? "byte" : "bytes"};

            if (version == 0) {
                {
                    WitnessV0KeyHash keyid;
                    if (data.size() == keyid.size()) {
                        std::copy(data.begin(), data.end(), keyid.begin());
                        return keyid;
                    }
                }
                {
                    WitnessV0ScriptHash scriptid;
                    if (data.size() == scriptid.size()) {
                        std::copy(data.begin(), data.end(), scriptid.begin());
                        return scriptid;
                    }
                }

                error_str = strprintf("Invalid Bech32 v0 address program size (%d %s), per BIP141", data.size(), byte_str);
                return CNoDestination();
            }

            // Lattica has no Taproot, so a version 1 / 32-byte program is not a
            // WitnessV1Taproot; it falls through to the upgradable WitnessUnknown.

            if (CScript::IsPayToAnchor(version, data)) {
                return PayToAnchor();
            }

            if (version > 16) {
                error_str = "Invalid Bech32 address witness version";
                return CNoDestination();
            }

            if (data.size() < 2 || data.size() > BECH32_WITNESS_PROG_MAX_LEN) {
                error_str = strprintf("Invalid Bech32 address program size (%d %s)", data.size(), byte_str);
                return CNoDestination();
            }

            return WitnessUnknown{version, data};
        } else {
            error_str = strprintf("Invalid padding in Bech32 data section");
            return CNoDestination();
        }
    }

    // Not a Bech32(m) string (and Lattica has no base58 addresses): run the bech32
    // error locator to give a helpful message / error positions.
    auto res = bech32::LocateErrors(str);
    error_str = res.first;
    if (error_locations) *error_locations = std::move(res.second);
    return CNoDestination();
}

std::string EncodeDestination(const CTxDestination& dest, const CChainParams& params)
{
    return std::visit(DestinationEncoder(params), dest);
}

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params)
{
    std::string error_msg;
    return DecodeDestination(str, params, error_msg, nullptr);
}

bool IsValidDestinationString(const std::string& str, const CChainParams& params)
{
    std::string error_msg;
    return IsValidDestination(DecodeDestination(str, params, error_msg, nullptr));
}
