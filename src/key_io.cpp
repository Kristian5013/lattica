// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <key_io.h>

#include <base58.h>
#include <bech32.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/overflow.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstring>
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

    std::string operator()(const PKHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

    std::string operator()(const ScriptHash& id) const
    {
        std::vector<unsigned char> data = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        data.insert(data.end(), id.begin(), id.end());
        return EncodeBase58Check(data);
    }

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

    std::string operator()(const WitnessV1Taproot& tap) const
    {
        std::vector<unsigned char> data = {1};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, tap.begin(), tap.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV2KeyHash& id) const
    {
        std::vector<unsigned char> data = {2};
        data.reserve(33);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

    std::string operator()(const WitnessV2ScriptHash& id) const
    {
        std::vector<unsigned char> data = {2};
        data.reserve(53);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, id.begin(), id.end());
        return bech32::Encode(bech32::Encoding::BECH32M, m_params.Bech32HRP(), data);
    }

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

    std::string operator()(const CNoDestination& no) const { return {}; }
    std::string operator()(const PubKeyDestination& pk) const { return {}; }
};
} // namespace

CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations)
{
    std::vector<unsigned char> data;
    uint160 hash;
    error_str = "";

    // Note this will be false if it is a valid Bech32 address for a different network.
    //
    // Core compares the first HRP-many characters, which is safe for Bitcoin:
    // its base58 addresses begin with '1' or '3' and cannot collide with "bc".
    // They collide here. The mainnet HRP is "la" and a P2PKH address begins with
    // 'L', so "La..." would be taken for bech32 and about one P2PKH address in
    // thirty would stop decoding altogether. What actually delimits an HRP is
    // the separator, and the bech32 data charset excludes '1', so the last one
    // in the string is it -- which a base58 address will not match.
    const size_t sep = str.rfind('1');
    const bool is_bech32 = sep != std::string::npos && ToLower(str.substr(0, sep)) == params.Bech32HRP();

    if (!is_bech32 && DecodeBase58Check(str, data, 21)) {
        // base58-encoded addresses.
        // The data vector contains RIPEMD160(SHA3-256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return PKHash(hash);
        }
        // The data vector contains RIPEMD160(SHA3-256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return ScriptHash(hash);
        }

        // If the prefix of data matches either the script or pubkey prefix, the length must have been wrong
        if ((data.size() >= script_prefix.size() &&
                std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) ||
            (data.size() >= pubkey_prefix.size() &&
                std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin()))) {
            error_str = "Invalid length for Base58 address (P2PKH or P2SH)";
        } else {
            error_str = "Invalid or unsupported Base58-encoded address.";
        }
        return CNoDestination();
    } else if (!is_bech32) {
        // Try Base58 decoding without the checksum, using a much larger max length
        if (!DecodeBase58(str, data, 100)) {
            // Core reports the prefix mismatch from inside the bech32 branch,
            // which the stricter routing above can no longer reach: a string
            // with another network's HRP never gets there. Pasting a testnet
            // address into a mainnet field is common enough to be worth naming,
            // so ask bech32 what it is before giving up on it.
            const auto dec = bech32::Decode(str);
            if (dec.encoding != bech32::Encoding::INVALID) {
                error_str = strprintf("Invalid or unsupported prefix for Segwit (Bech32) address (expected %s, got %s).", params.Bech32HRP(), dec.hrp);
            } else {
                error_str = "Invalid or unsupported Segwit (Bech32) or Base58 encoding.";
            }
        } else {
            error_str = "Invalid checksum or length of Base58 address (P2PKH or P2SH)";
        }
        return CNoDestination();
    }

    data.clear();
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

            if (version == 1 && data.size() == WITNESS_V1_TAPROOT_SIZE) {
                static_assert(WITNESS_V1_TAPROOT_SIZE == WitnessV1Taproot::size());
                WitnessV1Taproot tap;
                std::copy(data.begin(), data.end(), tap.begin());
                return tap;
            }

            if (version == 2) {
                {
                    WitnessV2KeyHash keyid;
                    if (data.size() == keyid.size()) {
                        std::copy(data.begin(), data.end(), keyid.begin());
                        return keyid;
                    }
                }
                {
                    WitnessV2ScriptHash scriptid;
                    if (data.size() == scriptid.size()) {
                        std::copy(data.begin(), data.end(), scriptid.begin());
                        return scriptid;
                    }
                }

                error_str = strprintf("Invalid Bech32m v2 address program size (%d %s)", data.size(), byte_str);
                return CNoDestination();
            }

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

    // Perform Bech32 error location
    auto res = bech32::LocateErrors(str);
    error_str = res.first;
    if (error_locations) *error_locations = std::move(res.second);
    return CNoDestination();
}

CKey DecodeSecret(const std::string& str, const CChainParams& params)
{
    CKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 34)) {
        const std::vector<unsigned char>& privkey_prefix = params.Base58Prefix(CChainParams::SECRET_KEY);
        // Core accepts the payload with or without the trailing compression flag,
        // the flag being what tells an uncompressed public key from a compressed
        // one. Every secp256k1 key here is compressed, so the flag has one legal
        // value; a payload without it is a key from a wallet that predates the
        // rule and is refused rather than guessed at.
        if (data.size() == CKey::SECP256K1_SIZE + 1 + privkey_prefix.size() && data.back() == 1 &&
            std::equal(privkey_prefix.begin(), privkey_prefix.end(), data.begin())) {
            // The scalar is the seed, which is what MakeKeyFromSeed takes: it also
            // derives the public key, which a CKey cannot be without.
            key.MakeKeyFromSeed(CKey::SECP256K1_SIZE,
                                std::span{data}.subspan(privkey_prefix.size(), CKey::SECP256K1_SIZE));
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeSecret(const CKey& key, const CChainParams& params)
{
    assert(key.IsValid());
    // WIF is Bitcoin's envelope for a 32-byte scalar. Neither lattice secret is
    // one, and base58 over 2560 bytes would not be an improvement on hex.
    if (key.size() != CKey::SECP256K1_SIZE) return {};
    std::vector<unsigned char> data = params.Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), key.begin(), key.end());
    data.push_back(1);
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
}

CExtPubKey DecodeExtPubKey(const std::string& str, const CChainParams& params)
{
    CExtPubKey key;
    std::vector<unsigned char> data;
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = params.Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
        if (data.size() == BIP32_EXTKEY_SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    return key;
}

std::string EncodeExtPubKey(const CExtPubKey& key, const CChainParams& params)
{
    std::vector<unsigned char> data = params.Base58Prefix(CChainParams::EXT_PUBLIC_KEY);
    size_t size = data.size();
    data.resize(size + BIP32_EXTKEY_SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    return ret;
}

CExtKey DecodeExtKey(const std::string& str, const CChainParams& params)
{
    CExtKey key;
    std::vector<unsigned char> data;
    // CExtKey::SIZE where Core has BIP32_EXTKEY_SIZE: an extended key here
    // carries the 32-byte node seed a child is derived from, not a 33-byte key.
    if (DecodeBase58Check(str, data, 78)) {
        const std::vector<unsigned char>& prefix = params.Base58Prefix(CChainParams::EXT_SECRET_KEY);
        if (data.size() == CExtKey::SIZE + prefix.size() && std::equal(prefix.begin(), prefix.end(), data.begin())) {
            key.Decode(data.data() + prefix.size());
        }
    }
    if (!data.empty()) {
        memory_cleanse(data.data(), data.size());
    }
    return key;
}

std::string EncodeExtKey(const CExtKey& key, const CChainParams& params)
{
    std::vector<unsigned char> data = params.Base58Prefix(CChainParams::EXT_SECRET_KEY);
    size_t size = data.size();
    data.resize(size + CExtKey::SIZE);
    key.Encode(data.data() + size);
    std::string ret = EncodeBase58Check(data);
    memory_cleanse(data.data(), data.size());
    return ret;
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
