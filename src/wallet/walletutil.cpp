// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <wallet/walletutil.h>

#include <chainparams.h>
#include <common/args.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <util/time.h>

#include <cassert>

namespace wallet {

fs::path GetWalletDir(const ArgsManager& args)
{
    if (args.IsArgSet("-walletdir")) {
        fs::path path{args.GetPathArg("-walletdir")};
        if (!fs::is_directory(path)) {
            // If the path specified doesn't exist, return the deliberately
            // invalid empty string (VerifyWallets validates it up front).
            return "";
        }
        return path;
    }
    const fs::path dir{args.GetDataDirNet() / "wallets"};
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
    }
    return dir;
}

WalletDescriptor GenerateWalletDescriptor(const CExtKey& master_key, const OutputType& addr_type, bool internal)
{
    int64_t creation_time = GetTime();

    // The xprv, not an xpub: this tree has no public derivation, so the key
    // expression carries the secret. See descriptor.cpp.
    std::string xprv = EncodeExtKey(master_key, Params());
    assert(!xprv.empty());

    // Build descriptor string
    std::string desc_prefix;
    std::string desc_suffix = "/*)";
    switch (addr_type) {
    case OutputType::LEGACY: {
        desc_prefix = "pkh(" + xprv + "/44h";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_prefix = "sh(wpkh(" + xprv + "/49h";
        desc_suffix += ")";
        break;
    }
    case OutputType::BECH32: {
        desc_prefix = "wpkh(" + xprv + "/84h";
        break;
    }
    case OutputType::BECH32M: {
        desc_prefix = "tr(" + xprv + "/86h";
        break;
    }
    case OutputType::FALCON512:
    case OutputType::MLDSA44: {
        // Witness v2, continuing BIP84's witness v0 and BIP86's witness v1. The
        // two schemes share the purpose because they share the script type; what
        // separates their keys is the tree, the scheme being part of the master
        // node's preimage rather than a step in the path.
        desc_prefix = "pqpkh(" + xprv + "/88h";
        break;
    }
    case OutputType::UNKNOWN: {
        // We should never have a DescriptorScriptPubKeyMan for an UNKNOWN OutputType,
        // so if we get to this point something is wrong
        assert(false);
    }
    } // no default case, so the compiler can warn about missing cases
    assert(!desc_prefix.empty());

    // Mainnet derives at 0', testnet and regtest derive at 1'
    if (Params().IsTestChain()) {
        desc_prefix += "/1h";
    } else {
        desc_prefix += "/0h";
    }

    std::string internal_path = internal ? "/1" : "/0";
    std::string desc_str = desc_prefix + "/0h" + internal_path + desc_suffix;

    // Make the descriptor
    FlatSigningProvider keys;
    std::string error;
    std::vector<std::unique_ptr<Descriptor>> desc = Parse(desc_str, keys, error, false);
    assert(desc.size() == 1);
    WalletDescriptor w_desc(std::move(desc.at(0)), creation_time, 0, 0, 0);
    return w_desc;
}

} // namespace wallet
