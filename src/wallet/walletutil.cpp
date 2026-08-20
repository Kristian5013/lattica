// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <wallet/walletutil.h>

#include <common/args.h>

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
} // namespace wallet
