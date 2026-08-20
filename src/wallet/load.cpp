// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <wallet/load.h>

#include <common/args.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <scheduler.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/translation.h>
#include <wallet/context.h>
#include <wallet/db.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <chrono>
#include <set>
#include <string>
#include <system_error>
#include <vector>

namespace wallet {
bool VerifyWallets(WalletContext& context)
{
    interfaces::Chain& chain = *context.chain;
    ArgsManager& args = *context.args;

    if (args.IsArgSet("-walletdir")) {
        const fs::path wallet_dir{args.GetPathArg("-walletdir")};
        std::error_code ec;
        // The canonical path cleans the path, preventing >1 database environment
        // for the same directory, and strips trailing slashes so the exists /
        // is_directory checks below pass on Windows.
        fs::path canonical_wallet_dir = fs::canonical(wallet_dir, ec);
        if (ec || !fs::exists(canonical_wallet_dir)) {
            chain.initError(strprintf(_("Specified -walletdir \"%s\" does not exist"), fs::PathToString(wallet_dir)));
            return false;
        } else if (!fs::is_directory(canonical_wallet_dir)) {
            chain.initError(strprintf(_("Specified -walletdir \"%s\" is not a directory"), fs::PathToString(wallet_dir)));
            return false;
        // The canonical path transforms relative paths into absolute ones, so we check the non-canonical version.
        } else if (!wallet_dir.is_absolute()) {
            chain.initError(strprintf(_("Specified -walletdir \"%s\" is a relative path"), fs::PathToString(wallet_dir)));
            return false;
        }
        args.ForceSetArg("-walletdir", fs::PathToString(canonical_wallet_dir));
    }

    // Lattica verifies lazily on open (MakeDatabase runs the SQLite integrity
    // check via DatabaseOptions::verify); here we just ensure the wallet directory
    // exists and reject duplicate wallet names across the merged settings list.
    (void)GetWalletDir(*context.args);
    std::set<std::string> seen;
    for (const common::SettingsValue& wallet : context.chain->getSettingsList("wallet")) {
        if (!wallet.isStr()) {
            LogError("Invalid value detected for '-wallet': requires a string value.");
            return false;
        }
        if (!seen.insert(wallet.get_str()).second) {
            LogWarning("Ignoring duplicate -wallet %s.", wallet.get_str());
        }
    }
    return true;
}

bool LoadWallets(WalletContext& context)
{
    // The "wallet" settings list merges -wallet command-line args with the
    // persistent settings.json load list, so wallets the user asked to load on
    // startup (via createwallet/loadwallet/restorewallet load_on_startup) come up
    // automatically here.
    std::set<std::string> seen;
    for (const common::SettingsValue& wallet : context.chain->getSettingsList("wallet")) {
        if (!wallet.isStr()) {
            LogError("Invalid value detected for '-wallet': requires a string value.");
            return false;
        }
        const std::string name{wallet.get_str()};
        if (!seen.insert(name).second) continue; // already loaded (de-dup CLI + settings)
        DatabaseOptions options;
        DatabaseStatus status;
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        options.require_existing = true;
        options.verify = false; // already verified above
        if (!LoadWallet(context, name, /*load_on_start=*/std::nullopt, options, status, error, warnings)) {
            LogError("Failed to load wallet %s: %s", name, error.original);
            return false;
        }
        LogInfo("Loaded wallet %s", name);
    }
    return true;
}

void StartWallets(WalletContext& context, CScheduler& scheduler)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        pwallet->postInitProcess();
    }

    // Rebroadcast unconfirmed wallet transactions periodically, so a payment that
    // gets evicted from peers' mempools is re-announced instead of stalling forever.
    scheduler.scheduleEvery([&context] { MaybeResendWalletTxs(context); }, std::chrono::minutes{1});
}

void FlushWallets(WalletContext& context)
{
    // The SQLite backend commits each write synchronously, so there is nothing
    // to flush between operations (Core's BDB backend needed an explicit flush).
    (void)context;
}

void StopWallets(WalletContext& context)
{
    for (const auto& wallet : GetWallets(context)) {
        wallet->GetDatabase().Close();
    }
}

void UnloadWallets(WalletContext& context)
{
    auto wallets{GetWallets(context)};
    while (!wallets.empty()) {
        auto wallet{wallets.back()};
        wallets.pop_back();
        RemoveWallet(context, wallet);
    }
}

} // namespace wallet
