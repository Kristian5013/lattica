// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <wallet/wallettool.h>

#include <chainparams.h>
#include <common/args.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/translation.h>
#include <wallet/dump.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <iostream>

namespace wallet {
namespace WalletTool {

// The standard wallet deleter function blocks on the validation interface
// queue, which doesn't exist for lattica-wallet. Define our own deleter here.
static void WalletToolReleaseWallet(CWallet* wallet)
{
    wallet->WalletLogPrintf("Releasing wallet\n");
    wallet->Close();
    delete wallet;
}

static void WalletCreate(CWallet* wallet_instance, uint64_t wallet_creation_flags)
{
    LOCK(wallet_instance->cs_wallet);

    wallet_instance->InitWalletFlags(wallet_creation_flags);

    // Lattica has no descriptor ScriptPubKeyMan or keypool; the HD ML-DSA seed is
    // the keystore. Generate it unless the wallet is blank / private-keys-disabled.
    if (!wallet_instance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) &&
        !wallet_instance->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
        wallet_instance->GenerateNewSeed();
    }
}

static std::shared_ptr<CWallet> MakeWallet(const std::string& name, const fs::path& path, DatabaseOptions options)
{
    DatabaseStatus status;
    bilingual_str error;
    std::unique_ptr<WalletDatabase> database = MakeDatabase(path, options, status, error);
    if (!database) {
        tfm::format(std::cerr, "%s\n", error.original);
        return nullptr;
    }

    // dummy chain interface
    std::shared_ptr<CWallet> wallet_instance{new CWallet(/*chain=*/nullptr, name, std::move(database)), WalletToolReleaseWallet};
    wallet_instance->SetChainParams(Params());
    DBErrors load_wallet_ret;
    try {
        load_wallet_ret = wallet_instance->PopulateWalletFromDB();
    } catch (const std::runtime_error&) {
        tfm::format(std::cerr, "Error loading %s. Is wallet being used by another process?\n", name);
        return nullptr;
    }

    if (load_wallet_ret != DBErrors::LOAD_OK) {
        return nullptr;
    }

    if (options.require_create) WalletCreate(wallet_instance.get(), options.create_flags);

    return wallet_instance;
}

static void WalletShowInfo(CWallet* wallet_instance)
{
    LOCK(wallet_instance->cs_wallet);

    tfm::format(std::cout, "Wallet info\n===========\n");
    tfm::format(std::cout, "Name: %s\n", wallet_instance->GetName());
    tfm::format(std::cout, "Format: %s\n", wallet_instance->GetDatabase().Format());
    tfm::format(std::cout, "Encrypted: %s\n", wallet_instance->HasEncryptionKeys() ? "yes" : "no");
    tfm::format(std::cout, "HD (hd seed available): %s\n", wallet_instance->IsHDEnabled() ? "yes" : "no");
    tfm::format(std::cout, "Transactions: %zu\n", wallet_instance->mapWallet.size());
    tfm::format(std::cout, "Address Book: %zu\n", wallet_instance->m_address_book.size());
}

bool ExecuteWalletToolFunc(const ArgsManager& args, const std::string& command)
{
    {
        std::vector<std::string> details;
        if (!args.CheckCommandOptions(command, &details)) {
            tfm::format(std::cerr, "Error: Invalid arguments provided:\n%s\n", util::MakeUnorderedList(details));
            return false;
        }
    }
    if ((command == "create" || command == "createfromdump") && !args.IsArgSet("-wallet")) {
        tfm::format(std::cerr, "Wallet name must be provided when creating a new wallet.\n");
        return false;
    }
    const std::string name = args.GetArg("-wallet", "");
    // Lattica opens wallets by name -> <walletdir>/<name> (single SQLite backend);
    // there is no GetWalletPath/format-dispatch the way Core's BDB+SQLite build has.
    const fs::path path = GetWalletDir(args) / fs::PathFromString(name);

    if (command == "create") {
        if (name.empty()) {
            tfm::format(std::cerr, "Wallet name cannot be empty\n");
            return false;
        }
        DatabaseOptions options;
        options.require_create = true;

        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (wallet_instance) {
            WalletShowInfo(wallet_instance.get());
            wallet_instance->Close();
        }
    } else if (command == "info") {
        DatabaseOptions options;
        options.require_existing = true;
        const std::shared_ptr<CWallet> wallet_instance = MakeWallet(name, path, options);
        if (!wallet_instance) return false;
        WalletShowInfo(wallet_instance.get());
        wallet_instance->Close();
    } else if (command == "dump") {
        DatabaseOptions options;
        options.require_existing = true;
        DatabaseStatus status;

        bilingual_str error;
        std::unique_ptr<WalletDatabase> database = MakeDatabase(path, options, status, error);
        if (!database) {
            tfm::format(std::cerr, "%s\n", error.original);
            return false;
        }

        bool ret = DumpWallet(args, *database, error);
        if (!ret && !error.empty()) {
            tfm::format(std::cerr, "%s\n", error.original);
            return ret;
        }
        tfm::format(std::cout, "The dumpfile may contain private keys. To ensure the safety of your Lattica, do not share the dumpfile.\n");
        return ret;
    } else if (command == "createfromdump") {
        bilingual_str error;
        std::vector<bilingual_str> warnings;
        bool ret = CreateFromDump(args, name, path, error, warnings);
        for (const auto& warning : warnings) {
            tfm::format(std::cout, "%s\n", warning.original);
        }
        if (!ret && !error.empty()) {
            tfm::format(std::cerr, "%s\n", error.original);
        }
        return ret;
    } else {
        tfm::format(std::cerr, "Invalid command: %s\n", command);
        return false;
    }

    return true;
}
} // namespace WalletTool
} // namespace wallet
