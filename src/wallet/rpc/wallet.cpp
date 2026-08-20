// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <wallet/rpc/wallet.h>
#include <wallet/rpc/util.h>

#include <chainparams.h>
#include <coins.h>
#include <core_io.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/translation.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/wallet.h>

#include <map>
#include <optional>
#include <string_view>

namespace wallet {

//! Human-readable names for the wallet flags Lattica supports (Core keeps the
//! WALLET_FLAG_TO_STRING / STRING_TO_WALLET_FLAG maps in walletflags; Lattica's
//! reduced flag set is small enough to spell out here).
static const std::map<std::string, uint64_t> STRING_TO_WALLET_FLAG{
    {"avoid_reuse", WALLET_FLAG_AVOID_REUSE},
    {"blank", WALLET_FLAG_BLANK_WALLET},
    {"disable_private_keys", WALLET_FLAG_DISABLE_PRIVATE_KEYS},
};

static std::string WalletFlagToString(uint64_t flag)
{
    for (const auto& [name, value] : STRING_TO_WALLET_FLAG) {
        if (value == flag) return name;
    }
    return "";
}

static const std::map<uint64_t, std::string> WALLET_FLAG_CAVEATS{
    {WALLET_FLAG_AVOID_REUSE,
     "You need to rescan the blockchain in order to correctly mark used "
     "destinations in the past. Until this is done, some destinations may "
     "be considered unused, even if the opposite is the case."},
};

static RPCMethod getwalletinfo()
{
    return RPCMethod{"getwalletinfo",
                "Returns an object containing various wallet state info.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                        {RPCResult::Type::NUM, "walletversion", "(DEPRECATED) the wallet version, kept for backwards compatibility"},
                        {RPCResult::Type::STR, "format", "the database format (only sqlite)"},
                        {RPCResult::Type::NUM, "txcount", "the total number of transactions in the wallet"},
                        {RPCResult::Type::NUM_TIME, "unlocked_until", /*optional=*/true, "the " + UNIX_EPOCH_TIME + " until which the wallet is unlocked for transfers, or 0 if the wallet is locked (only present for passphrase-encrypted wallets)"},
                        {RPCResult::Type::BOOL, "private_keys_enabled", "false if privatekeys are disabled for this wallet (enforced watch-only wallet)"},
                        {RPCResult::Type::BOOL, "avoid_reuse", "whether this wallet tracks clean/dirty coins in terms of reuse"},
                        {RPCResult::Type::BOOL, "scanning", "always false (Lattica has no background rescan)"},
                        {RPCResult::Type::BOOL, "descriptors", "always false (Lattica uses a native HD ML-DSA keystore, not Core output descriptors)"},
                        {RPCResult::Type::BOOL, "external_signer", "always false (no external signer support)"},
                        {RPCResult::Type::BOOL, "blank", "Whether this wallet intentionally does not contain any keys"},
                        {RPCResult::Type::NUM_TIME, "birthtime", /*optional=*/true, "The start time for blocks scanning."},
                        {RPCResult::Type::ARR, "flags", "The flags currently set on the wallet",
                        {
                            {RPCResult::Type::STR, "flag", "The name of the flag"},
                        }},
                        RESULT_LAST_PROCESSED_BLOCK,
                    }},
                },
                RPCExamples{
                    HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);

    const int latest_legacy_wallet_minversion{169900};

    obj.pushKV("walletname", pwallet->GetName());
    obj.pushKV("walletversion", latest_legacy_wallet_minversion);
    obj.pushKV("format", pwallet->GetDatabase().Format());
    obj.pushKV("txcount", (int)pwallet->mapWallet.size());

    if (pwallet->HasEncryptionKeys()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("private_keys_enabled", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    obj.pushKV("avoid_reuse", pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE));
    obj.pushKV("scanning", false);
    obj.pushKV("descriptors", false);
    obj.pushKV("external_signer", false);
    obj.pushKV("blank", pwallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    if (int64_t birthtime = pwallet->GetBirthTime(); birthtime > 0) {
        obj.pushKV("birthtime", birthtime);
    }

    // Push known flags
    UniValue flags(UniValue::VARR);
    uint64_t wallet_flags = pwallet->GetWalletFlags();
    for (uint64_t i = 0; i < 64; ++i) {
        uint64_t flag = uint64_t{1} << i;
        if (flag & wallet_flags) {
            if (flag & KNOWN_WALLET_FLAGS) {
                flags.push_back(WalletFlagToString(flag));
            } else {
                flags.push_back(strprintf("unknown_flag_%u", i));
            }
        }
    }
    obj.pushKV("flags", flags);

    AppendLastProcessedBlock(obj, *pwallet);
    return obj;
},
    };
}

static RPCMethod listwalletdir()
{
    return RPCMethod{"listwalletdir",
                "Returns a list of wallets in the wallet directory.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "wallets", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "name", "The wallet name"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwalletdir", "")
            + HelpExampleRpc("listwalletdir", "")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    UniValue wallets(UniValue::VARR);
    // Lattica has no ListDatabases helper (a single SQLite backend); a wallet is a
    // subdirectory of the wallets dir that holds a wallet.dat file.
    const fs::path wallet_dir{GetWalletDir(*context.args)};
    std::error_code ec;
    for (fs::directory_iterator it{wallet_dir, ec}, end; it != end && !ec; it.increment(ec)) {
        if (!it->is_directory()) continue;
        if (!fs::exists(it->path() / "wallet.dat")) continue;
        UniValue wallet(UniValue::VOBJ);
        wallet.pushKV("name", fs::PathToString(it->path().filename()));
        wallets.push_back(std::move(wallet));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallets", std::move(wallets));
    return result;
},
    };
}

static RPCMethod listwallets()
{
    return RPCMethod{"listwallets",
                "Returns a list of currently loaded wallets.\n"
                "For full information on the wallet, use \"getwalletinfo\"\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue obj(UniValue::VARR);

    WalletContext& context = EnsureWalletContext(request.context);
    for (const std::shared_ptr<CWallet>& wallet : GetWallets(context)) {
        LOCK(wallet->cs_wallet);
        obj.push_back(wallet->GetName());
    }

    return obj;
},
    };
}

static RPCMethod loadwallet()
{
    return RPCMethod{
        "loadwallet",
        "Loads a wallet from a wallet file or directory.\n",
                {
                    {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The wallet directory or .dat file."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "name", "The wallet name if loaded successfully."},
                        {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to loading the wallet.",
                        {
                            {RPCResult::Type::STR, "", ""},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("loadwallet", "\"walletname\"")
                    + HelpExampleRpc("loadwallet", "\"walletname\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    const std::string name(request.params[0].get_str());

    DatabaseOptions options;
    DatabaseStatus status;
    options.require_existing = true;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    std::optional<bool> load_on_start = request.params[1].isNull() ? std::nullopt : std::optional<bool>(request.params[1].get_bool());

    {
        LOCK(context.wallets_mutex);
        if (std::any_of(context.wallets.begin(), context.wallets.end(), [&name](const auto& wallet) { return wallet->GetName() == name; })) {
            throw JSONRPCError(RPC_WALLET_ALREADY_LOADED, "Wallet \"" + name + "\" is already loaded.");
        }
    }

    std::shared_ptr<CWallet> const wallet = LoadWallet(context, name, load_on_start, options, status, error, warnings);

    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;
},
    };
}

static RPCMethod setwalletflag()
{
            std::string flags;
            for (auto& it : STRING_TO_WALLET_FLAG)
                if (it.second & MUTABLE_WALLET_FLAGS)
                    flags += (flags == "" ? "" : ", ") + it.first;

    return RPCMethod{
        "setwalletflag",
        "Change the state of the given wallet flag for a wallet.\n",
                {
                    {"flag", RPCArg::Type::STR, RPCArg::Optional::NO, "The name of the flag to change. Current available flags: " + flags},
                    {"value", RPCArg::Type::BOOL, RPCArg::Default{true}, "The new state."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "flag_name", "The name of the flag that was modified"},
                        {RPCResult::Type::BOOL, "flag_state", "The new state of the flag"},
                        {RPCResult::Type::STR, "warnings", /*optional=*/true, "Any warnings associated with the change"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("setwalletflag", "avoid_reuse")
                  + HelpExampleRpc("setwalletflag", "\"avoid_reuse\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::string flag_str = request.params[0].get_str();
    bool value = request.params[1].isNull() || request.params[1].get_bool();

    if (!STRING_TO_WALLET_FLAG.contains(flag_str)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown wallet flag: %s", flag_str));
    }

    auto flag = STRING_TO_WALLET_FLAG.at(flag_str);

    if (!(flag & MUTABLE_WALLET_FLAGS)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is immutable: %s", flag_str));
    }

    UniValue res(UniValue::VOBJ);

    if (pwallet->IsWalletFlagSet(flag) == value) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is already set to %s: %s", value ? "true" : "false", flag_str));
    }

    res.pushKV("flag_name", flag_str);
    res.pushKV("flag_state", value);

    if (value) {
        pwallet->SetWalletFlag(flag);
    } else {
        pwallet->UnsetWalletFlag(flag);
    }

    if (flag && value && WALLET_FLAG_CAVEATS.contains(flag)) {
        res.pushKV("warnings", WALLET_FLAG_CAVEATS.at(flag));
    }

    return res;
},
    };
}

static RPCMethod createwallet()
{
    return RPCMethod{
        "createwallet",
        "Creates and loads a new wallet.\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name for the new wallet. If this is a path, the wallet will be created at the path location."},
            {"disable_private_keys", RPCArg::Type::BOOL, RPCArg::Default{false}, "Disable the possibility of private keys (only watchonlys are possible in this mode)."},
            {"blank", RPCArg::Type::BOOL, RPCArg::Default{false}, "Create a blank wallet. A blank wallet has no keys."},
            {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Encrypt the wallet with this passphrase."},
            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{false}, "Keep track of coin reuse, and treat dirty and clean coins differently with privacy considerations in mind."},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if created successfully."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to creating and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("createwallet", "\"testwallet\"")
            + HelpExampleRpc("createwallet", "\"testwallet\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    uint64_t flags = 0;
    if (!request.params[1].isNull() && request.params[1].get_bool()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    SecureString passphrase;
    passphrase.reserve(100);
    std::vector<bilingual_str> warnings;
    if (!request.params[3].isNull()) {
        passphrase = std::string_view{request.params[3].get_str()};
        if (passphrase.empty()) {
            // Empty string means unencrypted
            warnings.emplace_back(Untranslated("Empty string given as passphrase, wallet will not be encrypted."));
        }
    }

    if (!request.params[4].isNull() && request.params[4].get_bool()) {
        flags |= WALLET_FLAG_AVOID_REUSE;
    }

    DatabaseOptions options;
    DatabaseStatus status;
    options.require_create = true;
    options.create_flags = flags;
    options.create_passphrase = passphrase;
    bilingual_str error;
    std::optional<bool> load_on_start = request.params[5].isNull() ? std::nullopt : std::optional<bool>(request.params[5].get_bool());
    const std::shared_ptr<CWallet> wallet = CreateWallet(context, request.params[0].get_str(), load_on_start, options, status, error, warnings);
    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;
},
    };
}

static RPCMethod unloadwallet()
{
    return RPCMethod{"unloadwallet",
                "Unloads the wallet referenced by the request endpoint or the wallet_name argument.\n"
                "If both are specified, they must be identical.",
                {
                    {"wallet_name", RPCArg::Type::STR, RPCArg::DefaultHint{"the wallet name from the RPC endpoint"}, "The name of the wallet to unload. If provided both here and in the RPC endpoint, the two must be identical."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to unloading the wallet.",
                    {
                        {RPCResult::Type::STR, "", ""},
                    }},
                }},
                RPCExamples{
                    HelpExampleCli("unloadwallet", "wallet_name")
            + HelpExampleRpc("unloadwallet", "wallet_name")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string wallet_name{EnsureUniqueWalletName(request, self.MaybeArg<std::string_view>("wallet_name"))};

    WalletContext& context = EnsureWalletContext(request.context);
    std::shared_ptr<CWallet> wallet = GetWallet(context, wallet_name);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    }

    std::vector<bilingual_str> warnings;
    // Update the persistent load-on-startup setting before releasing the wallet.
    std::optional<bool> load_on_start{self.MaybeArg<bool>("load_on_startup")};
    if (load_on_start && context.chain) {
        if (load_on_start.value() && !AddWalletSetting(*context.chain, wallet_name)) {
            warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."));
        } else if (!load_on_start.value() && !RemoveWalletSetting(*context.chain, wallet_name)) {
            warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may still be loaded next node startup."));
        }
    }

    // Release the "main" shared pointer and prevent further notifications.
    if (!RemoveWallet(context, wallet)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Requested wallet already unloaded");
    }
    wallet.reset();

    UniValue result(UniValue::VOBJ);
    PushWarnings(warnings, result);

    return result;
},
    };
}

RPCMethod simulaterawtransaction()
{
    return RPCMethod{
        "simulaterawtransaction",
        "Calculate the balance change resulting in the signing and broadcasting of the given transaction(s).\n",
        {
            {"rawtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "An array of hex strings of raw transactions.\n",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "(DEPRECATED) No longer used"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "balance_change", "The wallet balance change (negative means decrease)."},
            }
        },
        RPCExamples{
            HelpExampleCli("simulaterawtransaction", "[\"myhex\"]")
            + HelpExampleRpc("simulaterawtransaction", "[\"myhex\"]")
        },
    [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> rpc_wallet = GetWalletForJSONRPCRequest(request);
    if (!rpc_wallet) return UniValue::VNULL;
    const CWallet& wallet = *rpc_wallet;

    LOCK(wallet.cs_wallet);

    const auto& txs = request.params[0].get_array();
    CAmount changes{0};
    std::map<COutPoint, CAmount> new_utxos; // UTXO:s that were made available in transaction array
    std::set<COutPoint> spent;

    for (size_t i = 0; i < txs.size(); ++i) {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, txs[i].get_str(), /*try_no_witness=*/ true, /*try_witness=*/ true)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction hex string decoding failure.");
        }

        // Fetch previous transactions (inputs)
        std::map<COutPoint, Coin> coins;
        for (const CTxIn& txin : mtx.vin) {
            coins[txin.prevout]; // Create empty map entry keyed by prevout.
        }
        wallet.chain().findCoins(coins);

        // Fetch debit; we are *spending* these.
        for (const auto& txin : mtx.vin) {
            const auto& outpoint = txin.prevout;
            if (spent.contains(outpoint)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction(s) are spending the same output more than once");
            }
            if (new_utxos.contains(outpoint)) {
                changes -= new_utxos.at(outpoint);
                new_utxos.erase(outpoint);
            } else {
                if (coins.at(outpoint).IsSpent()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "One or more transaction inputs are missing or have been spent already");
                }
                changes -= wallet.GetDebit(txin);
            }
            spent.insert(outpoint);
        }

        // Iterate over outputs; we are *receiving* these, if the wallet considers them "mine".
        const auto& hash = mtx.GetHash();
        for (size_t j = 0; j < mtx.vout.size(); ++j) {
            const auto& txout = mtx.vout[j];
            bool is_mine = wallet.IsMine(txout);
            changes += new_utxos[COutPoint(hash, j)] = is_mine ? txout.nValue : 0;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("balance_change", ValueFromAmount(changes));

    return result;
}
    };
}

// RPC commands defined across the other wallet/rpc/*.cpp files.
RPCMethod getreceivedbyaddress();
RPCMethod getreceivedbylabel();
RPCMethod getbalance();
RPCMethod getbalances();
RPCMethod lockunspent();
RPCMethod listlockunspent();
RPCMethod listunspent();
RPCMethod getnewaddress();
RPCMethod getrawchangeaddress();
RPCMethod setlabel();
RPCMethod listaddressgroupings();
RPCMethod getaddressinfo();
RPCMethod getaddressesbylabel();
RPCMethod listlabels();
RPCMethod listreceivedbyaddress();
RPCMethod listreceivedbylabel();
RPCMethod listtransactions();
RPCMethod listsinceblock();
RPCMethod gettransaction();
RPCMethod abandontransaction();
RPCMethod rescanblockchain();
RPCMethod abortrescan();
RPCMethod importprunedfunds();
RPCMethod removeprunedfunds();
RPCMethod backupwallet();
RPCMethod restorewallet();
RPCMethod walletpassphrase();
RPCMethod walletpassphrasechange();
RPCMethod walletlock();
RPCMethod encryptwallet();
RPCMethod signmessage();
RPCMethod sendtoaddress();
RPCMethod sendmany();
RPCMethod fundrawtransaction();
RPCMethod signrawtransactionwithwallet();
RPCMethod bumpfee();
RPCMethod send();
RPCMethod sendall();

std::span<const CRPCCommand> GetWalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &fundrawtransaction},
        {"wallet", &abandontransaction},
        {"wallet", &abortrescan},
        {"wallet", &backupwallet},
        {"wallet", &bumpfee},
        {"wallet", &createwallet},
        {"wallet", &restorewallet},
        {"wallet", &encryptwallet},
        {"wallet", &getaddressesbylabel},
        {"wallet", &getaddressinfo},
        {"wallet", &getbalance},
        {"wallet", &getnewaddress},
        {"wallet", &getrawchangeaddress},
        {"wallet", &getreceivedbyaddress},
        {"wallet", &getreceivedbylabel},
        {"wallet", &gettransaction},
        {"wallet", &getbalances},
        {"wallet", &getwalletinfo},
        {"wallet", &importprunedfunds},
        {"wallet", &listaddressgroupings},
        {"wallet", &listlabels},
        {"wallet", &listlockunspent},
        {"wallet", &listreceivedbyaddress},
        {"wallet", &listreceivedbylabel},
        {"wallet", &listsinceblock},
        {"wallet", &listtransactions},
        {"wallet", &listunspent},
        {"wallet", &listwalletdir},
        {"wallet", &listwallets},
        {"wallet", &loadwallet},
        {"wallet", &lockunspent},
        {"wallet", &removeprunedfunds},
        {"wallet", &rescanblockchain},
        {"wallet", &send},
        {"wallet", &sendmany},
        {"wallet", &sendtoaddress},
        {"wallet", &setlabel},
        {"wallet", &setwalletflag},
        {"wallet", &signmessage},
        {"wallet", &signrawtransactionwithwallet},
        {"wallet", &simulaterawtransaction},
        {"wallet", &sendall},
        {"wallet", &unloadwallet},
        {"wallet", &walletlock},
        {"wallet", &walletpassphrase},
        {"wallet", &walletpassphrasechange},
    };
    return commands;
}
} // namespace wallet
