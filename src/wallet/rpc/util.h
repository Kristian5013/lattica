// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_WALLET_RPC_UTIL_H
#define LATTICA_WALLET_RPC_UTIL_H

#include <rpc/util.h>
#include <wallet/wallet.h>

#include <any>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

class JSONRPCRequest;
class UniValue;
struct bilingual_str;

namespace wallet {
enum class DatabaseStatus;
struct WalletContext;

extern const std::string HELP_REQUIRING_PASSPHRASE;

static const RPCResult RESULT_LAST_PROCESSED_BLOCK { RPCResult::Type::OBJ, "lastprocessedblock", "hash and height of the block this information was generated on",{
    {RPCResult::Type::STR_HEX, "hash", "hash of the block this information was generated on"},
    {RPCResult::Type::NUM, "height", "height of the block this information was generated on"}}
};

/**
 * Figures out what wallet, if any, to use for a JSONRPCRequest.
 *
 * @param[in] request JSONRPCRequest that wishes to access a wallet
 * @return nullptr if no wallet should be used, or a pointer to the CWallet
 */
std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request);
std::optional<std::string> GetWalletNameFromJSONRPCRequest(const JSONRPCRequest& request);
/**
 * Ensures that a wallet name is specified across the endpoint and wallet_name.
 * Throws `RPC_INVALID_PARAMETER` if none or different wallet names are specified.
 */
std::string EnsureUniqueWalletName(const JSONRPCRequest& request, std::optional<std::string_view> wallet_name);

void EnsureWalletIsUnlocked(const CWallet&);
WalletContext& EnsureWalletContext(const std::any& context);

bool GetAvoidReuseFlag(const CWallet& wallet, const UniValue& param);
std::string LabelFromValue(const UniValue& value);

void HandleWalletError(const std::shared_ptr<CWallet>& wallet, DatabaseStatus& status, bilingual_str& error);
void AppendLastProcessedBlock(UniValue& entry, const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
} //  namespace wallet

#endif // LATTICA_WALLET_RPC_UTIL_H
