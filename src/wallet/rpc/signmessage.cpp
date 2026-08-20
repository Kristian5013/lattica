// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <chainparams.h>
#include <common/signmessage.h>
#include <key.h>
#include <key_io.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

#include <optional>
#include <variant>

namespace wallet {
RPCMethod signmessage()
{
    return RPCMethod{
        "signmessage",
        "Sign a message with the private key of an address" +
          HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The lattica address to use for the private key."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
        },
        RPCResult{
            RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"address\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"address\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessage", "\"address\", \"my message\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            EnsureWalletIsUnlocked(*pwallet);

            std::string strAddress = request.params[0].get_str();
            std::string strMessage = request.params[1].get_str();

            CTxDestination dest = DecodeDestination(strAddress, Params());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }

            // Lattica addresses are witness-v0 key hashes (P2WPKH); map either a
            // witness key hash or a legacy pubkey hash to the underlying CKeyID.
            std::optional<CKeyID> keyid;
            if (const auto* wpkh = std::get_if<WitnessV0KeyHash>(&dest)) {
                keyid = ToKeyID(*wpkh);
            } else if (const auto* pkh = std::get_if<PKHash>(&dest)) {
                keyid = ToKeyID(*pkh);
            }
            if (!keyid) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
            }

            std::optional<CKey> key{pwallet->GetKey(*keyid)};
            if (!key) {
                throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(SigningResult::PRIVATE_KEY_NOT_AVAILABLE));
            }

            std::string signature;
            if (!MessageSign(*key, strMessage, signature)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, SigningResultString(SigningResult::SIGNING_FAILED));
            }

            return signature;
        },
    };
}
} // namespace wallet
