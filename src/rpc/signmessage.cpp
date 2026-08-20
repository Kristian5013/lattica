// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <common/signmessage.h>
#include <key.h>
#include <key_io.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>

#include <string>

static RPCMethod verifymessage()
{
    return RPCMethod{"verifymessage",
        "Verify a signed message.",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to use for the signature."},
            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature provided by the signer in base 64 encoding (see signmessage)."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
        },
        RPCResult{
            RPCResult::Type::BOOL, "", "If the signature is verified or not."
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            switch (MessageVerify(std::string{self.Arg<std::string_view>("address")},
                                  std::string{self.Arg<std::string_view>("signature")},
                                  std::string{self.Arg<std::string_view>("message")})) {
            case MessageVerificationResult::ERR_INVALID_ADDRESS:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            case MessageVerificationResult::ERR_ADDRESS_NO_KEY:
                throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
            case MessageVerificationResult::ERR_MALFORMED_SIGNATURE:
                throw JSONRPCError(RPC_TYPE_ERROR, "Malformed base64 encoding");
            case MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED:
            case MessageVerificationResult::ERR_NOT_SIGNED:
                return false;
            case MessageVerificationResult::OK:
                return true;
            }

            return false;
        },
    };
}


void RegisterSignMessageRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"util", &verifymessage},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}