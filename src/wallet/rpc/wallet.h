// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_WALLET_RPC_WALLET_H
#define LATTICA_WALLET_RPC_WALLET_H

#include <span>

class CRPCCommand;

namespace wallet {
std::span<const CRPCCommand> GetWalletRPCCommands();
} // namespace wallet

#endif // LATTICA_WALLET_RPC_WALLET_H
