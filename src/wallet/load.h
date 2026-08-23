// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_WALLET_LOAD_H
#define LATTICA_WALLET_LOAD_H

#include <string>
#include <vector>

class ArgsManager;
class CScheduler;

namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {
struct WalletContext;

//! Responsible for reading and validating the -wallet arguments and verifying the wallet database.
bool VerifyWallets(WalletContext& context);

//! Load wallet databases.
bool LoadWallets(WalletContext& context);

//! Complete startup of wallets.
void StartWallets(WalletContext& context);

void UnloadWallets(WalletContext& context);
} // namespace wallet

#endif // LATTICA_WALLET_LOAD_H
