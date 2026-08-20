// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_WALLETINITINTERFACE_H
#define LATTICA_WALLETINITINTERFACE_H

class ArgsManager;

namespace node {
struct NodeContext;
} // namespace node

class WalletInitInterface {
public:
    /** Is the wallet component enabled */
    virtual bool HasWalletSupport() const = 0;
    /** Get wallet help string */
    virtual void AddWalletOptions(ArgsManager& argsman) const = 0;
    /** Check wallet parameter interaction */
    virtual bool ParameterInteraction() const = 0;
    /** Add wallets that should be opened to list of chain clients. */
    virtual void Construct(node::NodeContext& node) const = 0;

    virtual ~WalletInitInterface() = default;
};

extern const WalletInitInterface& g_wallet_init_interface;

#endif // LATTICA_WALLETINITINTERFACE_H