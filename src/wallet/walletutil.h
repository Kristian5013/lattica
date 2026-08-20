// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_WALLET_WALLETUTIL_H
#define LATTICA_WALLET_WALLETUTIL_H

#include <util/fs.h>

#include <cstdint>

class ArgsManager;

namespace wallet {

//! The directory holding wallet databases: <datadir>/wallets/ (created if absent).
//! A wallet `name` lives at <walletdir>/<name>/wallet.dat. Lattica opens wallets by
//! explicit name -> path, so this takes the ArgsManager rather than reading gArgs.
fs::path GetWalletDir(const ArgsManager& args);

enum WalletFlags : uint64_t {
    // wallet flags in the upper section (> 1 << 31) will lead to not opening the wallet if flag is unknown
    // unknown wallet flags in the lower section <= (1 << 31) will be tolerated

    // will categorize coins as clean (not reused) and dirty (reused), and handle
    // them with privacy considerations in mind
    WALLET_FLAG_AVOID_REUSE = (1ULL << 0),

    // Indicates that the metadata has already been upgraded to contain key origins
    WALLET_FLAG_KEY_ORIGIN_METADATA = (1ULL << 1),

    // Indicates that the descriptor cache has been upgraded to cache last hardened xpubs
    WALLET_FLAG_LAST_HARDENED_XPUB_CACHED = (1ULL << 2),

    // will enforce the rule that the wallet can't contain any private keys (only watch-only/pubkeys)
    WALLET_FLAG_DISABLE_PRIVATE_KEYS = (1ULL << 32),

    //! Flag set when a wallet contains no HD seed and no private keys, scripts,
    //! addresses, and other watch only things, and is therefore "blank."
    //!
    //! The main function this flag serves is to distinguish a blank wallet from
    //! a newly created wallet when the wallet database is loaded, to avoid
    //! initialization that should only happen on first run.
    //!
    //! A secondary function of this flag, which applies to descriptor wallets
    //! only, is to serve as an ongoing indication that descriptors in the
    //! wallet should be created manually, and that the wallet should not
    //! generate automatically generate new descriptors if it is later
    //! encrypted. To support this behavior, descriptor wallets unlike legacy
    //! wallets do not automatically unset the BLANK flag when things are
    //! imported.
    //!
    //! This flag is also a mandatory flag to prevent previous versions of
    //! bitcoin from opening the wallet, thinking it was newly created, and
    //! then improperly reinitializing it.
    WALLET_FLAG_BLANK_WALLET = (1ULL << 33),

    //! Indicate that this wallet supports DescriptorScriptPubKeyMan
    WALLET_FLAG_DESCRIPTORS = (1ULL << 34),

    //! Indicates that the wallet needs an external signer
    WALLET_FLAG_EXTERNAL_SIGNER = (1ULL << 35),
};

// NOTE: Core's walletutil.h also declares the descriptor helper
// WalletDescriptor / GenerateWalletDescriptor(CExtPubKey, ...). It is deliberately
// omitted: WalletDescriptor wraps a secp256k1 output descriptor and CExtPubKey-based
// range expansion, which a post-quantum (ML-DSA) witness-only chain has no analog
// for (no xpub homomorphism). Lattica's wallet uses a direct ML-DSA HD keystore
// rather than a DescriptorScriptPubKeyMan.

} // namespace wallet

#endif // LATTICA_WALLET_WALLETUTIL_H
