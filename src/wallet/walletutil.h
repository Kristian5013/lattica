// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_WALLET_WALLETUTIL_H
#define LATTICA_WALLET_WALLETUTIL_H

#include <script/descriptor.h>
#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <ios>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

class ArgsManager;
struct CExtKey;
enum class OutputType;

namespace wallet {

//! The directory holding wallet databases: <datadir>/wallets/ (created if absent).
//! A wallet `name` lives at <walletdir>/<name>/wallet.dat.
//!
//! Core reads the global gArgs here. This takes the ArgsManager instead, so that
//! the five call sites name where their configuration comes from.
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
    //! A secondary function of this flag is to serve as an ongoing indication
    //! that descriptors in the wallet should be created manually, and that the
    //! wallet should not automatically generate new descriptors if it is later
    //! encrypted. To support this behavior, importing something into a wallet
    //! does not unset the BLANK flag.
    WALLET_FLAG_BLANK_WALLET = (1ULL << 33),

    //! Indicate that this wallet supports DescriptorScriptPubKeyMan
    WALLET_FLAG_DESCRIPTORS = (1ULL << 34),

    //! Indicates that the wallet needs an external signer
    WALLET_FLAG_EXTERNAL_SIGNER = (1ULL << 35),
};

/** Descriptor with some wallet metadata */
class WalletDescriptor
{
public:
    std::shared_ptr<Descriptor> descriptor;
    uint256 id; // Descriptor ID (calculated once at descriptor initialization/deserialization)
    uint64_t creation_time = 0;
    int32_t range_start = 0; // First item in range; start of range, inclusive, i.e. [range_start, range_end). This never changes.
    int32_t range_end = 0; // Item after the last; end of range, exclusive, i.e. [range_start, range_end). This will increment with each TopUp()
    int32_t next_index = 0; // Position of the next item to generate
    DescriptorCache cache;

    void DeserializeDescriptor(const std::string& str)
    {
        std::string error;
        FlatSigningProvider keys;
        auto descs = Parse(str, keys, error, true);
        if (descs.empty()) {
            throw std::ios_base::failure("Invalid descriptor: " + error);
        }
        if (descs.size() > 1) {
            throw std::ios_base::failure("Can't load a multipath descriptor from databases");
        }
        descriptor = std::move(descs.at(0));
        id = DescriptorID(*descriptor);
    }

    SERIALIZE_METHODS(WalletDescriptor, obj)
    {
        std::string descriptor_str;
        SER_WRITE(obj, descriptor_str = obj.descriptor->ToString());
        READWRITE(descriptor_str, obj.creation_time, obj.next_index, obj.range_start, obj.range_end);
        SER_READ(obj, obj.DeserializeDescriptor(descriptor_str));
    }

    WalletDescriptor() = default;
    WalletDescriptor(std::shared_ptr<Descriptor> descriptor, uint64_t creation_time, int32_t range_start, int32_t range_end, int32_t next_index) : descriptor(descriptor), id(DescriptorID(*descriptor)), creation_time(creation_time), range_start(range_start), range_end(range_end), next_index(next_index) { }
};

/** Build the wallet's own descriptor for an output type, over the given tree.
 *
 *  The master key must be the root of the tree whose scheme `output_type` names
 *  -- see SecretSizeForOutputType -- since a lattice key belongs under witness v2
 *  and a secp256k1 key does not. Core has one tree for all four of its types;
 *  here one seed gives three, and which one this is comes from the key.
 */
WalletDescriptor GenerateWalletDescriptor(const CExtPubKey& master_key, const OutputType& output_type, bool internal);

} // namespace wallet

#endif // LATTICA_WALLET_WALLETUTIL_H
