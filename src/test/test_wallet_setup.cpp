// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Setting up a fresh wallet: one seed, a master key per scheme, a descriptor
// manager per output type.
//
// Bitcoin's four output types are four formats over one key, so its wallet draws
// a single master key and hands it to all four. Two of the six types here name a
// signature scheme rather than a format, and a key cannot be read under a scheme
// that is not its own -- so the seed has to fan out into three trees before the
// descriptors are built. Nothing below reaches into the wallet: it creates one
// the way `createwallet` does, asks it for an address of each type, and looks at
// what came back.

#include <chainparams.h>
#include <chainparamsbase.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/script.h>
#include <script/solver.h>
#include <sync.h>
#include <util/fs.h>
#include <util/translation.h>
#include <wallet/db.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

using wallet::CWallet;
using wallet::DescriptorScriptPubKeyMan;
using wallet::WALLET_FLAG_DESCRIPTORS;

namespace {

int g_fail = 0;
bool Check(const std::string& name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name.c_str());
    if (!ok) ++g_fail;
    return ok;
}

//! A wallet on a fresh SQLite database, set up as `createwallet` sets one up.
std::shared_ptr<CWallet> MakeWallet(const std::string& dir_name)
{
    std::filesystem::remove_all(dir_name);
    std::filesystem::create_directories(dir_name);

    wallet::DatabaseOptions options;
    wallet::DatabaseStatus status;
    bilingual_str error;
    auto database = wallet::MakeDatabase(fs::PathFromString(dir_name), options, status, error);
    if (!database) {
        std::printf("    could not open the wallet database: %s\n", error.original.c_str());
        return nullptr;
    }

    auto wallet = std::make_shared<CWallet>(/*chain=*/nullptr, dir_name, std::move(database));
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetupWalletGeneration();
    return wallet;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};
    SelectParams(ChainType::MAIN);

    auto wallet = MakeWallet("lattica_wallet_setup_test");
    if (!Check("a wallet is created and generates its descriptors", wallet != nullptr)) {
        std::printf("FAILURES\n");
        return 1;
    }

    // ---- One manager per output type per chain, external and internal.
    {
        LOCK(wallet->cs_wallet);
        Check("there is a manager for every output type, receiving and change",
              wallet->GetActiveScriptPubKeyMans().size() == OUTPUT_TYPES.size() * 2);
        for (const OutputType t : OUTPUT_TYPES) {
            for (const bool internal : {false, true}) {
                Check("a " + FormatOutputType(t) + (internal ? " change" : " receiving") + " manager exists",
                      wallet->GetScriptPubKeyMan(t, internal) != nullptr);
            }
        }
    }

    // ---- An address of each type is the script the type names, and the key
    // under it belongs to the scheme the type names.
    std::set<std::string> addresses;
    for (const OutputType t : OUTPUT_TYPES) {
        const auto dest = wallet->GetNewDestination(t, "");
        if (!Check(FormatOutputType(t) + ": an address is handed out", dest.has_value())) {
            if (!dest) std::printf("       %s\n", util::ErrorString(dest).original.c_str());
            continue;
        }
        const CScript spk = GetScriptForDestination(*dest);
        std::vector<std::vector<unsigned char>> solutions;
        const TxoutType type = Solver(spk, solutions);

        TxoutType want{TxoutType::NONSTANDARD};
        switch (t) {
        case OutputType::LEGACY: want = TxoutType::PUBKEYHASH; break;
        case OutputType::P2SH_SEGWIT: want = TxoutType::SCRIPTHASH; break;
        case OutputType::BECH32: want = TxoutType::WITNESS_V0_KEYHASH; break;
        case OutputType::BECH32M: want = TxoutType::WITNESS_V1_TAPROOT; break;
        case OutputType::FALCON512:
        case OutputType::MLDSA44: want = TxoutType::WITNESS_V2_KEYHASH; break;
        case OutputType::UNKNOWN: break;
        }
        Check(FormatOutputType(t) + ": ...of the script type it names", type == want);
        Check(FormatOutputType(t) + ": ...distinct from every other type's",
              addresses.insert(EncodeDestination(*dest, Params())).second);

        // The scheme is not in the address -- both witness v2 types encode the
        // same way -- so ask the wallet for the key behind it.
        auto* spk_man = wallet->GetScriptPubKeyMan(t, /*internal=*/false);
        std::unique_ptr<SigningProvider> provider = spk_man ? spk_man->GetSolvingProvider(spk) : nullptr;
        CKeyID keyid;
        if (type == TxoutType::PUBKEYHASH || type == TxoutType::WITNESS_V0_KEYHASH || type == TxoutType::WITNESS_V2_KEYHASH) {
            keyid = CKeyID(uint160(solutions[0]));
        }
        // The length of a public key names its scheme, just as the length of a
        // secret does; this is the pair of the two for the type at hand.
        const auto pubkey_size_for = [](OutputType type) -> unsigned int {
            switch (SecretSizeForOutputType(type)) {
            case CKey::SECP256K1_SIZE: return CPubKey::SECP256K1_SIZE;
            case CKey::FALCON512_SIZE: return CPubKey::FALCON512_SIZE;
            case CKey::MLDSA44_SIZE: return CPubKey::MLDSA44_SIZE;
            }
            return 0;
        };

        CPubKey pubkey;
        if (provider && !keyid.IsNull() && provider->GetPubKey(keyid, pubkey)) {
            Check(FormatOutputType(t) + ": ...over a key of the scheme it names",
                  pubkey.size() == pubkey_size_for(t));
        } else if (t != OutputType::P2SH_SEGWIT && t != OutputType::BECH32M) {
            Check(FormatOutputType(t) + ": ...over a key of the scheme it names", false);
        }
    }

    // ---- The two witness v2 trees are separate trees, not two views of one.
    // Both are reached by the same path from the same seed, so if the scheme
    // were not part of the master node's preimage they would share node seeds
    // and one scheme's key would leak the other's.
    {
        LOCK(wallet->cs_wallet);
        auto get_descriptor = [&](OutputType t) {
            auto* spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(wallet->GetScriptPubKeyMan(t, /*internal=*/false));
            return spk_man ? spk_man->GetWalletDescriptor().descriptor->ToString() : std::string{};
        };
        const std::string falcon = get_descriptor(OutputType::FALCON512);
        const std::string mldsa = get_descriptor(OutputType::MLDSA44);
        Check("both witness v2 types are pqpkh() at the same purpose",
              falcon.rfind("pqpkh(", 0) == 0 && mldsa.rfind("pqpkh(", 0) == 0 &&
              falcon.find("/88h/") != std::string::npos && mldsa.find("/88h/") != std::string::npos);
        Check("...yet their master keys are unrelated", !falcon.empty() && falcon != mldsa);

        // And neither shares a master with the four secp256k1 types, which do
        // share one with each other, exactly as in Bitcoin.
        const std::string legacy = get_descriptor(OutputType::LEGACY);
        const std::string bech32 = get_descriptor(OutputType::BECH32);
        auto xpub_of = [](const std::string& desc) {
            const size_t open = desc.find_last_of('(');
            const size_t slash = desc.find('/', open);
            return (open == std::string::npos || slash == std::string::npos) ? std::string{} : desc.substr(open + 1, slash - open - 1);
        };
        Check("the four secp256k1 types share one master key, as in Bitcoin",
              !xpub_of(legacy).empty() && xpub_of(legacy) == xpub_of(bech32));
        Check("...which is not the master key of either lattice scheme",
              xpub_of(legacy) != xpub_of(falcon) && xpub_of(legacy) != xpub_of(mldsa) &&
              xpub_of(falcon) != xpub_of(mldsa));
    }

    // ---- The default is post-quantum, and change follows what is being paid.
    {
        Check("the default address type is a witness v2 one",
              wallet::DEFAULT_ADDRESS_TYPE == OutputType::MLDSA44 || wallet::DEFAULT_ADDRESS_TYPE == OutputType::FALCON512);

        const auto pq_dest = wallet->GetNewDestination(OutputType::FALCON512, "");
        const auto v0_dest = wallet->GetNewDestination(OutputType::BECH32, "");
        if (pq_dest && v0_dest) {
            std::vector<wallet::CRecipient> to_pq{{*pq_dest, 1000, false}};
            const OutputType change = wallet->TransactionChangeType(std::nullopt, to_pq);
            Check("paying to a witness v2 address takes change on witness v2",
                  change == OutputType::MLDSA44 || change == OutputType::FALCON512);

            std::vector<wallet::CRecipient> to_v0{{*v0_dest, 1000, false}};
            Check("paying to a witness v0 address still takes change on witness v0",
                  wallet->TransactionChangeType(std::nullopt, to_v0) == OutputType::BECH32);
        } else {
            Check("two addresses for the change test", false);
        }
    }

    wallet->Close();
    std::filesystem::remove_all("lattica_wallet_setup_test");

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
