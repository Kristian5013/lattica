// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for wallet/walletutil.cpp: the descriptors a wallet builds for itself,
// and the WalletDescriptor record they are stored as.
//
// Built from the master xpub, as Core builds them. Two things differ and both
// are silent if got wrong, so both are checked against the scripts the
// descriptors actually expand to: the tree handed over must be the one whose
// scheme the output type names, one seed giving three unrelated trees; and no
// descriptor here expands from public data alone, derivation being hardened at
// every step, so the extended key has to be in the signing provider.

#include <wallet/walletutil.h>

#include <chainparams.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>
#include <util/chaintype.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {
int g_fail = 0;
bool Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
    return ok;
}

//! The master node of the tree whose scheme this output type names.
CExtKey MasterFor(OutputType type, std::span<const unsigned char> seed)
{
    CExtKey master;
    master.SetSeed(seed, SecretSizeForOutputType(type));
    return master;
}
} // namespace

int main()
{
    ECC_Context ecc_context{};
    SelectParams(ChainType::MAIN);

    unsigned char seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (unsigned char)(i * 3 + 5);

    // ---- Every output type produces a descriptor that parses, is ranged, and
    // expands to the script that type names.
    for (OutputType type : OUTPUT_TYPES) {
        const std::string name = FormatOutputType(type);
        const CExtKey master = MasterFor(type, seed);
        wallet::WalletDescriptor wdesc = wallet::GenerateWalletDescriptor(master.Neuter(), type, /*internal=*/false);

        // The descriptor names the tree by its public half; expanding it needs
        // the extended key, every step of the tree being hardened.
        FlatSigningProvider tree;
        tree.extkeys.emplace(master.Neuter().pubkey.GetID(), master);

        if (!Check((name + ": a descriptor is generated").c_str(), wdesc.descriptor != nullptr)) continue;
        Check((name + ": it is ranged").c_str(), wdesc.descriptor->IsRange());
        Check((name + ": it is solvable").c_str(), wdesc.descriptor->IsSolvable());
        // Hardened at every step, so it never expands from public data alone.
        Check((name + ": it cannot expand itself").c_str(), !wdesc.descriptor->CanSelfExpand());
        Check((name + ": it names that output type").c_str(), wdesc.descriptor->GetOutputType() == type);

        FlatSigningProvider keys;
        std::vector<CScript> scripts;
        if (!Check((name + ": it expands at position 0").c_str(),
                   wdesc.descriptor->Expand(0, tree, scripts, keys) && scripts.size() == 1)) {
            continue;
        }
        std::vector<std::vector<unsigned char>> solutions;
        const TxoutType got = Solver(scripts[0], solutions);
        TxoutType want{};
        switch (type) {
        case OutputType::LEGACY: want = TxoutType::PUBKEYHASH; break;
        case OutputType::P2SH_SEGWIT: want = TxoutType::SCRIPTHASH; break;
        case OutputType::BECH32: want = TxoutType::WITNESS_V0_KEYHASH; break;
        case OutputType::BECH32M: want = TxoutType::WITNESS_V1_TAPROOT; break;
        case OutputType::FALCON512:
        case OutputType::MLDSA44: want = TxoutType::WITNESS_V2_KEYHASH; break;
        case OutputType::UNKNOWN: break;
        }
        Check((name + ": it expands to the right script type").c_str(), got == want);

        // The key under the script is the scheme the output type names.
        Check((name + ": the derived key is that scheme's").c_str(),
              keys.pubkeys.size() == 1 &&
              keys.pubkeys.begin()->second.size() ==
                  (type == OutputType::FALCON512 ? CPubKey::FALCON512_SIZE :
                   type == OutputType::MLDSA44 ? CPubKey::MLDSA44_SIZE : CPubKey::SECP256K1_SIZE));

        // Two positions are two different addresses.
        FlatSigningProvider keys1;
        std::vector<CScript> scripts1;
        Check((name + ": position 1 is a different script").c_str(),
              wdesc.descriptor->Expand(1, tree, scripts1, keys1) && scripts1.size() == 1 && scripts1[0] != scripts[0]);
    }

    // ---- The internal (change) chain is a different branch, so it hands out
    // different addresses than the external one.
    {
        const CExtKey master = MasterFor(OutputType::MLDSA44, seed);
        FlatSigningProvider tree;
        tree.extkeys.emplace(master.Neuter().pubkey.GetID(), master);
        auto ext = wallet::GenerateWalletDescriptor(master.Neuter(), OutputType::MLDSA44, /*internal=*/false);
        auto in = wallet::GenerateWalletDescriptor(master.Neuter(), OutputType::MLDSA44, /*internal=*/true);
        Check("the internal chain is a different descriptor", ext.id != in.id);

        FlatSigningProvider ke, ki;
        std::vector<CScript> se, si;
        Check("...expanding to different scripts",
              ext.descriptor->Expand(0, tree, se, ke) && in.descriptor->Expand(0, tree, si, ki) &&
              se.size() == 1 && si.size() == 1 && se[0] != si[0]);
    }

    // ---- The two witness v2 output types share a path and are separated by the
    // tree, the scheme being part of the master node's preimage.
    {
        const CExtKey falcon = MasterFor(OutputType::FALCON512, seed);
        const CExtKey mldsa = MasterFor(OutputType::MLDSA44, seed);
        Check("one seed gives two unrelated witness v2 trees", falcon.nodeseed != mldsa.nodeseed);

        auto f = wallet::GenerateWalletDescriptor(falcon.Neuter(), OutputType::FALCON512, /*internal=*/false);
        auto m = wallet::GenerateWalletDescriptor(mldsa.Neuter(), OutputType::MLDSA44, /*internal=*/false);
        Check("...and two different descriptors", f.id != m.id);
        Check("...both spelled pqpkh()",
              f.descriptor->ToString().rfind("pqpkh(", 0) == 0 &&
              m.descriptor->ToString().rfind("pqpkh(", 0) == 0);
    }

    // ---- The record round-trips: a wallet that writes a descriptor must read
    // back the same one, id included.
    {
        const CExtKey master = MasterFor(OutputType::MLDSA44, seed);
        wallet::WalletDescriptor wdesc = wallet::GenerateWalletDescriptor(master.Neuter(), OutputType::MLDSA44, /*internal=*/false);
        wdesc.range_end = 100;
        wdesc.next_index = 7;

        DataStream ss;
        ss << wdesc;
        wallet::WalletDescriptor back;
        ss >> back;

        Check("a WalletDescriptor round-trips through serialization",
              back.descriptor != nullptr &&
              back.descriptor->ToString() == wdesc.descriptor->ToString());
        Check("...keeping its id", back.id == wdesc.id);
        Check("...and its range", back.range_start == 0 && back.range_end == 100 && back.next_index == 7);
        Check("...and its creation time", back.creation_time == wdesc.creation_time);
    }

    // ---- A descriptor string with no checksum is refused on load, which is what
    // stops a corrupted wallet record from being read as a different descriptor.
    {
        DataStream ss;
        ss << std::string{"pqpkh(x)"} << uint64_t{0} << int32_t{0} << int32_t{0} << int32_t{0};
        wallet::WalletDescriptor back;
        bool threw = false;
        try {
            ss >> back;
        } catch (const std::ios_base::failure&) {
            threw = true;
        }
        Check("an unparsable descriptor record is refused", threw);
    }

    // ---- Networks differ in the coin type, so the same seed gives different
    // addresses on mainnet and on regtest.
    {
        const CExtKey master = MasterFor(OutputType::MLDSA44, seed);
        const std::string on_main = wallet::GenerateWalletDescriptor(master.Neuter(), OutputType::MLDSA44, false).descriptor->ToString();
        SelectParams(ChainType::REGTEST);
        const std::string on_regtest = wallet::GenerateWalletDescriptor(master.Neuter(), OutputType::MLDSA44, false).descriptor->ToString();
        SelectParams(ChainType::MAIN);
        Check("mainnet and regtest derive at different coin types", on_main != on_regtest);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
