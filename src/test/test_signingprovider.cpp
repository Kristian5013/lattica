// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for signingprovider.cpp: the FillableSigningProvider keystore (keys and
// scripts round-trip through the maps; adding a key implicitly learns the witness
// script its own scheme is spendable under, so a P2SH-of-P2WPKH redeemScript is
// solvable), the flat/hiding/multi providers, GetKeyForDestination over every
// single-key destination, and the Taproot tree machinery — TaprootBuilder against
// InferTaprootTree, which must recover the tree the builder was handed.

#include <script/signingprovider.h>
#include <addresstype.h>
#include <key.h>
#include <musig.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/keyorigin.h>
#include <script/script.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}
} // namespace

int main()
{
    ECC_Context ecc_context{};

    const CKey key = GenerateRandomKey();
    const CPubKey pub = key.GetPubKey();
    const CKeyID id = pub.GetID();

    FillableSigningProvider ks;

    // Key storage.
    Check("HaveKey is false before add", !ks.HaveKey(id));
    Check("AddKey succeeds", ks.AddKey(key));
    Check("HaveKey is true after add", ks.HaveKey(id));
    {
        CKey out;
        Check("GetKey returns the stored key", ks.GetKey(id, out) && out == key);
        CPubKey pout;
        Check("GetPubKey returns the public key", ks.GetPubKey(id, pout) && pout == pub);
        Check("GetKeys contains the key id", ks.GetKeys().count(id) == 1);
    }

    // Adding a key implicitly learns the keyhash script of the witness version
    // its scheme is spendable under. An ML-DSA signature does not fit under the
    // v0 element cap, so a lattice key learns the v2 script and not the v0 one.
    const CScript p2w2pkh = GetScriptForDestination(WitnessV2KeyHash(pub));
    const CScriptID p2w2pkh_id(p2w2pkh);
    {
        Check("implicit witness v2 script was learned", ks.HaveCScript(p2w2pkh_id));
        CScript sout;
        Check("GetCScript returns the witness v2 script", ks.GetCScript(p2w2pkh_id, sout) && sout == p2w2pkh);
        Check("no witness v0 script for a lattice key",
              !ks.HaveCScript(CScriptID(GetScriptForDestination(WitnessV0KeyHash(pub)))));
    }

    // A secp256k1 key learns the v0 script instead.
    const CKey seckey = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CPubKey secpub = seckey.GetPubKey();
    const CScript sec_p2wpkh = GetScriptForDestination(WitnessV0KeyHash(secpub));
    {
        FillableSigningProvider sec_ks;
        sec_ks.AddKey(seckey);
        Check("secp256k1 key learns the witness v0 script", sec_ks.HaveCScript(CScriptID(sec_p2wpkh)));
        Check("secp256k1 key learns no witness v2 script",
              !sec_ks.HaveCScript(CScriptID(GetScriptForDestination(WitnessV2KeyHash(secpub)))));
    }

    // Explicit script storage.
    {
        const CScript redeem = CScript() << OP_1;
        const CScriptID redeem_id(redeem);
        Check("AddCScript succeeds", ks.AddCScript(redeem));
        Check("HaveCScript is true for the redeem script", ks.HaveCScript(redeem_id));
        Check("GetCScripts contains the redeem script", ks.GetCScripts().count(redeem_id) == 1);

        // The bound is the v2 element cap: a witnessScript carrying a lattice
        // signature is past the 520-byte one and must still be storable.
        const std::vector<unsigned char> mid(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x00);
        const CScript past_v0(mid.begin(), mid.end());
        Check("a script past the v0 element cap is accepted", ks.AddCScript(past_v0));

        const std::vector<unsigned char> big(MAX_SCRIPT_ELEMENT_SIZE_V2 + 1, 0x00);
        const CScript too_big(big.begin(), big.end());
        Check("oversized redeem script is rejected", !ks.AddCScript(too_big));
    }

    // GetKeyForDestination.
    {
        Check("GetKeyForDestination(P2PKH) -> key id", GetKeyForDestination(ks, CTxDestination(PKHash(pub))) == id);
        Check("GetKeyForDestination(P2W2PKH) -> key id", GetKeyForDestination(ks, CTxDestination(WitnessV2KeyHash(pub))) == id);
        // P2SH wrapping the (implicitly learned) v2 keyhash script resolves to the key.
        Check("GetKeyForDestination(P2SH-P2W2PKH) -> key id", GetKeyForDestination(ks, CTxDestination(ScriptHash(p2w2pkh))) == id);
        // A P2SH whose redeem script the store does not know yields a null id.
        const CScript unknown = CScript() << OP_2 << OP_3;
        Check("GetKeyForDestination(unknown P2SH) -> null", GetKeyForDestination(ks, CTxDestination(ScriptHash(unknown))) == CKeyID());

        FillableSigningProvider sec_ks;
        sec_ks.AddKey(seckey);
        Check("GetKeyForDestination(P2WPKH) -> key id", GetKeyForDestination(sec_ks, CTxDestination(WitnessV0KeyHash(secpub))) == secpub.GetID());
        Check("GetKeyForDestination(P2SH-P2WPKH) -> key id", GetKeyForDestination(sec_ks, CTxDestination(ScriptHash(sec_p2wpkh))) == secpub.GetID());
    }

    // A second key, for the multi-key providers below.
    const CKey key2 = GenerateRandomKey();
    const CPubKey pub2 = key2.GetPubKey();
    const CKeyID id2 = pub2.GetID();

    // FlatSigningProvider: plain public maps + Merge.
    {
        FlatSigningProvider flat;
        flat.keys[id] = key;
        flat.pubkeys[id] = pub;
        flat.scripts[p2w2pkh_id] = p2w2pkh;
        CKey kout;
        Check("Flat.GetKey", flat.GetKey(id, kout) && kout == key);
        Check("Flat.HaveKey", flat.HaveKey(id) && !flat.HaveKey(id2));
        CPubKey pout;
        Check("Flat.GetPubKey", flat.GetPubKey(id, pout) && pout == pub);
        CScript sout;
        Check("Flat.GetCScript", flat.GetCScript(p2w2pkh_id, sout) && sout == p2w2pkh);

        // Key origins.
        KeyOriginInfo origin;
        origin.fingerprint = {0xde, 0xad, 0xbe, 0xef};
        origin.path = {0x80000000 + 44, 0x80000000, 0x80000000, 0, 7};
        flat.origins[id] = std::make_pair(pub, origin);
        KeyOriginInfo oout;
        Check("Flat.GetKeyOrigin", flat.GetKeyOrigin(id, oout) && oout == origin);
        Check("Flat.GetKeyOrigin misses an unknown key", !flat.GetKeyOrigin(id2, oout));

        FlatSigningProvider a, b;
        a.keys[id] = key;
        b.keys[id2] = key2;
        b.origins[id2] = std::make_pair(pub2, origin);
        a.Merge(std::move(b));
        Check("Flat.Merge combines keys", a.HaveKey(id) && a.HaveKey(id2));
        Check("Flat.Merge combines origins", a.GetKeyOrigin(id2, oout));
    }

    // MuSig2 participant lists ride along on the flat provider.
    {
        const CKey part_a = GenerateRandomKey(CKey::SECP256K1_SIZE);
        const CKey part_b = GenerateRandomKey(CKey::SECP256K1_SIZE);
        const std::vector<CPubKey> parts{part_a.GetPubKey(), part_b.GetPubKey()};
        const auto agg = MuSig2AggregatePubkeys(parts);
        Check("MuSig2AggregatePubkeys over two secp256k1 keys", agg.has_value());
        if (agg) {
            FlatSigningProvider flat;
            flat.aggregate_pubkeys[*agg] = parts;
            Check("Flat.GetMuSig2ParticipantPubkeys", flat.GetMuSig2ParticipantPubkeys(*agg) == parts);
            Check("Flat.GetMuSig2ParticipantPubkeys misses a plain key", flat.GetMuSig2ParticipantPubkeys(parts[0]).empty());
            Check("Flat.GetAllMuSig2ParticipantPubkeys", flat.GetAllMuSig2ParticipantPubkeys().size() == 1);

            // A participant list holding a lattice key aggregates to nothing:
            // key aggregation is a statement about points on a curve.
            Check("MuSig2AggregatePubkeys refuses a lattice participant",
                  !MuSig2AggregatePubkeys({part_a.GetPubKey(), pub}).has_value());
        }
    }

    // HidingSigningProvider: hides the secret but forwards public data.
    {
        FillableSigningProvider base;
        base.AddKey(key);
        HidingSigningProvider hidden(&base, /*hide_secret=*/true, /*hide_origin=*/false);
        CKey kout;
        Check("Hiding(hide_secret) blocks GetKey", !hidden.GetKey(id, kout));
        CPubKey pout;
        Check("Hiding still forwards GetPubKey", hidden.GetPubKey(id, pout) && pout == pub);
        CScript sout;
        Check("Hiding still forwards GetCScript", hidden.GetCScript(p2w2pkh_id, sout) && sout == p2w2pkh);

        HidingSigningProvider shown(&base, /*hide_secret=*/false, /*hide_origin=*/false);
        Check("Hiding(!hide_secret) forwards GetKey", shown.GetKey(id, kout) && kout == key);

        // hide_origin also hides the MuSig2 participant list, which is origin data.
        FlatSigningProvider flat;
        const CKey part = GenerateRandomKey(CKey::SECP256K1_SIZE);
        const std::vector<CPubKey> parts{part.GetPubKey(), secpub};
        if (const auto agg = MuSig2AggregatePubkeys(parts)) {
            flat.aggregate_pubkeys[*agg] = parts;
            HidingSigningProvider hide_origin(&flat, /*hide_secret=*/false, /*hide_origin=*/true);
            Check("Hiding(hide_origin) blocks the participant list", hide_origin.GetMuSig2ParticipantPubkeys(*agg).empty());
            HidingSigningProvider show_origin(&flat, /*hide_secret=*/false, /*hide_origin=*/false);
            Check("Hiding(!hide_origin) forwards the participant list", show_origin.GetMuSig2ParticipantPubkeys(*agg) == parts);
        }
    }

    // MultiSigningProvider: fans out over several providers.
    {
        auto p1 = std::make_unique<FillableSigningProvider>();
        p1->AddKey(key);
        auto p2 = std::make_unique<FillableSigningProvider>();
        p2->AddKey(key2);
        MultiSigningProvider multi;
        multi.AddProvider(std::move(p1));
        multi.AddProvider(std::move(p2));
        CKey kout;
        Check("Multi finds key in first provider", multi.GetKey(id, kout) && kout == key);
        Check("Multi finds key in second provider", multi.GetKey(id2, kout) && kout == key2);
        CKey unrelated = GenerateRandomKey();
        Check("Multi misses an unknown key", !multi.GetKey(unrelated.GetPubKey().GetID(), kout));
    }

    // TaprootBuilder, key path only.
    {
        const XOnlyPubKey internal{secpub};
        Check("XOnlyPubKey of a secp256k1 key is valid", internal.IsFullyValid());

        TaprootBuilder builder;
        Check("empty builder is complete", builder.IsComplete() && !builder.HasScripts());
        builder.Finalize(internal);
        const WitnessV1Taproot output = builder.GetOutput();

        const TaprootSpendData spd = builder.GetSpendData();
        Check("key-path spend data has the internal key", spd.internal_key == internal);
        Check("key-path spend data has no Merkle root", spd.merkle_root.IsNull());
        Check("key-path spend data has no scripts", spd.scripts.empty());

        // A store holding the tree resolves the output key back to the signing key.
        FlatSigningProvider flat;
        flat.keys[secpub.GetID()] = seckey;
        flat.pubkeys[secpub.GetID()] = secpub;
        flat.tr_trees[XOnlyPubKey(output)] = builder;
        TaprootSpendData out_spd;
        Check("Flat.GetTaprootSpendData", flat.GetTaprootSpendData(XOnlyPubKey(output), out_spd) && out_spd.internal_key == internal);
        TaprootBuilder out_builder;
        Check("Flat.GetTaprootBuilder", flat.GetTaprootBuilder(XOnlyPubKey(output), out_builder));
        Check("GetKeyForDestination(P2TR key path) -> key id", GetKeyForDestination(flat, CTxDestination(output)) == secpub.GetID());

        // InferTaprootTree on an empty tree yields an empty tree, not a failure.
        const auto inferred = InferTaprootTree(spd, XOnlyPubKey(output));
        Check("InferTaprootTree of a key-path output is empty", inferred.has_value() && inferred->empty());
        // ...and refuses an output key the spend data does not tweak to.
        Check("InferTaprootTree refuses a foreign output key", !InferTaprootTree(spd, XOnlyPubKey(GenerateRandomKey(CKey::SECP256K1_SIZE).GetPubKey())).has_value());
    }

    // TaprootBuilder, script path: build a three-leaf tree and infer it back.
    {
        const XOnlyPubKey internal{secpub};
        const CScript leaf_a = CScript() << OP_1;
        const CScript leaf_b = CScript() << OP_2;
        const CScript leaf_c = CScript() << OP_3;

        Check("ValidDepths accepts {1,2,2}", TaprootBuilder::ValidDepths({1, 2, 2}));
        Check("ValidDepths rejects {1,2}", !TaprootBuilder::ValidDepths({1, 2}));
        Check("ValidDepths rejects a negative depth", !TaprootBuilder::ValidDepths({-1}));

        TaprootBuilder builder;
        builder.Add(1, leaf_a, TAPROOT_LEAF_TAPSCRIPT);
        builder.Add(2, leaf_b, TAPROOT_LEAF_TAPSCRIPT);
        builder.Add(2, leaf_c, TAPROOT_LEAF_TAPSCRIPT);
        Check("three-leaf builder is valid", builder.IsValid());
        Check("three-leaf builder is complete", builder.IsComplete());
        Check("three-leaf builder has scripts", builder.HasScripts());
        builder.Finalize(internal);

        const WitnessV1Taproot output = builder.GetOutput();
        const TaprootSpendData spd = builder.GetSpendData();
        Check("script-path spend data has a Merkle root", !spd.merkle_root.IsNull());
        Check("script-path spend data has three leaves", spd.scripts.size() == 3);
        Check("the output key is the tweaked internal key",
              XOnlyPubKey(output).CheckTapTweak(internal, spd.merkle_root, /*parity=*/false) ||
              XOnlyPubKey(output).CheckTapTweak(internal, spd.merkle_root, /*parity=*/true));

        // Every control block carries the internal key right after the leaf version.
        bool control_blocks_ok = true;
        for (const auto& [leaf, controls] : spd.scripts) {
            for (const auto& control : controls) {
                if (control.size() < TAPROOT_CONTROL_BASE_SIZE) control_blocks_ok = false;
                else if ((control[0] & TAPROOT_LEAF_MASK) != leaf.second) control_blocks_ok = false;
                else if (!std::equal(internal.begin(), internal.end(), control.begin() + 1)) control_blocks_ok = false;
            }
        }
        Check("control blocks carry the leaf version and internal key", control_blocks_ok);

        // The tuples the builder reports are the tree it was handed.
        auto tuples = builder.GetTreeTuples();
        Check("GetTreeTuples reports three leaves", tuples.size() == 3);
        std::sort(tuples.begin(), tuples.end());
        Check("GetTreeTuples reports the tree it was given",
              tuples == decltype(tuples){
                  {1, TAPROOT_LEAF_TAPSCRIPT, std::vector<unsigned char>(leaf_a.begin(), leaf_a.end())},
                  {2, TAPROOT_LEAF_TAPSCRIPT, std::vector<unsigned char>(leaf_b.begin(), leaf_b.end())},
                  {2, TAPROOT_LEAF_TAPSCRIPT, std::vector<unsigned char>(leaf_c.begin(), leaf_c.end())},
              });

        // And InferTaprootTree recovers it from the spend data alone.
        const auto inferred = InferTaprootTree(spd, XOnlyPubKey(output));
        Check("InferTaprootTree recovers the tree", inferred.has_value() && inferred->size() == 3);
        if (inferred && inferred->size() == 3) {
            std::vector<std::tuple<int, std::vector<unsigned char>, int>> want{
                {1, std::vector<unsigned char>(leaf_a.begin(), leaf_a.end()), TAPROOT_LEAF_TAPSCRIPT},
                {2, std::vector<unsigned char>(leaf_b.begin(), leaf_b.end()), TAPROOT_LEAF_TAPSCRIPT},
                {2, std::vector<unsigned char>(leaf_c.begin(), leaf_c.end()), TAPROOT_LEAF_TAPSCRIPT},
            };
            auto got = *inferred;
            std::sort(want.begin(), want.end());
            std::sort(got.begin(), got.end());
            Check("InferTaprootTree recovers the same leaves at the same depths", got == want);
        }

        // A builder fed an out-of-order traversal goes invalid rather than lying.
        TaprootBuilder bad;
        bad.Add(2, leaf_a, TAPROOT_LEAF_TAPSCRIPT);
        bad.Add(0, leaf_b, TAPROOT_LEAF_TAPSCRIPT);
        Check("out-of-order Add() invalidates the builder", !bad.IsValid());

        // Two builders describing the same tree compare equal.
        TaprootBuilder same;
        same.Add(1, leaf_a, TAPROOT_LEAF_TAPSCRIPT);
        same.Add(2, leaf_b, TAPROOT_LEAF_TAPSCRIPT);
        same.Add(2, leaf_c, TAPROOT_LEAF_TAPSCRIPT);
        same.Finalize(internal);
        Check("builders over the same tree compare equal", same == builder);
        Check("the same tree gives the same output key", same.GetOutput() == output);

        // An omitted node stands in for a subtree whose scripts we do not have.
        TaprootBuilder pruned;
        pruned.Add(1, leaf_a, TAPROOT_LEAF_TAPSCRIPT);
        pruned.AddOmitted(1, ComputeTapbranchHash(ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_b),
                                                  ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_c)));
        Check("a pruned tree is complete", pruned.IsComplete());
        pruned.Finalize(internal);
        Check("a pruned tree reaches the same output key", pruned.GetOutput() == output);
        Check("a pruned tree reports only the leaves it kept", pruned.GetTreeTuples().size() == 1);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
