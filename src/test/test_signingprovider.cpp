// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the FillableSigningProvider keystore (signingprovider.cpp): keys and
// scripts round-trip through the maps, adding a key implicitly learns its P2WPKH
// script (so a P2SH-of-P2WPKH redeemScript is solvable), oversized redeem scripts
// are rejected, and GetKeyForDestination resolves P2PKH/P2WPKH/P2SH-P2WPKH to the
// signing key id.

#include <script/signingprovider.h>
#include <addresstype.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>

#include <cstdio>
#include <memory>
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

    // Adding a key implicitly learns its P2WPKH script.
    const CScript p2wpkh = GetScriptForDestination(WitnessV0KeyHash(pub));
    const CScriptID p2wpkh_id(p2wpkh);
    {
        Check("implicit P2WPKH script was learned", ks.HaveCScript(p2wpkh_id));
        CScript sout;
        Check("GetCScript returns the P2WPKH script", ks.GetCScript(p2wpkh_id, sout) && sout == p2wpkh);
    }

    // Explicit script storage.
    {
        const CScript redeem = CScript() << OP_1;
        const CScriptID redeem_id(redeem);
        Check("AddCScript succeeds", ks.AddCScript(redeem));
        Check("HaveCScript is true for the redeem script", ks.HaveCScript(redeem_id));
        Check("GetCScripts contains the redeem script", ks.GetCScripts().count(redeem_id) == 1);

        // Oversized redeem scripts (> MAX_SCRIPT_ELEMENT_SIZE) are rejected.
        const std::vector<unsigned char> big(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x00);
        const CScript too_big(big.begin(), big.end());
        Check("oversized redeem script is rejected", !ks.AddCScript(too_big));
    }

    // GetKeyForDestination.
    {
        Check("GetKeyForDestination(P2PKH) -> key id", GetKeyForDestination(ks, CTxDestination(PKHash(pub))) == id);
        Check("GetKeyForDestination(P2WPKH) -> key id", GetKeyForDestination(ks, CTxDestination(WitnessV0KeyHash(pub))) == id);
        // P2SH wrapping the (implicitly learned) P2WPKH script resolves to the key.
        Check("GetKeyForDestination(P2SH-P2WPKH) -> key id", GetKeyForDestination(ks, CTxDestination(ScriptHash(p2wpkh))) == id);
        // A P2SH whose redeem script the store does not know yields a null id.
        const CScript unknown = CScript() << OP_2 << OP_3;
        Check("GetKeyForDestination(unknown P2SH) -> null", GetKeyForDestination(ks, CTxDestination(ScriptHash(unknown))) == CKeyID());
    }

    // A second key, for the multi-key providers below.
    const CKey key2 = GenerateRandomKey();
    const CPubKey pub2 = key2.GetPubKey();
    const CKeyID id2 = pub2.GetID();
    const CScript p2wpkh2 = GetScriptForDestination(WitnessV0KeyHash(pub2));
    const CScriptID p2wpkh2_id(p2wpkh2);

    // FlatSigningProvider: plain public maps + Merge.
    {
        FlatSigningProvider flat;
        flat.keys[id] = key;
        flat.pubkeys[id] = pub;
        flat.scripts[p2wpkh_id] = p2wpkh;
        CKey kout;
        Check("Flat.GetKey", flat.GetKey(id, kout) && kout == key);
        Check("Flat.HaveKey", flat.HaveKey(id) && !flat.HaveKey(id2));
        CPubKey pout;
        Check("Flat.GetPubKey", flat.GetPubKey(id, pout) && pout == pub);
        CScript sout;
        Check("Flat.GetCScript", flat.GetCScript(p2wpkh_id, sout) && sout == p2wpkh);

        FlatSigningProvider a, b;
        a.keys[id] = key;
        b.keys[id2] = key2;
        a.Merge(std::move(b));
        Check("Flat.Merge combines keys", a.HaveKey(id) && a.HaveKey(id2));
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
        Check("Hiding still forwards GetCScript", hidden.GetCScript(p2wpkh_id, sout) && sout == p2wpkh);

        HidingSigningProvider shown(&base, /*hide_secret=*/false, /*hide_origin=*/false);
        Check("Hiding(!hide_secret) forwards GetKey", shown.GetKey(id, kout) && kout == key);
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

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
