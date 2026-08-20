// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <script/signingprovider.h>

#include <addresstype.h>
#include <logging.h>

const SigningProvider& DUMMY_SIGNING_PROVIDER = SigningProvider();

namespace {
template <typename M, typename K, typename V>
bool LookupHelper(const M& map, const K& key, V& value)
{
    auto it = map.find(key);
    if (it != map.end()) {
        value = it->second;
        return true;
    }
    return false;
}
} // namespace

bool HidingSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    return m_provider->GetCScript(scriptid, script);
}

bool HidingSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    return m_provider->GetPubKey(keyid, pubkey);
}

bool HidingSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    if (m_hide_secret) return false;
    return m_provider->GetKey(keyid, key);
}

bool FlatSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const { return LookupHelper(scripts, scriptid, script); }
bool FlatSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const { return LookupHelper(pubkeys, keyid, pubkey); }
bool FlatSigningProvider::HaveKey(const CKeyID& keyid) const
{
    CKey key;
    return LookupHelper(keys, keyid, key);
}
bool FlatSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const { return LookupHelper(keys, keyid, key); }

FlatSigningProvider& FlatSigningProvider::Merge(FlatSigningProvider&& b)
{
    // Lattica drops Core's origins/tr_trees/aggregate_pubkeys/musig2 maps
    // (Taproot/MuSig2/key-origin), so only scripts/pubkeys/keys are merged.
    scripts.merge(b.scripts);
    pubkeys.merge(b.pubkeys);
    keys.merge(b.keys);
    return *this;
}

bool FillableSigningProvider::GetCScript(const CScriptID& hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end()) {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

bool FillableSigningProvider::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.contains(hash);
}

std::set<CScriptID> FillableSigningProvider::GetCScripts() const
{
    LOCK(cs_KeyStore);
    std::set<CScriptID> set_script;
    for (const auto& mi : mapScripts) {
        set_script.insert(mi.first);
    }
    return set_script;
}

bool FillableSigningProvider::GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool FillableSigningProvider::AddKeyPubKey(const CKey& key, const CPubKey& pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    ImplicitlyLearnRelatedKeyScripts(pubkey);
    return true;
}

bool FillableSigningProvider::GetKey(const CKeyID& address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    KeyMap::const_iterator mi = mapKeys.find(address);
    if (mi != mapKeys.end()) {
        keyOut = mi->second;
        return true;
    }
    return false;
}

std::set<CKeyID> FillableSigningProvider::GetKeys() const
{
    LOCK(cs_KeyStore);
    std::set<CKeyID> set_address;
    for (const auto& mi : mapKeys) {
        set_address.insert(mi.first);
    }
    return set_address;
}

bool FillableSigningProvider::HaveKey(const CKeyID& address) const
{
    LOCK(cs_KeyStore);
    return mapKeys.contains(address);
}

bool FillableSigningProvider::AddCScript(const CScript& redeemScript)
{
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        LogError("FillableSigningProvider::AddCScript(): redeemScripts > %i bytes are invalid\n", MAX_SCRIPT_ELEMENT_SIZE);
        return false;
    }

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

void FillableSigningProvider::ImplicitlyLearnRelatedKeyScripts(const CPubKey& pubkey)
{
    AssertLockHeld(cs_KeyStore);
    CKeyID key_id = pubkey.GetID();
    // Lattica: ML-DSA public keys have no compressed/uncompressed distinction
    // and are always valid in SegWit, so (unlike Core, which gates this on
    // pubkey.IsCompressed()) always learn the implied P2WPKH script for the key,
    // so that a P2SH-of-P2WPKH redeemScript can later be solved.
    CScript script = GetScriptForDestination(WitnessV0KeyHash(key_id));
    CScriptID id(script);
    mapScripts[id] = std::move(script);
}

void MultiSigningProvider::AddProvider(std::unique_ptr<SigningProvider> provider)
{
    m_providers.push_back(std::move(provider));
}

bool MultiSigningProvider::GetCScript(const CScriptID& scriptid, CScript& script) const
{
    for (const auto& provider : m_providers) {
        if (provider->GetCScript(scriptid, script)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const
{
    for (const auto& provider : m_providers) {
        if (provider->GetPubKey(keyid, pubkey)) return true;
    }
    return false;
}

bool MultiSigningProvider::GetKey(const CKeyID& keyid, CKey& key) const
{
    for (const auto& provider : m_providers) {
        if (provider->GetKey(keyid, key)) return true;
    }
    return false;
}

CKeyID GetKeyForDestination(const SigningProvider& store, const CTxDestination& dest)
{
    // Only supports destinations which map to single public keys:
    // P2PKH, P2WPKH, and P2SH-witness-v0-keyhash.
    if (auto id = std::get_if<PKHash>(&dest)) {
        return ToKeyID(*id);
    }
    if (auto witness_id = std::get_if<WitnessV0KeyHash>(&dest)) {
        return ToKeyID(*witness_id);
    }
    if (auto script_hash = std::get_if<ScriptHash>(&dest)) {
        CScript script;
        CScriptID script_id = ToScriptID(*script_hash);
        CTxDestination inner_dest;
        if (store.GetCScript(script_id, script) && ExtractDestination(script, inner_dest)) {
            if (auto inner_witness_id = std::get_if<WitnessV0KeyHash>(&inner_dest)) {
                return ToKeyID(*inner_witness_id);
            }
        }
    }
    // Lattica (option A) has no Taproot, so no WitnessV1Taproot key-path case.
    return CKeyID();
}
