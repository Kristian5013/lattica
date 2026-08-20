// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Keystores that can supply keys/scripts for signing, modeled on Bitcoin Core's
// script/signingprovider.h.
//
// This is DELIBERATELY a custom subset of Core's interface, not an incomplete
// port. Core's SigningProvider is coupled to elliptic-curve cryptography: of its
// ~15 virtuals, ~10 are Taproot (GetTaprootSpendData/GetTaprootBuilder, the XOnly
// helpers), MuSig2 (session nonce methods), or BIP32 descriptor key-origin
// (GetKeyOrigin). Lattica has no EC: a lattice signature cannot be tweaked or
// aggregated and an ML-DSA key is 1312 bytes, so Taproot/MuSig2 are impossible
// here (see the WitnessV1Taproot omission in addresstype.h). Reproducing those
// methods would mean porting XOnlyPubKey/TaprootBuilder/MuSig2SecNonce into a coin
// that can never populate them — pure dead code. So the interface keeps only the
// scheme-agnostic surface that actually applies: keys and scripts. This layer is
// where Lattica's crypto lives and therefore where it diverges most from Core;
// the consensus engine, mempool, and validation are faithful 1:1 ports.
//
// FillableSigningProvider (CKeyID -> CKey, CScriptID -> CScript) is the keystore
// the signer and wallet build on; FlatSigningProvider (a plain struct of maps,
// with Merge), HidingSigningProvider (a secret-hiding wrapper), and
// MultiSigningProvider (a fan-out over several providers) round out the set.

#ifndef LATTICA_SCRIPT_SIGNINGPROVIDER_H
#define LATTICA_SCRIPT_SIGNINGPROVIDER_H

#include <addresstype.h>
#include <attributes.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <sync.h>
#include <uint256.h>

#include <map>
#include <memory>
#include <set>
#include <vector>

/** An interface to be implemented by keystores that support signing. */
class SigningProvider
{
public:
    virtual ~SigningProvider() = default;
    virtual bool GetCScript(const CScriptID& /*scriptid*/, CScript& /*script*/) const { return false; }
    virtual bool HaveCScript(const CScriptID& /*scriptid*/) const { return false; }
    virtual bool GetPubKey(const CKeyID& /*address*/, CPubKey& /*pubkey*/) const { return false; }
    virtual bool GetKey(const CKeyID& /*address*/, CKey& /*key*/) const { return false; }
    virtual bool HaveKey(const CKeyID& /*address*/) const { return false; }
};

extern const SigningProvider& DUMMY_SIGNING_PROVIDER;

/** A signing provider that wraps another, optionally hiding its private keys. */
class HidingSigningProvider : public SigningProvider
{
private:
    const bool m_hide_secret;
    const bool m_hide_origin; //!< Retained for ctor/API parity; only the (dropped) GetKeyOrigin consults it.
    const SigningProvider* m_provider;

public:
    HidingSigningProvider(const SigningProvider* provider, bool hide_secret, bool hide_origin)
        : m_hide_secret(hide_secret), m_hide_origin(hide_origin), m_provider(provider) {}
    bool GetCScript(const CScriptID& scriptid, CScript& script) const override;
    bool GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const override;
    bool GetKey(const CKeyID& keyid, CKey& key) const override;
};

/** A signing provider that stores keys and scripts in plain (public) maps. */
struct FlatSigningProvider final : public SigningProvider {
    std::map<CScriptID, CScript> scripts;
    std::map<CKeyID, CPubKey> pubkeys;
    std::map<CKeyID, CKey> keys;

    bool GetCScript(const CScriptID& scriptid, CScript& script) const override;
    bool GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const override;
    bool HaveKey(const CKeyID& keyid) const override;
    bool GetKey(const CKeyID& keyid, CKey& key) const override;

    FlatSigningProvider& Merge(FlatSigningProvider&& b) LIFETIMEBOUND;
};

/** Fillable signing provider that keeps keys and scripts in an in-memory map. */
class FillableSigningProvider : public SigningProvider
{
protected:
    using KeyMap = std::map<CKeyID, CKey>;
    using ScriptMap = std::map<CScriptID, CScript>;

    /** Map of key id to unencrypted private keys known by the signing provider. */
    KeyMap mapKeys GUARDED_BY(cs_KeyStore);
    /** Map of script id to scripts known by the signing provider. */
    ScriptMap mapScripts GUARDED_BY(cs_KeyStore);

    void ImplicitlyLearnRelatedKeyScripts(const CPubKey& pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

public:
    mutable RecursiveMutex cs_KeyStore;

    virtual bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey);
    virtual bool AddKey(const CKey& key) { return AddKeyPubKey(key, key.GetPubKey()); }
    virtual bool GetPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const override;
    virtual bool HaveKey(const CKeyID& address) const override;
    virtual std::set<CKeyID> GetKeys() const;
    virtual bool GetKey(const CKeyID& address, CKey& keyOut) const override;
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID& hash) const override;
    virtual std::set<CScriptID> GetCScripts() const;
    virtual bool GetCScript(const CScriptID& hash, CScript& redeemScriptOut) const override;
};

/** A signing provider that delegates to several others in turn. */
class MultiSigningProvider : public SigningProvider
{
private:
    std::vector<std::unique_ptr<SigningProvider>> m_providers;

public:
    void AddProvider(std::unique_ptr<SigningProvider> provider);

    bool GetCScript(const CScriptID& scriptid, CScript& script) const override;
    bool GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const override;
    bool GetKey(const CKeyID& keyid, CKey& key) const override;
};

/** Return the CKeyID of the key that can sign for the given destination, if the
 *  store can determine it (else a null CKeyID). */
CKeyID GetKeyForDestination(const SigningProvider& store, const CTxDestination& dest);

/** Checks if a script can be signed (i.e. solved) by the given SigningProvider. */
bool IsSolvable(const SigningProvider& provider, const CScript& script);

#endif // LATTICA_SCRIPT_SIGNINGPROVIDER_H
