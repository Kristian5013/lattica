// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_ADDRESSTYPE_H
#define LATTICA_ADDRESSTYPE_H

#include <attributes.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <util/check.h>
#include <util/hash_type.h>

#include <algorithm>
#include <variant>
#include <vector>

class CNoDestination
{
private:
    CScript m_script;

public:
    CNoDestination() = default;
    explicit CNoDestination(const CScript& script) : m_script(script) {}

    const CScript& GetScript() const LIFETIMEBOUND { return m_script; }

    friend bool operator==(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() == b.GetScript(); }
    friend bool operator<(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() < b.GetScript(); }
};

struct PubKeyDestination {
private:
    CPubKey m_pubkey;

public:
    explicit PubKeyDestination(const CPubKey& pubkey) : m_pubkey(pubkey) {}

    const CPubKey& GetPubKey() const LIFETIMEBOUND { return m_pubkey; }

    friend bool operator==(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() == b.GetPubKey(); }
    friend bool operator<(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() < b.GetPubKey(); }
};

struct PKHash : public BaseHash<uint160>
{
    PKHash() : BaseHash() {}
    explicit PKHash(const uint160& hash) : BaseHash(hash) {}
    explicit PKHash(const CPubKey& pubkey);
    explicit PKHash(const CKeyID& pubkey_id);
};
CKeyID ToKeyID(const PKHash& key_hash);

struct WitnessV0KeyHash;
struct WitnessV2KeyHash;

struct ScriptHash : public BaseHash<uint160>
{
    ScriptHash() : BaseHash() {}
    // These don't do what you'd expect.
    // Use ScriptHash(GetScriptForDestination(...)) instead.
    explicit ScriptHash(const WitnessV0KeyHash& hash) = delete;
    explicit ScriptHash(const WitnessV2KeyHash& hash) = delete;
    explicit ScriptHash(const PKHash& hash) = delete;

    explicit ScriptHash(const uint160& hash) : BaseHash(hash) {}
    explicit ScriptHash(const CScript& script);
    explicit ScriptHash(const CScriptID& script);
};
CScriptID ToScriptID(const ScriptHash& script_hash);

struct WitnessV0ScriptHash : public BaseHash<uint256>
{
    WitnessV0ScriptHash() : BaseHash() {}
    explicit WitnessV0ScriptHash(const uint256& hash) : BaseHash(hash) {}
    explicit WitnessV0ScriptHash(const CScript& script);
};

struct WitnessV0KeyHash : public BaseHash<uint160>
{
    WitnessV0KeyHash() : BaseHash() {}
    explicit WitnessV0KeyHash(const uint160& hash) : BaseHash(hash) {}
    explicit WitnessV0KeyHash(const CPubKey& pubkey);
    explicit WitnessV0KeyHash(const PKHash& pubkey_hash);
};
CKeyID ToKeyID(const WitnessV0KeyHash& key_hash);

struct WitnessV1Taproot : public XOnlyPubKey
{
    WitnessV1Taproot() : XOnlyPubKey() {}
    explicit WitnessV1Taproot(const XOnlyPubKey& xpk) : XOnlyPubKey(xpk) {}
};

/** Witness v2, the post-quantum pair. Structurally v0's, and told apart from it
 *  only by the version byte the script carries: the hash is the same Hash160 of
 *  a public key or SHA3-256 of a script. What differs is the scheme the key
 *  inside belongs to, which the witness version names. */
struct WitnessV2ScriptHash : public BaseHash<uint256>
{
    WitnessV2ScriptHash() : BaseHash() {}
    explicit WitnessV2ScriptHash(const uint256& hash) : BaseHash(hash) {}
    explicit WitnessV2ScriptHash(const CScript& script);
};

struct WitnessV2KeyHash : public BaseHash<uint160>
{
    WitnessV2KeyHash() : BaseHash() {}
    explicit WitnessV2KeyHash(const uint160& hash) : BaseHash(hash) {}
    explicit WitnessV2KeyHash(const CPubKey& pubkey);
    explicit WitnessV2KeyHash(const PKHash& pubkey_hash);
};
CKeyID ToKeyID(const WitnessV2KeyHash& key_hash);

//! CTxDestination subtype to encode any future Witness version
struct WitnessUnknown
{
private:
    unsigned int m_version;
    std::vector<unsigned char> m_program;

public:
    WitnessUnknown(unsigned int version, const std::vector<unsigned char>& program) : m_version(version), m_program(program) {}
    WitnessUnknown(int version, const std::vector<unsigned char>& program) : m_version(static_cast<unsigned int>(version)), m_program(program) {}

    unsigned int GetWitnessVersion() const { return m_version; }
    const std::vector<unsigned char>& GetWitnessProgram() const LIFETIMEBOUND { return m_program; }

    friend bool operator==(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() != w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() == w2.GetWitnessProgram();
    }

    friend bool operator<(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() < w2.GetWitnessVersion()) return true;
        if (w1.GetWitnessVersion() > w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() < w2.GetWitnessProgram();
    }
};

/** Witness program for Pay-to-Anchor output script type */
inline const std::vector<unsigned char> ANCHOR_BYTES{0x4e, 0x73};

struct PayToAnchor : public WitnessUnknown
{
    PayToAnchor() : WitnessUnknown(1, ANCHOR_BYTES) {
        Assume(CScript::IsPayToAnchor(1, ANCHOR_BYTES));
    };
};

/**
 * A txout script categorized into standard templates.
 *  * CNoDestination: Optionally a script, no corresponding address.
 *  * PubKeyDestination: TxoutType::PUBKEY (P2PK), no corresponding address
 *  * PKHash: TxoutType::PUBKEYHASH destination (P2PKH address)
 *  * ScriptHash: TxoutType::SCRIPTHASH destination (P2SH address)
 *  * WitnessV0ScriptHash: TxoutType::WITNESS_V0_SCRIPTHASH destination (P2WSH address)
 *  * WitnessV0KeyHash: TxoutType::WITNESS_V0_KEYHASH destination (P2WPKH address)
 *  * WitnessV1Taproot: TxoutType::WITNESS_V1_TAPROOT destination (P2TR address)
 *  * WitnessV2ScriptHash: TxoutType::WITNESS_V2_SCRIPTHASH destination
 *  * WitnessV2KeyHash: TxoutType::WITNESS_V2_KEYHASH destination
 *  * PayToAnchor: TxoutType::ANCHOR destination (P2A address)
 *  * WitnessUnknown: TxoutType::WITNESS_UNKNOWN destination (P2W??? address)
 *  A CTxDestination is the internal data type encoded in a Lattica address
 */
using CTxDestination = std::variant<CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1Taproot, WitnessV2ScriptHash, WitnessV2KeyHash, PayToAnchor, WitnessUnknown>;

/** Check whether a CTxDestination corresponds to one with an address. */
bool IsValidDestination(const CTxDestination& dest);

/**
 * Parse a scriptPubKey for the destination.
 *
 * For standard scripts that have addresses (and P2PK as an exception), a corresponding CTxDestination
 * is assigned to addressRet.
 * For all other scripts. addressRet is assigned as a CNoDestination containing the scriptPubKey.
 *
 * Returns true for standard destinations with addresses - P2PKH, P2SH, P2WPKH, P2WSH, P2TR, the
 * witness v2 pair and P2W??? scripts.
 * Returns false for non-standard destinations and those without addresses - P2PK, bare multisig, null data, and nonstandard scripts.
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/**
 * Generate a Lattica scriptPubKey for the given CTxDestination. Returns a P2PKH
 * script for a CKeyID destination, a P2SH script for a CScriptID, and an empty
 * script for CNoDestination.
 */
CScript GetScriptForDestination(const CTxDestination& dest);

#endif // LATTICA_ADDRESSTYPE_H
