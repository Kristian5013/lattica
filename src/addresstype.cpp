// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <addresstype.h>

#include <crypto/sha3.h>
#include <hash.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/solver.h>
#include <uint256.h>

#include <algorithm>
#include <cassert>
#include <span>
#include <vector>

typedef std::vector<unsigned char> valtype;

namespace {
//! Construct a uint160 from a 20-byte hash buffer.
uint160 ToUint160(const unsigned char* p) { return uint160(std::span<const unsigned char>(p, 20)); }
} // namespace

ScriptHash::ScriptHash(const CScript& in) : BaseHash(Hash160(in)) {}
ScriptHash::ScriptHash(const CScriptID& in) : BaseHash{in} {}

PKHash::PKHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
PKHash::PKHash(const CKeyID& pubkey_id) : BaseHash(pubkey_id) {}

WitnessV0KeyHash::WitnessV0KeyHash(const CPubKey& pubkey) : BaseHash(pubkey.GetID()) {}
WitnessV0KeyHash::WitnessV0KeyHash(const PKHash& pubkey_hash) : BaseHash{pubkey_hash} {}

CKeyID ToKeyID(const PKHash& key_hash)
{
    return CKeyID{ToUint160(key_hash.begin())};
}

CKeyID ToKeyID(const WitnessV0KeyHash& key_hash)
{
    return CKeyID{ToUint160(key_hash.begin())};
}

CScriptID ToScriptID(const ScriptHash& script_hash)
{
    return CScriptID{ToUint160(script_hash.begin())};
}

// Lattica divergence: Core hashes the witnessScript with SHA-256
// (CSHA256().Write(in.data(), in.size()).Finalize(begin())); Lattica is
// SHA3-only, so the v0 witness-script hash is SHA3-256 — matching the P2WSH
// program check in the script interpreter.
WitnessV0ScriptHash::WitnessV0ScriptHash(const CScript& in)
{
    SHA3_256()
        .Write(std::span<const unsigned char>(in.data(), in.size()))
        .Finalize(std::span<unsigned char>(begin(), SHA3_256::OUTPUT_SIZE));
}

bool IsValidDestination(const CTxDestination& dest)
{
    return !std::holds_alternative<CNoDestination>(dest);
}

namespace {
class CScriptVisitor
{
public:
    CScript operator()(const CNoDestination& dest) const
    {
        return dest.GetScript();
    }

    CScript operator()(const PubKeyDestination& dest) const
    {
        return CScript() << ToByteVector(dest.GetPubKey()) << OP_CHECKSIG;
    }

    CScript operator()(const PKHash& keyID) const
    {
        return CScript() << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    CScript operator()(const ScriptHash& scriptID) const
    {
        return CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    }

    CScript operator()(const WitnessV0KeyHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    CScript operator()(const WitnessV0ScriptHash& id) const
    {
        return CScript() << OP_0 << ToByteVector(id);
    }

    // Lattica (option A) has no Taproot, so there is no WitnessV1Taproot case.
    // PayToAnchor is a WitnessUnknown subtype and is handled by this overload.
    CScript operator()(const WitnessUnknown& id) const
    {
        return CScript() << CScript::EncodeOP_N(id.GetWitnessVersion()) << id.GetWitnessProgram();
    }
};
} // namespace

CScript GetScriptForDestination(const CTxDestination& dest)
{
    return std::visit(CScriptVisitor(), dest);
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    std::vector<valtype> vSolutions;
    const TxoutType whichType = Solver(scriptPubKey, vSolutions);

    switch (whichType) {
    case TxoutType::PUBKEY: {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid()) {
            addressRet = CNoDestination(scriptPubKey);
        } else {
            addressRet = PubKeyDestination(pubKey);
        }
        return false;
    }
    case TxoutType::PUBKEYHASH: {
        addressRet = PKHash(uint160(vSolutions[0]));
        return true;
    }
    case TxoutType::SCRIPTHASH: {
        addressRet = ScriptHash(uint160(vSolutions[0]));
        return true;
    }
    case TxoutType::WITNESS_V0_KEYHASH: {
        WitnessV0KeyHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH: {
        WitnessV0ScriptHash hash;
        std::copy(vSolutions[0].begin(), vSolutions[0].end(), hash.begin());
        addressRet = hash;
        return true;
    }
    case TxoutType::ANCHOR: {
        addressRet = PayToAnchor();
        return true;
    }
    case TxoutType::WITNESS_UNKNOWN: {
        addressRet = WitnessUnknown{vSolutions[0][0], vSolutions[1]};
        return true;
    }
    case TxoutType::MULTISIG:
    case TxoutType::NULL_DATA:
    case TxoutType::NONSTANDARD:
        addressRet = CNoDestination(scriptPubKey);
        return false;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}
