// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the destination <-> script mapping (addresstype.cpp): each standard
// destination produces the expected scriptPubKey, ExtractDestination recovers it,
// and a script -> destination -> script round-trip is stable. Uses a real ML-DSA
// public key so the hashes (Hash160 = first 20 of SHA3-256; v0 script hash =
// SHA3-256) are exercised end to end.

#include <addresstype.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/solver.h>

#include <cstdio>
#include <variant>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

// dest -> script -> dest' -> script' must be stable, and the recovered script
// equal to the original.
bool RoundTrips(const CTxDestination& dest)
{
    const CScript spk = GetScriptForDestination(dest);
    CTxDestination back;
    ExtractDestination(spk, back);
    return GetScriptForDestination(back) == spk && IsValidDestination(back);
}
} // namespace

int main()
{
    const CKey key = GenerateRandomKey();
    const CPubKey pub = key.GetPubKey();
    const CKeyID keyid = pub.GetID();

    // P2WPKH program == Hash160(pubkey), and the P2PKH/P2WPKH key hashes agree.
    {
        const WitnessV0KeyHash wkh(pub);
        const PKHash pkh(pub);
        Check("WitnessV0KeyHash(pubkey) == PKHash(pubkey) bytes",
              std::vector<unsigned char>(wkh.begin(), wkh.end()) == std::vector<unsigned char>(pkh.begin(), pkh.end()));
        Check("PKHash(pubkey) == PKHash(keyid)",
              std::vector<unsigned char>(pkh.begin(), pkh.end()) == std::vector<unsigned char>(keyid.begin(), keyid.end()));
    }

    // P2WPKH: OP_0 <20-byte keyhash>.
    {
        const CTxDestination dest = WitnessV0KeyHash(pub);
        const CScript spk = GetScriptForDestination(dest);
        const CScript expect = CScript() << OP_0 << ToByteVector(WitnessV0KeyHash(pub));
        Check("P2WPKH script is OP_0 <20>", spk == expect);
        CTxDestination back;
        Check("ExtractDestination(P2WPKH) ok", ExtractDestination(spk, back));
        Check("P2WPKH is WitnessV0KeyHash", std::holds_alternative<WitnessV0KeyHash>(back));
        Check("P2WPKH round-trips", RoundTrips(dest));
    }

    // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG.
    {
        const CTxDestination dest = PKHash(pub);
        const CScript spk = GetScriptForDestination(dest);
        const CScript expect = CScript() << OP_DUP << OP_HASH160 << ToByteVector(PKHash(pub)) << OP_EQUALVERIFY << OP_CHECKSIG;
        Check("P2PKH script shape", spk == expect);
        CTxDestination back;
        Check("ExtractDestination(P2PKH) ok", ExtractDestination(spk, back) && std::holds_alternative<PKHash>(back));
        Check("P2PKH round-trips", RoundTrips(dest));
    }

    // P2SH of an arbitrary redeem script: OP_HASH160 <20> OP_EQUAL.
    {
        const CScript redeem = CScript() << OP_1; // any script
        const CTxDestination dest = ScriptHash(redeem);
        const CScript spk = GetScriptForDestination(dest);
        const CScript expect = CScript() << OP_HASH160 << ToByteVector(ScriptHash(redeem)) << OP_EQUAL;
        Check("P2SH script shape", spk == expect);
        CTxDestination back;
        Check("ExtractDestination(P2SH) ok", ExtractDestination(spk, back) && std::holds_alternative<ScriptHash>(back));
        Check("P2SH round-trips", RoundTrips(dest));
    }

    // P2WSH of a witnessScript: OP_0 <32-byte SHA3-256(script)>.
    {
        const CScript witnessScript = CScript() << ToByteVector(pub) << OP_CHECKSIG;
        const CTxDestination dest = WitnessV0ScriptHash(witnessScript);
        const CScript spk = GetScriptForDestination(dest);
        const CScript expect = CScript() << OP_0 << ToByteVector(WitnessV0ScriptHash(witnessScript));
        Check("P2WSH script is OP_0 <32>", spk == expect && spk.size() == 34);
        CTxDestination back;
        Check("ExtractDestination(P2WSH) ok", ExtractDestination(spk, back) && std::holds_alternative<WitnessV0ScriptHash>(back));
        Check("P2WSH round-trips", RoundTrips(dest));
    }

    // P2PK has no address: ExtractDestination returns false but yields PubKeyDestination.
    {
        const CScript spk = CScript() << ToByteVector(pub) << OP_CHECKSIG;
        CTxDestination back;
        const bool ok = ExtractDestination(spk, back);
        Check("ExtractDestination(P2PK) returns false (no address)", !ok);
        Check("P2PK yields PubKeyDestination", std::holds_alternative<PubKeyDestination>(back));
        Check("GetScriptForDestination(PubKeyDestination) == P2PK", GetScriptForDestination(back) == spk);
    }

    // IsValidDestination.
    {
        Check("CNoDestination is not valid", !IsValidDestination(CTxDestination(CNoDestination())));
        Check("WitnessV0KeyHash is valid", IsValidDestination(CTxDestination(WitnessV0KeyHash(pub))));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
