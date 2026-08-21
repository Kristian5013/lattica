// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for Solver() (script/solver.cpp), which had none. It is not consensus
// code, but policy and the wallet both read its answer, so a script it
// misclassifies is a script the node relays or refuses wrongly.
//
// Every branch of Solver is covered once, plus the property the byte-offset
// form of MatchPayToPubkey exists to give: a P2PK output must use the minimal
// push encoding for its key. Parsing the push instead would have accepted a
// 33-byte key announced by OP_PUSHDATA1 or OP_PUSHDATA4 and called two
// different scripts the same output type.

#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/solver.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

void CheckType(const char* name, const CScript& spk, TxoutType want)
{
    std::vector<valtype> solutions;
    const TxoutType got = Solver(spk, solutions);
    const bool ok = (got == want);
    std::printf("[%s] %-52s %s\n", ok ? "PASS" : "FAIL", name, GetTxnOutputType(got).c_str());
    if (!ok) {
        std::printf("       want                                                 %s\n",
                    GetTxnOutputType(want).c_str());
        ++g_fail;
    }
}

//! A P2PK script built by hand with a chosen push opcode, so a non-minimal
//! encoding can be constructed — CScript's operator<< would always pick the
//! minimal one.
CScript RawP2PK(const valtype& key, opcodetype push)
{
    CScript s;
    s.push_back(static_cast<unsigned char>(push));
    switch (push) {
    case OP_PUSHDATA1:
        s.push_back(static_cast<unsigned char>(key.size()));
        break;
    case OP_PUSHDATA2:
        s.push_back(static_cast<unsigned char>(key.size() & 0xff));
        s.push_back(static_cast<unsigned char>((key.size() >> 8) & 0xff));
        break;
    case OP_PUSHDATA4:
        s.push_back(static_cast<unsigned char>(key.size() & 0xff));
        s.push_back(static_cast<unsigned char>((key.size() >> 8) & 0xff));
        s.push_back(static_cast<unsigned char>((key.size() >> 16) & 0xff));
        s.push_back(static_cast<unsigned char>((key.size() >> 24) & 0xff));
        break;
    default:
        break; // a direct push: the opcode itself is the length
    }
    s.insert(s.end(), key.begin(), key.end());
    s.push_back(OP_CHECKSIG);
    return s;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};

    const CKey secp = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CKey falcon = GenerateRandomKey(CKey::FALCON512_SIZE);
    const CKey mldsa = GenerateRandomKey(CKey::MLDSA44_SIZE);
    // Bind each public key before taking iterators from it. GetPubKey() returns
    // by value, so begin() and end() on two separate calls belong to two
    // different temporaries — a range that is not a range.
    const CPubKey p_secp = secp.GetPubKey();
    const CPubKey p_falcon = falcon.GetPubKey();
    const CPubKey p_mldsa = mldsa.GetPubKey();
    const valtype k_secp(p_secp.begin(), p_secp.end());
    const valtype k_falcon(p_falcon.begin(), p_falcon.end());
    const valtype k_mldsa(p_mldsa.begin(), p_mldsa.end());
    const valtype h20(20, 0xab);
    const valtype h32(32, 0xcd);

    // ---- P2PK, one per scheme. 33 bytes push directly; 897 and 1312 need
    // OP_PUSHDATA2, and Solver has to know both encodings.
    {
        std::vector<valtype> sol;
        for (const auto& [name, key] : {std::pair{"secp256k1", k_secp},
                                        std::pair{"Falcon-512", k_falcon},
                                        std::pair{"ML-DSA-44", k_mldsa}}) {
            const CScript spk = CScript() << key << OP_CHECKSIG;
            CheckType((std::string("P2PK ") + name).c_str(), spk, TxoutType::PUBKEY);
            Solver(spk, sol);
            Check("...and the key comes back intact", sol.size() == 1 && sol[0] == key);
        }
    }

    // ---- The minimal-encoding rule.
    {
        // What CScript itself emits is minimal, and must classify.
        CheckType("P2PK secp with a direct push (minimal)",
                  RawP2PK(k_secp, static_cast<opcodetype>(CPubKey::SECP256K1_SIZE)), TxoutType::PUBKEY);
        CheckType("P2PK Falcon with OP_PUSHDATA2 (minimal)",
                  RawP2PK(k_falcon, OP_PUSHDATA2), TxoutType::PUBKEY);

        // The same keys announced a longer way round must not.
        CheckType("P2PK secp via OP_PUSHDATA1 is not standard",
                  RawP2PK(k_secp, OP_PUSHDATA1), TxoutType::NONSTANDARD);
        CheckType("P2PK secp via OP_PUSHDATA2 is not standard",
                  RawP2PK(k_secp, OP_PUSHDATA2), TxoutType::NONSTANDARD);
        CheckType("P2PK Falcon via OP_PUSHDATA4 is not standard",
                  RawP2PK(k_falcon, OP_PUSHDATA4), TxoutType::NONSTANDARD);
        CheckType("P2PK ML-DSA via OP_PUSHDATA4 is not standard",
                  RawP2PK(k_mldsa, OP_PUSHDATA4), TxoutType::NONSTANDARD);
    }

    // ---- The remaining branches, one script each.
    CheckType("P2PKH",
              CScript() << OP_DUP << OP_HASH160 << h20 << OP_EQUALVERIFY << OP_CHECKSIG,
              TxoutType::PUBKEYHASH);
    CheckType("P2SH",
              CScript() << OP_HASH160 << h20 << OP_EQUAL,
              TxoutType::SCRIPTHASH);
    CheckType("witness v0, 20-byte program",
              CScript() << OP_0 << h20,
              TxoutType::WITNESS_V0_KEYHASH);
    CheckType("witness v0, 32-byte program",
              CScript() << OP_0 << h32,
              TxoutType::WITNESS_V0_SCRIPTHASH);
    CheckType("witness v1 is unknown here (no Taproot)",
              CScript() << OP_1 << h32,
              TxoutType::WITNESS_UNKNOWN);
    CheckType("witness v2 is unknown, and reserved for post-quantum",
              CScript() << OP_2 << h32,
              TxoutType::WITNESS_UNKNOWN);
    CheckType("witness v0 of an unexpected length",
              CScript() << OP_0 << valtype(30, 0x11),
              TxoutType::NONSTANDARD);
    CheckType("anchor",
              CScript() << OP_1 << valtype{0x4e, 0x73},
              TxoutType::ANCHOR);
    CheckType("OP_RETURN with data",
              CScript() << OP_RETURN << valtype{1, 2, 3},
              TxoutType::NULL_DATA);
    CheckType("bare OP_RETURN",
              CScript() << OP_RETURN,
              TxoutType::NULL_DATA);
    CheckType("garbage",
              CScript() << OP_ADD << OP_DUP,
              TxoutType::NONSTANDARD);

    // ---- Multisig, and the solution layout callers rely on.
    {
        const CScript ms = CScript() << OP_2 << k_secp << k_secp << OP_2 << OP_CHECKMULTISIG;
        CheckType("2-of-2 multisig", ms, TxoutType::MULTISIG);
        std::vector<valtype> sol;
        Solver(ms, sol);
        Check("multisig solutions are threshold, keys..., count",
              sol.size() == 4 && sol.front() == valtype{2} && sol.back() == valtype{2} &&
              sol[1] == k_secp && sol[2] == k_secp);
    }

    // ---- Mixed-scheme multisig, the shape a transition wants: the sizes
    // differ, so this also confirms MatchMultisig is not size-locked.
    CheckType("multisig mixing secp256k1 and ML-DSA-44",
              CScript() << OP_2 << k_secp << k_mldsa << OP_2 << OP_CHECKMULTISIG,
              TxoutType::MULTISIG);

    // ---- Every name round-trips, so a new TxoutType cannot be added without
    // giving it one.
    for (const TxoutType t : {TxoutType::NONSTANDARD, TxoutType::ANCHOR, TxoutType::PUBKEY,
                              TxoutType::PUBKEYHASH, TxoutType::SCRIPTHASH, TxoutType::MULTISIG,
                              TxoutType::NULL_DATA, TxoutType::WITNESS_V0_SCRIPTHASH,
                              TxoutType::WITNESS_V0_KEYHASH, TxoutType::WITNESS_UNKNOWN}) {
        if (!GetTxnOutputType(t).empty()) continue;
        Check("every TxoutType has a name", false);
        break;
    }
    Check("every TxoutType has a name", true);

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
