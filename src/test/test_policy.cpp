// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for local node policy (policy/policy): IsStandard script classification,
// IsStandardTx, IsDust, the Lattica-adapted MANDATORY/STANDARD verify-flag sets
// (no DERSIG/Taproot), and the vsize == bytes identity (WITNESS_SCALE_FACTOR=1).

#include <policy/policy.h>
#include <pubkey.h>
#include <policy/feerate.h>
#include <script/solver.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <primitives/transaction.h>
#include <consensus/amount.h>

#include <cstdio>
#include <optional>
#include <string>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

CScript P2PKH() { CScript s; s << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xab) << OP_EQUALVERIFY << OP_CHECKSIG; return s; }
CScript P2WPKH() { CScript s; s << OP_0 << std::vector<unsigned char>(20, 0xcd); return s; }
CScript P2SH() { CScript s; s << OP_HASH160 << std::vector<unsigned char>(20, 0xef) << OP_EQUAL; return s; }
CScript NullData() { CScript s; s << OP_RETURN << std::vector<unsigned char>(8, 0x01); return s; }

} // namespace

int main()
{
    // IsStandard classification.
    {
        TxoutType t;
        Check("P2PKH standard", IsStandard(P2PKH(), t) && t == TxoutType::PUBKEYHASH);
        Check("P2WPKH standard", IsStandard(P2WPKH(), t) && t == TxoutType::WITNESS_V0_KEYHASH);
        Check("P2SH standard", IsStandard(P2SH(), t) && t == TxoutType::SCRIPTHASH);
        Check("NULL_DATA standard", IsStandard(NullData(), t) && t == TxoutType::NULL_DATA);
        CScript junk; junk << OP_1 << OP_2 << OP_3 << OP_CHECKSIG; // not a known form
        Check("junk nonstandard", !IsStandard(junk, t) && t == TxoutType::NONSTANDARD);
    }

    // Lattica verify-flag sets: P2SH + WITNESS mandatory; no DERSIG/Taproot exist.
    {
        bool p2sh = bool(MANDATORY_SCRIPT_VERIFY_FLAGS & script_verify_flags{SCRIPT_VERIFY_P2SH});
        bool wit = bool(MANDATORY_SCRIPT_VERIFY_FLAGS & script_verify_flags{SCRIPT_VERIFY_WITNESS});
        bool std_super = (STANDARD_SCRIPT_VERIFY_FLAGS & MANDATORY_SCRIPT_VERIFY_FLAGS) == MANDATORY_SCRIPT_VERIFY_FLAGS;
        Check("MANDATORY has P2SH+WITNESS", p2sh && wit);
        Check("STANDARD superset of MANDATORY", std_super);
        Check("witness v0 keeps Bitcoin's standard item size", MAX_STANDARD_P2WSH_STACK_ITEM_SIZE == 80);
        Check("witness v2 relays a whole ML-DSA signature",
              MAX_STANDARD_WITNESS_V2_STACK_ITEM_SIZE == MAX_SCRIPT_ELEMENT_SIZE_V2 &&
              MAX_STANDARD_WITNESS_V2_STACK_ITEM_SIZE >= CPubKey::MLDSA44_SIGNATURE_SIZE + 1);
    }

    // IsStandardTx: a plain version-2 P2WPKH-output spend is standard.
    {
        CMutableTransaction tx;
        tx.version = 2;
        CTxIn in;
        uint256 prev; for (unsigned i = 0; i < uint256::size(); ++i) prev.begin()[i] = (unsigned char)(i + 1);
        in.prevout = COutPoint(Txid::FromUint256(prev), 0);
        in.scriptSig = CScript(); // pushonly (empty)
        tx.vin.push_back(in);
        tx.vout.push_back(CTxOut(50000, P2WPKH()));
        std::string reason;
        bool ok = IsStandardTx(CTransaction(tx), /*max_datacarrier_bytes=*/std::optional<unsigned>{83}, /*permit_bare_multisig=*/true, CFeeRate(DUST_RELAY_TX_FEE), reason);
        Check("plain tx is standard", ok);

        // Bad version -> nonstandard.
        CMutableTransaction txv = tx; txv.version = 9;
        std::string r2;
        Check("bad version nonstandard", !IsStandardTx(CTransaction(txv), std::optional<unsigned>{83}, true, CFeeRate(DUST_RELAY_TX_FEE), r2) && r2 == "version");
    }

    // IsDust: a tiny output is dust; a large one isn't.
    {
        CFeeRate rate(DUST_RELAY_TX_FEE);
        Check("1-sat output is dust", IsDust(CTxOut(1, P2WPKH()), rate));
        Check("1-coin output not dust", !IsDust(CTxOut(COIN, P2WPKH()), rate));
    }

    // vsize == serialized bytes (WITNESS_SCALE_FACTOR == 1).
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
        tx.vout.push_back(CTxOut(COIN, P2PKH()));
        const CTransaction ctx{tx};
        Check("vsize == weight (vsize=bytes)", GetVirtualTransactionSize(ctx) == GetTransactionWeight(ctx));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
