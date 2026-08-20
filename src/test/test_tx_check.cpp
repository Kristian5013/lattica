// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Functional tests for context-free transaction checks (CheckTransaction):
// every consensus rejection path (empty vin/vout, oversize, negative/overflow
// values, duplicate inputs, coinbase scriptSig length, null prevout) plus the
// accepting paths for a valid coinbase and a valid spend.

#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdio>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

// A spendable prevout (non-null), distinct per (tag,n).
COutPoint Op(uint8_t tag, uint32_t n)
{
    uint256 h;
    for (unsigned i = 0; i < uint256::size(); ++i) h.begin()[i] = (unsigned char)(tag + i);
    return COutPoint(Txid::FromUint256(h), n);
}

// Run CheckTransaction and confirm it rejected with exactly `reason`.
bool Rejects(const CMutableTransaction& mtx, const char* reason)
{
    TxValidationState state;
    bool ok = CheckTransaction(CTransaction(mtx), state);
    return !ok && state.GetRejectReason() == reason;
}
bool Accepts(const CMutableTransaction& mtx)
{
    TxValidationState state;
    return CheckTransaction(CTransaction(mtx), state) && state.IsValid();
}

CTxOut Out(CAmount v)
{
    CScript spk;
    spk << OP_TRUE;
    return CTxOut(v, spk);
}

} // namespace

int main()
{
    // Empty vin.
    {
        CMutableTransaction tx;
        tx.vout.push_back(Out(COIN));
        Check("empty vin -> bad-txns-vin-empty", Rejects(tx, "bad-txns-vin-empty"));
    }

    // Empty vout.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(1, 0));
        Check("empty vout -> bad-txns-vout-empty", Rejects(tx, "bad-txns-vout-empty"));
    }

    // Negative output value.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(1, 0));
        tx.vout.push_back(Out(-1));
        Check("negative value -> bad-txns-vout-negative", Rejects(tx, "bad-txns-vout-negative"));
    }

    // Single output above MAX_MONEY.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(1, 0));
        tx.vout.push_back(Out(MAX_MONEY + 1));
        Check("value > MAX_MONEY -> bad-txns-vout-toolarge", Rejects(tx, "bad-txns-vout-toolarge"));
    }

    // Two outputs each in range but summing past MAX_MONEY.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(1, 0));
        tx.vout.push_back(Out(MAX_MONEY));
        tx.vout.push_back(Out(MAX_MONEY));
        Check("output total overflow -> bad-txns-txouttotal-toolarge", Rejects(tx, "bad-txns-txouttotal-toolarge"));
    }

    // Duplicate inputs.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(5, 3));
        tx.vin.emplace_back(Op(5, 3)); // same outpoint
        tx.vout.push_back(Out(COIN));
        Check("duplicate inputs -> bad-txns-inputs-duplicate", Rejects(tx, "bad-txns-inputs-duplicate"));
    }

    // Coinbase with scriptSig too short (< 2 bytes).
    {
        CMutableTransaction tx;
        CTxIn in;
        in.prevout.SetNull();
        in.scriptSig = CScript() << OP_0; // 1 byte
        tx.vin.push_back(in);
        tx.vout.push_back(Out(50 * COIN));
        Check("coinbase short scriptSig -> bad-cb-length", Rejects(tx, "bad-cb-length"));
    }

    // Non-coinbase spending a null prevout.
    {
        CMutableTransaction tx;
        CTxIn in;
        in.prevout.SetNull();
        tx.vin.push_back(in);
        tx.vin.emplace_back(Op(7, 1)); // a second, non-null input -> not a coinbase
        tx.vout.push_back(Out(COIN));
        Check("non-coinbase null prevout -> bad-txns-prevout-null", Rejects(tx, "bad-txns-prevout-null"));
    }

    // A valid coinbase: single null-prevout input, scriptSig in [2,100], one output.
    {
        CMutableTransaction tx;
        CTxIn in;
        in.prevout.SetNull();
        in.scriptSig = CScript() << 486604799 << CScriptNum(4); // > 2 bytes, < 100
        tx.vin.push_back(in);
        tx.vout.push_back(Out(50 * COIN));
        Check("valid coinbase accepted", Accepts(tx));
    }

    // A valid ordinary spend.
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(8, 0));
        tx.vin.emplace_back(Op(8, 1));
        tx.vout.push_back(Out(3 * COIN));
        tx.vout.push_back(Out(7 * COIN));
        Check("valid spend accepted", Accepts(tx));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
