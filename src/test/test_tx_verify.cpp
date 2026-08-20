// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for contextual transaction checks (consensus/tx_verify): Consensus::
// CheckTxInputs (fee computation, value-in >= value-out, coinbase maturity,
// missing/spent inputs), GetTransactionSigOpCost, and IsFinalTx.

#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
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

COutPoint Op(uint8_t tag, uint32_t n)
{
    uint256 h;
    for (unsigned i = 0; i < uint256::size(); ++i) h.begin()[i] = (unsigned char)(tag + i);
    return COutPoint(Txid::FromUint256(h), n);
}

CScript P2Pk()
{
    CScript s;
    s << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG;
    return s;
}

} // namespace

int main()
{
    CCoinsView& empty = CoinsViewEmpty::Get();

    // ---- CheckTxInputs: a valid spend, fee = in - out ----
    {
        CCoinsViewCache cache(&empty, /*deterministic=*/true);
        const COutPoint a = Op(1, 0), b = Op(2, 0);
        cache.AddCoin(a, Coin(CTxOut(6 * COIN, P2Pk()), 10, /*coinbase=*/false), false);
        cache.AddCoin(b, Coin(CTxOut(4 * COIN, P2Pk()), 10, false), false);

        CMutableTransaction tx;
        tx.vin.emplace_back(a);
        tx.vin.emplace_back(b);
        tx.vout.push_back(CTxOut(9 * COIN, CScript() << OP_TRUE));

        TxValidationState state;
        CAmount fee = -1;
        bool ok = Consensus::CheckTxInputs(CTransaction(tx), state, cache, /*nSpendHeight=*/100, fee);
        Check("valid spend accepted", ok && state.IsValid());
        Check("fee == in - out == 1 COIN", fee == 1 * COIN);
    }

    // ---- in < out -> bad-txns-in-belowout ----
    {
        CCoinsViewCache cache(&empty, true);
        const COutPoint a = Op(3, 0);
        cache.AddCoin(a, Coin(CTxOut(1 * COIN, P2Pk()), 10, false), false);
        CMutableTransaction tx;
        tx.vin.emplace_back(a);
        tx.vout.push_back(CTxOut(2 * COIN, CScript() << OP_TRUE));
        TxValidationState state;
        CAmount fee = -1;
        bool ok = Consensus::CheckTxInputs(CTransaction(tx), state, cache, 100, fee);
        Check("in < out rejected (bad-txns-in-belowout)",
              !ok && state.GetRejectReason() == "bad-txns-in-belowout");
    }

    // ---- missing input -> TX_MISSING_INPUTS ----
    {
        CCoinsViewCache cache(&empty, true);
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(4, 0)); // never added
        tx.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
        TxValidationState state;
        CAmount fee = -1;
        bool ok = Consensus::CheckTxInputs(CTransaction(tx), state, cache, 100, fee);
        Check("missing input rejected (TX_MISSING_INPUTS)",
              !ok && state.GetResult() == TxValidationResult::TX_MISSING_INPUTS);
    }

    // ---- coinbase maturity (COINBASE_MATURITY = 100) ----
    {
        CCoinsViewCache cache(&empty, true);
        const COutPoint cb = Op(5, 0);
        cache.AddCoin(cb, Coin(CTxOut(50 * COIN, P2Pk()), /*height=*/50, /*coinbase=*/true), false);
        CMutableTransaction tx;
        tx.vin.emplace_back(cb);
        tx.vout.push_back(CTxOut(49 * COIN, CScript() << OP_TRUE));

        // Spent at height 50 + 99 = 149 -> depth 99 < 100 -> premature.
        {
            TxValidationState state; CAmount fee = -1;
            bool ok = Consensus::CheckTxInputs(CTransaction(tx), state, cache, 149, fee);
            Check("immature coinbase rejected (TX_PREMATURE_SPEND)",
                  !ok && state.GetResult() == TxValidationResult::TX_PREMATURE_SPEND);
        }
        // Spent at height 150 -> depth 100 >= 100 -> ok.
        {
            TxValidationState state; CAmount fee = -1;
            bool ok = Consensus::CheckTxInputs(CTransaction(tx), state, cache, 150, fee);
            Check("mature coinbase accepted", ok && fee == 1 * COIN);
        }
    }

    // ---- GetTransactionSigOpCost ----
    {
        CCoinsViewCache cache(&empty, true);
        const COutPoint a = Op(6, 0);
        cache.AddCoin(a, Coin(CTxOut(COIN, P2Pk()), 10, false), false);
        CMutableTransaction tx;
        tx.vin.emplace_back(a);
        // One output carrying a single CHECKSIG -> one legacy sigop.
        tx.vout.push_back(CTxOut(COIN, P2Pk()));
        const script_verify_flags flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        int64_t cost = GetTransactionSigOpCost(CTransaction(tx), cache, flags);
        // WITNESS_SCALE_FACTOR == 1, non-witness/non-P2SH spend: cost == legacy count == 1.
        Check("GetTransactionSigOpCost == 1 (single CHECKSIG output)", cost == 1);
    }

    // ---- IsFinalTx ----
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(Op(7, 0));
        tx.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));

        // nLockTime == 0 -> always final.
        tx.nLockTime = 0;
        Check("IsFinalTx: nLockTime 0 is final", IsFinalTx(CTransaction(tx), 100, 1'000'000));

        // Height-based locktime in the future, non-final sequence -> not final.
        tx.nLockTime = 200;
        tx.vin[0].nSequence = 0;
        Check("IsFinalTx: future height locktime not final", !IsFinalTx(CTransaction(tx), 100, 1'000'000));

        // Core semantics: final iff nLockTime < nBlockHeight, so still not final
        // at exactly the locktime height, and final one block later.
        Check("IsFinalTx: not final at exactly locktime height", !IsFinalTx(CTransaction(tx), 200, 1'000'000));
        Check("IsFinalTx: final one block past locktime", IsFinalTx(CTransaction(tx), 201, 1'000'000));

        // Future locktime but SEQUENCE_FINAL on all inputs -> final (locktime ignored).
        tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        Check("IsFinalTx: SEQUENCE_FINAL overrides locktime", IsFinalTx(CTransaction(tx), 100, 1'000'000));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
