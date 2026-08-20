// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the transaction signer (sign.cpp): ProduceSignature/SignSignature
// solve a scriptPubKey from a FillableSigningProvider and assemble a satisfying
// scriptSig/scriptWitness — replacing the hand-built witness the validation tests
// used. The produced input is checked against the real consensus VerifyScript.
//
// Lattica reality (option A): an ML-DSA signature (2421 B) and public key (1312 B)
// both exceed MAX_SCRIPT_ELEMENT_SIZE (520), so legacy P2PK/P2PKH/multisig — which
// push them with an executed script — cannot verify; only witness-v0 paths, where
// they ride the witness stack (bound MAX_WITNESS_ITEM = 3600), are spendable. So
// P2WPKH and P2SH-P2WPKH sign and verify, while P2PKH signing does not complete.

#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <addresstype.h>
#include <consensus/amount.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>

#include <cstdio>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

const CAmount AMOUNT = 50'000;

CMutableTransaction MakeSpend()
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = AMOUNT;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

// Verify a signed input against its scriptPubKey with the real consensus checker.
bool ConsensusVerifies(const CScript& spk, const CMutableTransaction& tx)
{
    const MutableTransactionSignatureChecker checker(&tx, 0, AMOUNT, MissingDataBehavior::FAIL);
    ScriptError err = SCRIPT_ERR_OK;
    return VerifyScript(tx.vin[0].scriptSig, spk, &tx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err);
}
} // namespace

int main()
{
    const CKey key = GenerateRandomKey();
    const CPubKey pub = key.GetPubKey();

    FillableSigningProvider ks;
    ks.AddKey(key);

    // P2WPKH: signs, completes, and the produced witness verifies under consensus.
    const CScript p2wpkh = GetScriptForDestination(WitnessV0KeyHash(pub));
    {
        CMutableTransaction tx = MakeSpend();
        SignatureData sd;
        const bool ok = SignSignature(ks, p2wpkh, tx, 0, AMOUNT, SIGHASH_ALL, sd);
        Check("P2WPKH SignSignature completes", ok && sd.complete);
        Check("P2WPKH witness is set, scriptSig empty", sd.witness && tx.vin[0].scriptSig.empty() && tx.vin[0].scriptWitness.stack.size() == 2);
        Check("P2WPKH verifies under consensus VerifyScript", ConsensusVerifies(p2wpkh, tx));
        // Tampering the signature breaks verification.
        CMutableTransaction bad = tx;
        bad.vin[0].scriptWitness.stack[0][bad.vin[0].scriptWitness.stack[0].size() / 2] ^= 0xff;
        Check("P2WPKH with tampered signature fails VerifyScript", !ConsensusVerifies(p2wpkh, bad));
    }

    // P2SH-P2WPKH: the redeemScript (small) is the P2WPKH program; the big pubkey
    // rides the witness. Signs, completes, verifies.
    const CScript redeem = GetScriptForDestination(WitnessV0KeyHash(pub));
    const CScript p2sh = GetScriptForDestination(ScriptHash(redeem));
    {
        ks.AddCScript(redeem); // also learned implicitly, but be explicit
        CMutableTransaction tx = MakeSpend();
        SignatureData sd;
        const bool ok = SignSignature(ks, p2sh, tx, 0, AMOUNT, SIGHASH_ALL, sd);
        Check("P2SH-P2WPKH SignSignature completes", ok && sd.complete);
        Check("P2SH-P2WPKH scriptSig pushes the redeemScript, witness carries the key",
              !tx.vin[0].scriptSig.empty() && tx.vin[0].scriptWitness.stack.size() == 2);
        Check("P2SH-P2WPKH verifies under consensus VerifyScript", ConsensusVerifies(p2sh, tx));
    }

    // Legacy P2PKH: the signer cannot complete it, because the 2421-byte sig and
    // 1312-byte pubkey would be pushed by the scriptSig and exceed the 520-byte
    // element limit (ML-DSA is witness-only).
    const CScript p2pkh = GetScriptForDestination(PKHash(pub));
    {
        CMutableTransaction tx = MakeSpend();
        SignatureData sd;
        const bool ok = SignSignature(ks, p2pkh, tx, 0, AMOUNT, SIGHASH_ALL, sd);
        Check("legacy P2PKH does not complete (witness-only)", !ok && !sd.complete);
    }

    // Signing with a keystore that lacks the key fails.
    {
        FillableSigningProvider empty;
        CMutableTransaction tx = MakeSpend();
        SignatureData sd;
        const bool ok = SignSignature(empty, p2wpkh, tx, 0, AMOUNT, SIGHASH_ALL, sd);
        Check("P2WPKH without the key does not complete", !ok && !sd.complete);
    }

    // IsSolvable: true when the store has the key/redeem, false otherwise.
    {
        FillableSigningProvider empty;
        Check("IsSolvable(P2WPKH) with key", IsSolvable(ks, p2wpkh));
        Check("IsSolvable(P2WPKH) without key is false", !IsSolvable(empty, p2wpkh));
        Check("IsSolvable(P2SH-P2WPKH) with redeem", IsSolvable(ks, p2sh));
        // Legacy P2PKH is not solvable (oversized pushes).
        Check("IsSolvable(P2PKH) is false (witness-only)", !IsSolvable(ks, p2pkh));
    }

    // IsSegWitOutput.
    {
        Check("IsSegWitOutput(P2WPKH) is true", IsSegWitOutput(ks, p2wpkh));
        Check("IsSegWitOutput(P2SH-P2WPKH) is true", IsSegWitOutput(ks, p2sh));
        Check("IsSegWitOutput(P2PKH) is false", !IsSegWitOutput(ks, p2pkh));
    }

    // DataFromTransaction re-extracts the signature data that ProduceSignature
    // wrote into an input. This is the round-trip combinerawtransaction relies
    // on to merge partial signatures from independently-signed transaction copies.
    {
        CMutableTransaction tx = MakeSpend();
        SignatureData sd;
        SignSignature(ks, p2wpkh, tx, 0, AMOUNT, SIGHASH_ALL, sd);
        const CTxOut txout{AMOUNT, p2wpkh};
        const SignatureData extracted = DataFromTransaction(tx, 0, txout);
        Check("DataFromTransaction marks a fully-signed P2WPKH input complete", extracted.complete);

        const CMutableTransaction unsigned_tx = MakeSpend();
        const SignatureData none = DataFromTransaction(unsigned_tx, 0, txout);
        Check("DataFromTransaction leaves an unsigned input incomplete", !none.complete);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
