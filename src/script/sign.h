// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Transaction signing, ported from Bitcoin Core's script/sign.h. Lattica option
// A is witness-only ML-DSA with no Taproot, so Core's Schnorr/Taproot and MuSig2
// signing paths (CreateSchnorrSig, taproot_*, musig2_*) are dropped, along with
// the descriptor/PSBT-only machinery (the SHA256/HASH160 hash-preimage maps, the
// partial-signature extractor used by SignTransaction/DataFromTransaction). What
// remains is the core signer the wallet drives: a MutableTransactionSignature
// creator that ML-DSA-signs the BIP-143 sighash, and ProduceSignature, which
// solves a scriptPubKey and assembles the scriptSig / scriptWitness — so callers
// no longer hand-build a witness as the validation tests had to.

#ifndef LATTICA_SCRIPT_SIGN_H
#define LATTICA_SCRIPT_SIGN_H

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <uint256.h>
#include <util/translation.h>

#include <map>
#include <utility>
#include <vector>

class CKey;
class CKeyID;

/** A signature together with the public key that produced it. */
using SigPair = std::pair<CPubKey, std::vector<unsigned char>>;

/** Mutable signature data, accumulated while solving and assembling an input. */
struct SignatureData {
    bool complete = false;             //!< Stores whether the scriptSig and scriptWitness are complete.
    bool witness = false;              //!< Stores whether the input this SigData corresponds to is a witness input.
    CScript scriptSig;                 //!< The scriptSig of an input.
    CScript redeem_script;             //!< The redeemScript (if any) for the input.
    CScript witness_script;            //!< The witnessScript (if any) for the input.
    CScriptWitness scriptWitness;      //!< The scriptWitness of an input.
    std::map<CKeyID, SigPair> signatures;     //!< BIP 174 style partial signatures for the input.
    std::map<CKeyID, CPubKey> misc_pubkeys;   //!< Public keys involved in this input.

    SignatureData() = default;
    explicit SignatureData(const CScript& script) : scriptSig(script) {}
    void MergeSignatureData(SignatureData sigdata);
};

/** An interface for producing a script signature for one transaction input. */
class BaseSignatureCreator
{
public:
    virtual ~BaseSignatureCreator() = default;
    virtual const BaseSignatureChecker& Checker() const = 0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const = 0;
};

/** A signature creator for transactions. */
class MutableTransactionSignatureCreator : public BaseSignatureCreator
{
    const CMutableTransaction& m_txto;
    unsigned int nIn;
    int nHashType;
    CAmount amount;
    const MutableTransactionSignatureChecker checker;
    const PrecomputedTransactionData* m_txdata;

public:
    MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, int hash_type);
    MutableTransactionSignatureCreator(const CMutableTransaction& tx, unsigned int input_idx, const CAmount& amount, const PrecomputedTransactionData* txdata, int hash_type);
    const BaseSignatureChecker& Checker() const override { return checker; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override;
};

/** A signature creator that just produces 0-length signatures (for size estimation/solvability). */
extern const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR;

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey, SignatureData& sigdata);

/** Extract signature data from a (partially) signed input, recovering the
 *  partial signatures, redeem/witness scripts, and pubkeys it carries. */
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout);

/** Sign every input of mtx that `coins` and `keystore` can satisfy (combining any
 *  signatures already present), recording per-input failures in input_errors.
 *  Returns true iff all inputs were signed. */
bool SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, int nHashType, std::map<int, bilingual_str>& input_errors);

/** Produce a satisfying script (scriptSig or scriptWitness) for the given input,
 *  writing it back into txTo's input. */
bool SignSignature(const SigningProvider& provider, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType, SignatureData& sig_data);
bool SignSignature(const SigningProvider& provider, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType, SignatureData& sig_data);

/** Apply a SignatureData to a CTxIn (its scriptSig and scriptWitness). */
void UpdateInput(CTxIn& input, const SignatureData& data);

/** Determine whether a script (or, for P2SH, its known redeemScript) is a SegWit output. */
bool IsSegWitOutput(const SigningProvider& provider, const CScript& script);

#endif // LATTICA_SCRIPT_SIGN_H
