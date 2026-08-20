// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Script interpreter interface, adapted from Bitcoin Core's script/interpreter.h
// to Lattica's design (option A): witness-only signing with ML-DSA, a SHA3-256
// BIP-143-style sighash, and no Taproot/Schnorr/ECDSA-DER machinery. SigVersion is
// just BASE (bare / P2SH redeemscript) and WITNESS_V0 (P2WPKH-/P2WSH-analog with
// ML-DSA). The signature checker exposes a single CheckSig (ML-DSA), not the
// ECDSA/Schnorr pair. Large ML-DSA sig/pubkey ride in the witness (MAX_WITNESS_ITEM).

#ifndef LATTICA_SCRIPT_INTERPRETER_H
#define LATTICA_SCRIPT_INTERPRETER_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/verify_flags.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

class CPubKey;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,

    SIGHASH_OUTPUT_MASK = 3,
    SIGHASH_INPUT_MASK = 0x80,
};

/** Script verification flags.
 *
 *  All flags are intended to be soft forks: the set of acceptable scripts under
 *  flags (A | B) is a subset of the acceptable scripts under flag (A).
 *
 *  Lattica omits the ECDSA/DER-encoding and Taproot flags (witness-only ML-DSA);
 *  the remaining flags govern P2SH, witness, and the BIP62 malleability rules that
 *  still apply.
 */
static constexpr script_verify_flags SCRIPT_VERIFY_NONE{0};

enum class script_verify_flag_name : uint8_t {
    // Evaluate P2SH subscripts (BIP16).
    SCRIPT_VERIFY_P2SH,
    // Using a non-push operator in the scriptSig causes script failure (BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY,
    // Require minimal encodings for all push operations and number interpretations (BIP62 rules 3/4).
    SCRIPT_VERIFY_MINIMALDATA,
    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY,
    // Discourage use of NOPs reserved for upgrades (NOP1-10).
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
    // Require that only a single stack element remains after evaluation (BIP62 rule 6).
    SCRIPT_VERIFY_CLEANSTACK,
    // Verify CHECKLOCKTIMEVERIFY (BIP65).
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
    // Support CHECKSEQUENCEVERIFY opcode (BIP112).
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
    // Support segregated witness.
    SCRIPT_VERIFY_WITNESS,
    // Making v1-v16 witness program non-standard.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    // Segwit script only: require the argument of OP_IF/NOTIF to be exactly 0x01 or empty.
    SCRIPT_VERIFY_MINIMALIF,
    // Signature(s) must be empty vector if a CHECK(MULTI)SIG operation failed.
    SCRIPT_VERIFY_NULLFAIL,
    // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts.
    SCRIPT_VERIFY_CONST_SCRIPTCODE,

    // Constant to point past the highest flag in use. Add new flags above this line.
    SCRIPT_VERIFY_END_MARKER
};
using enum script_verify_flag_name;

static constexpr int MAX_SCRIPT_VERIFY_FLAGS_BITS = static_cast<int>(SCRIPT_VERIFY_END_MARKER);
static_assert(0 < MAX_SCRIPT_VERIFY_FLAGS_BITS && MAX_SCRIPT_VERIFY_FLAGS_BITS <= 63);
static constexpr script_verify_flags::value_type MAX_SCRIPT_VERIFY_FLAGS = ((script_verify_flags::value_type{1} << MAX_SCRIPT_VERIFY_FLAGS_BITS) - 1);

/** Precomputed transaction data for the BIP-143-style (witness) sighash, hashed
 *  with SHA3-256. */
struct PrecomputedTransactionData
{
    uint256 hashPrevouts, hashSequence, hashOutputs;
    //! Whether the 3 fields above are initialized.
    bool m_bip143_ready = false;

    std::vector<CTxOut> m_spent_outputs;
    //! Whether m_spent_outputs is initialized.
    bool m_spent_outputs_ready = false;

    PrecomputedTransactionData() = default;

    template <class T>
    void Init(const T& tx, std::vector<CTxOut>&& spent_outputs, bool force = false);

    template <class T>
    explicit PrecomputedTransactionData(const T& tx);
};

enum class SigVersion
{
    BASE = 0,       //!< Bare scripts and BIP16 P2SH-wrapped redeemscripts
    WITNESS_V0 = 1, //!< Witness v0 (P2WPKH and P2WSH analogs, ML-DSA)
};

struct ScriptExecutionData
{
    //! Whether m_codeseparator_pos is initialized.
    bool m_codeseparator_pos_init = false;
    //! Opcode position of the last executed OP_CODESEPARATOR (or 0xFFFFFFFF if none executed).
    uint32_t m_codeseparator_pos = 0xFFFFFFFFUL;
};

/** Witness program sizes. */
static constexpr size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;
static constexpr size_t WITNESS_V0_KEYHASH_SIZE = 20;
/** Maximum size of a single witness stack item. Sized to hold an ML-DSA-44 public
 *  key (1312 B) or signature (2420 B); Lattica-specific (Core's is 80 B). */
static constexpr size_t MAX_WITNESS_ITEM = 3600;

template <class T>
uint256 SignatureHash(const CScript& scriptCode, const T& txTo, unsigned int nIn, int32_t nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache = nullptr);

class BaseSignatureChecker
{
public:
    /** Verify a signature over the transaction. `sig` carries the ML-DSA signature
     *  with a trailing sighash-type byte; `pubkey` is the ML-DSA public key. */
    virtual bool CheckSig(const std::vector<unsigned char>& /*sig*/, const std::vector<unsigned char>& /*pubkey*/, const CScript& /*scriptCode*/, SigVersion /*sigversion*/) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& /*nLockTime*/) const
    {
        return false;
    }

    virtual bool CheckSequence(const CScriptNum& /*nSequence*/) const
    {
        return false;
    }

    virtual ~BaseSignatureChecker() = default;
};

/** What a *TransactionSignatureChecker should do when transaction data is missing. */
enum class MissingDataBehavior
{
    ASSERT_FAIL, //!< Abort execution through assertion failure (for consensus code)
    FAIL,        //!< Just act as if the signature was invalid
};

template <class T>
class GenericTransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const T* txTo;
    const MissingDataBehavior m_mdb;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData* txdata;

protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn, MissingDataBehavior mdb) : txTo(txToIn), m_mdb(mdb), nIn(nInIn), amount(amountIn), txdata(nullptr) {}
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn, const PrecomputedTransactionData& txdataIn, MissingDataBehavior mdb) : txTo(txToIn), m_mdb(mdb), nIn(nInIn), amount(amountIn), txdata(&txdataIn) {}
    bool CheckSig(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey, const CScript& scriptCode, SigVersion sigversion) const override;
    bool CheckLockTime(const CScriptNum& nLockTime) const override;
    bool CheckSequence(const CScriptNum& nSequence) const override;
};

using TransactionSignatureChecker = GenericTransactionSignatureChecker<CTransaction>;
using MutableTransactionSignatureChecker = GenericTransactionSignatureChecker<CMutableTransaction>;

class DeferringSignatureChecker : public BaseSignatureChecker
{
protected:
    const BaseSignatureChecker& m_checker;

public:
    DeferringSignatureChecker(const BaseSignatureChecker& checker) : m_checker(checker) {}

    bool CheckSig(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& pubkey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        return m_checker.CheckSig(sig, pubkey, scriptCode, sigversion);
    }
    bool CheckLockTime(const CScriptNum& nLockTime) const override
    {
        return m_checker.CheckLockTime(nLockTime);
    }
    bool CheckSequence(const CScriptNum& nSequence) const override
    {
        return m_checker.CheckSequence(nSequence);
    }
};

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, script_verify_flags flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* error = nullptr);
bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, script_verify_flags flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* error = nullptr);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, script_verify_flags flags, const BaseSignatureChecker& checker, ScriptError* serror = nullptr);

int FindAndDelete(CScript& script, const CScript& b);

/** Count the sigops for the witness/P2SH input being spent, mirroring Core's
 *  consensus accounting (WITNESS_SCALE_FACTOR-weighted at the call site). */
size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness& witness, script_verify_flags flags);

const std::map<std::string, script_verify_flag_name>& ScriptFlagNamesToEnum();
std::vector<std::string> GetScriptFlagNames(script_verify_flags flags);

#endif  // LATTICA_SCRIPT_INTERPRETER_H
