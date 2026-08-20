// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_POLICY_POLICY_H
#define LATTICA_POLICY_POLICY_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <util/feefrac.h>

#include <cstdint>
#include <string>

class CCoinsViewCache;
class CFeeRate;
class CScript;

/** Default for -blockmaxweight, which controls the range of block weights the mining code will create **/
static constexpr unsigned int DEFAULT_BLOCK_MAX_WEIGHT{MAX_BLOCK_WEIGHT};
/** Default for -blockreservedweight **/
static constexpr unsigned int DEFAULT_BLOCK_RESERVED_WEIGHT{8000};
/** Default sigops cost to reserve for coinbase transaction outputs when creating block templates. */
static constexpr unsigned int DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS{400};
/** This accounts for the block header, var_int encoding of the transaction count and a minimally viable
 * coinbase transaction. It adds an additional safety margin, because even with a thorough understanding
 * of block serialization, it's easy to make a costly mistake when trying to squeeze every last byte.
 * Setting a lower value is prevented at startup. */
static constexpr unsigned int MINIMUM_BLOCK_RESERVED_WEIGHT{2000};
/** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code **/
static constexpr unsigned int DEFAULT_BLOCK_MIN_TX_FEE{1};
/** The maximum weight for transactions we're willing to relay/mine */
static constexpr int32_t MAX_STANDARD_TX_WEIGHT{400000};
/** The minimum non-witness size for transactions we're willing to relay/mine: one larger than 64  */
static constexpr unsigned int MIN_STANDARD_TX_NONWITNESS_SIZE{65};
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static constexpr unsigned int MAX_P2SH_SIGOPS{15};
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static constexpr unsigned int MAX_STANDARD_TX_SIGOPS_COST{MAX_BLOCK_SIGOPS_COST/5};
/** The maximum number of potentially executed legacy signature operations in a single standard tx */
static constexpr unsigned int MAX_TX_LEGACY_SIGOPS{2'500};
/** Default for -incrementalrelayfee, which sets the minimum feerate increase for mempool limiting or replacement **/
static constexpr unsigned int DEFAULT_INCREMENTAL_RELAY_FEE{100};
/** Default for -bytespersigop */
static constexpr unsigned int DEFAULT_BYTES_PER_SIGOP{20};
/** Default for -permitbaremultisig */
static constexpr bool DEFAULT_PERMIT_BAREMULTISIG{true};
/** The maximum number of witness stack items in a standard P2WSH script */
static constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS{100};
/** The maximum size in bytes of each witness stack item in a standard P2WSH script.
 *  Lattica: raised from Core's 80 to MAX_WITNESS_ITEM so an ML-DSA-44 public key
 *  (1312 B) / signature (2420 B) is relayable as a standard witness item. */
static constexpr unsigned int MAX_STANDARD_P2WSH_STACK_ITEM_SIZE{MAX_WITNESS_ITEM};
/** The maximum size in bytes of a standard witnessScript.
 *  Lattica: raised from Core's 3600 so that multi-key ML-DSA scripts relay. A
 *  serialized ML-DSA-44 pubkey costs ~1316 B in-script (PUSHDATA2 + 1313 B), so a
 *  3-key HTLC (~4100 B) or an n-of-m funding/multisig with several keys would be
 *  non-standard under 3600. 7000 fits ~5 in-script keys while staying well below
 *  the consensus MAX_SCRIPT_SIZE (10000) — relay stays a strict subset of what a
 *  block may contain, so raising it is policy-only (no consensus fork). */
static constexpr unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE{7000};
/** The maximum size of a standard ScriptSig */
static constexpr unsigned int MAX_STANDARD_SCRIPTSIG_SIZE{1650};
/** Min feerate for defining dust.
 * Changing the dust limit changes which transactions are
 * standard and should be done with care and ideally rarely. It makes sense to
 * only increase the dust limit after prior releases were already not creating
 * outputs below the new threshold */
static constexpr unsigned int DUST_RELAY_TX_FEE{3000};
/** Default for -minrelaytxfee, minimum relay fee for transactions */
static constexpr unsigned int DEFAULT_MIN_RELAY_TX_FEE{100};
/** Maximum number of transactions per cluster (default) */
static constexpr unsigned int DEFAULT_CLUSTER_LIMIT{64};
/** Maximum size of cluster in virtual kilobytes.
 *  Lattica: Core uses 101 with WITNESS_SCALE_FACTOR=4 (cluster holds 404000
 *  weight). With our WITNESS_SCALE_FACTOR=1 (vsize=bytes) the cluster must hold
 *  the same 404000 bytes a max package weighs, so this is scaled up 4x to 404
 *  (keeps the packages.h invariant MAX_PACKAGE_WEIGHT <= KVB * SCALE * 1000). */
static constexpr unsigned int DEFAULT_CLUSTER_SIZE_LIMIT_KVB{404};
/** Default for -limitancestorcount, max number of in-mempool ancestors */
static constexpr unsigned int DEFAULT_ANCESTOR_LIMIT{25};
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static constexpr unsigned int DEFAULT_DESCENDANT_LIMIT{25};
/** Default for -datacarrier */
static const bool DEFAULT_ACCEPT_DATACARRIER = true;
/**
 * Default setting for -datacarriersize in vbytes.
 */
static const unsigned int MAX_OP_RETURN_RELAY = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR;
/**
 * An extra transaction can be added to a package, as long as it only has one
 * ancestor and is no larger than this. Not really any reason to make this
 * configurable as it doesn't materially change DoS parameters.
 */
static constexpr unsigned int EXTRA_DESCENDANT_TX_SIZE_LIMIT{10000};

/**
 * Maximum number of ephemeral dust outputs allowed.
 */
static constexpr unsigned int MAX_DUST_OUTPUTS_PER_TX{1};

/**
 * Mandatory script verification flags that all new transactions must comply with for
 * them to be valid.
 *
 * Note that this does not affect consensus validity; see GetBlockScriptFlags()
 * for that.
 *
 * Lattica (option A): no DERSIG (ML-DSA, not ECDSA) and no Taproot.
 */
static constexpr script_verify_flags MANDATORY_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH |
                                                             SCRIPT_VERIFY_NULLDUMMY |
                                                             SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                             SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                             SCRIPT_VERIFY_WITNESS};

/**
 * Standard script verification flags that standard transactions will comply
 * with. However we do not ban/disconnect nodes that forward txs violating
 * the additional (non-mandatory) rules here, to improve forwards and
 * backwards compatibility.
 *
 * Lattica (option A): the secp256k1/Taproot-only flags (STRICTENC, LOW_S,
 * WITNESS_PUBKEYTYPE, DISCOURAGE_UPGRADABLE_TAPROOT_VERSION/OP_SUCCESS/
 * PUBKEYTYPE) do not exist and are omitted.
 */
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS{MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                             SCRIPT_VERIFY_MINIMALDATA |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                             SCRIPT_VERIFY_CLEANSTACK |
                                                             SCRIPT_VERIFY_MINIMALIF |
                                                             SCRIPT_VERIFY_NULLFAIL |
                                                             SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
                                                             SCRIPT_VERIFY_CONST_SCRIPTCODE};

/** For convenience, standard but not mandatory verify flags. */
static constexpr script_verify_flags STANDARD_NOT_MANDATORY_VERIFY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS};

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static constexpr unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS{LOCKTIME_VERIFY_SEQUENCE};

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsStandard(const CScript& scriptPubKey, TxoutType& whichType);

/** Get the vout index numbers of all dust outputs */
std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate);

// Changing the default transaction version requires a two step process: first
// adapting relay policy by bumping TX_MAX_STANDARD_VERSION, and then later
// allowing the new transaction version in the wallet/RPC.
static constexpr decltype(CTransaction::version) TX_MIN_STANDARD_VERSION{1};
static constexpr decltype(CTransaction::version) TX_MAX_STANDARD_VERSION{3};

/**
* Check for standard transaction types
* @return True if all outputs (scriptPubKeys) use only standard transaction forms
*/
bool IsStandardTx(const CTransaction& tx, const std::optional<unsigned>& max_datacarrier_bytes, bool permit_bare_multisig, const CFeeRate& dust_relay_fee, std::string& reason);
/**
 * Check for standard transaction types
 * @param[in] mapInputs       Map of previous transactions that have outputs we're spending
 * @returns valid TxValidationState if all inputs (scriptSigs) use only standard transaction forms else returns
 * invalid TxValidationState which states why the first invalid input is not standard
 */
TxValidationState ValidateInputsStandardness(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
* Check if the transaction is over standard P2WSH resources limit:
* MAX_STANDARD_P2WSH_SCRIPT_SIZE witnessScript size, MAX_STANDARD_P2WSH_STACK_ITEM_SIZE
* per witness stack element, MAX_STANDARD_P2WSH_STACK_ITEMS witness stack elements.
*/
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
/**
 * Check whether this transaction spends any witness program but P2A, including not-yet-defined ones.
 * May return `false` early for consensus-invalid transactions.
 */
bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts);

/** Compute the virtual transaction size (weight reinterpreted as bytes). */
int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);
int64_t GetVirtualTransactionInputSize(const CTxIn& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop);

static inline int64_t GetVirtualTransactionSize(const CTransaction& tx)
{
    return GetVirtualTransactionSize(tx, 0, 0);
}

static inline int64_t GetVirtualTransactionInputSize(const CTxIn& tx)
{
    return GetVirtualTransactionInputSize(tx, 0, 0);
}

int64_t GetSigOpsAdjustedWeight(int64_t weight, int64_t sigop_cost, unsigned int bytes_per_sigop);

static inline FeePerVSize ToFeePerVSize(FeePerWeight feerate) { return {feerate.fee, (feerate.size + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR}; }

#endif // LATTICA_POLICY_POLICY_H
