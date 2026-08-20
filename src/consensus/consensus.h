// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_CONSENSUS_CONSENSUS_H
#define LATTICA_CONSENSUS_CONSENSUS_H

#include <cstdint>
#include <cstdlib>

// Lattica block-size economics: ML-DSA-44 signatures are ~35x larger than
// ECDSA (sig 2420 + pubkey 1312 vs ~72 + 33 bytes), so a Bitcoin-sized block
// would hold ~1/30th the payments. A 32 MB block restores Bitcoin-like payment
// throughput (~8.5-9k tx/block). Lattica gives no witness discount, so the
// weight model is simply vsize = serialized bytes (WITNESS_SCALE_FACTOR = 1)
// and MAX_BLOCK_WEIGHT == MAX_BLOCK_SERIALIZED_SIZE.

/** The maximum allowed size for a serialized block, in bytes (32 MB) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 32000000;
/** The maximum allowed weight for a block (network rule). With no witness
 *  discount the weight is the serialized size, so this equals
 *  MAX_BLOCK_SERIALIZED_SIZE. */
static const unsigned int MAX_BLOCK_WEIGHT = 32000000;
/** The maximum allowed number of signature check operations in a block
 *  (network rule). Scaled with the block size from Bitcoin's 80000 at 4 MB. */
static const int64_t MAX_BLOCK_SIGOPS_COST = 640000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

//! Lattica charges fees per serialized byte and gives the witness no discount,
//! so vsize = serialized bytes and the weight scale factor is 1.
static const int WITNESS_SCALE_FACTOR = 1;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
static constexpr int64_t MAX_TIMEWARP = 600;

#endif // LATTICA_CONSENSUS_CONSENSUS_H
