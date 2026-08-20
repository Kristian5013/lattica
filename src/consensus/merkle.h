// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Lattica computes Merkle roots with SHA3-256 (via Hash()), not Bitcoin's
// double SHA-256. The tree shape and the CVE-2012-2459 duplicate guard are
// identical to Core; only the per-pair hash differs.

#ifndef LATTICA_CONSENSUS_MERKLE_H
#define LATTICA_CONSENSUS_MERKLE_H

#include <vector>

#include <primitives/block.h>
#include <uint256.h>

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated = nullptr);

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockMerkleRoot(const CBlock& block, bool* mutated = nullptr);

/*
 * Compute the Merkle root of the witness transactions in a block.
 */
uint256 BlockWitnessMerkleRoot(const CBlock& block);

/**
 * Compute merkle path to the specified transaction
 *
 * @param[in] block the block
 * @param[in] position transaction for which to calculate the merkle path (0 is the coinbase)
 *
 * @return merkle path ordered from the deepest
 */
std::vector<uint256> TransactionMerklePath(const CBlock& block, uint32_t position);

#endif // LATTICA_CONSENSUS_MERKLE_H
