// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

#include <memory>
#include <sstream>

uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}

uint256 CBlockHeader::GetPoWHash() const
{
    // NIST SHA3-256d (FIPS 202): one more SHA3-256 over the block hash. The block
    // hash stays a single SHA3-256 (like every txid and the Merkle root); only this
    // proof-of-work value uses the double — the analogue of Bitcoin's
    // double-SHA256.
    return Hash(GetHash());
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
