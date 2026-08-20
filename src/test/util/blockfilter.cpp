// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <test/util/blockfilter.h>

#include <chainparams.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <undo.h>
#include <validation.h>

using node::BlockManager;

bool ComputeFilter(BlockFilterType filter_type, const CBlockIndex& block_index, BlockFilter& filter, const BlockManager& blockman)
{
    LOCK(::cs_main);

    CBlock block;
    if (!blockman.ReadBlock(block, block_index)) {
        return false;
    }

    CBlockUndo block_undo;
    if (block_index.nHeight > 0 && !blockman.ReadBlockUndo(block_undo, block_index)) {
        return false;
    }

    filter = BlockFilter(filter_type, block, block_undo);
    return true;
}
