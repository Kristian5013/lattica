// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Multi-threaded genesis miner. Grinds nNonce for the genesis at a given compact
// nBits and timestamp until SHA3-256d of the 80-byte header is at or under the
// target, then prints nNonce / hashGenesisBlock for kernel/chainparams.cpp.
// Usage: mine_genesis <nBits_hex> <nTime> [start_nonce]
#include <arith_uint256.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <uint256.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <limits>
#include <thread>
#include <vector>

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Google Quantum AI 30/Mar/2026 ECDLP-256 in minutes on under half a million physical qubits";
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4)
                                       << std::vector<unsigned char>((const unsigned char*)pszTimestamp,
                                                                     (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime = nTime; genesis.nBits = nBits; genesis.nNonce = 0; genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

int main(int argc, char** argv)
{
    const uint32_t nBits = (argc >= 2) ? (uint32_t)strtoul(argv[1], nullptr, 16) : 0x1e02cbd3u;
    const uint32_t nTime = (argc >= 3) ? (uint32_t)strtoul(argv[2], nullptr, 10) : 1782086400u;
    const uint64_t start = (argc >= 4) ? strtoull(argv[3], nullptr, 10) : 0;

    // The genesis sits at minimum difficulty, so its target is the powLimit; mine
    // against the target that this nBits decodes to.
    Consensus::Params params{};
    {
        arith_uint256 bn; bn.SetCompact(nBits);
        params.powLimit = ArithToUint256(bn);
    }

    std::printf("nBits=%08x\n", nBits);
    std::printf("powLimit=%s\n", params.powLimit.ToString().c_str());

    const CBlock genesis = CreateGenesisBlock(nTime, nBits, 1, 50 * COIN);
    std::printf("nTime=%u merkle=%s\n", nTime, genesis.hashMerkleRoot.ToString().c_str());

    unsigned nthreads = std::thread::hardware_concurrency();
    if (nthreads == 0) nthreads = 4;
    std::printf("mining: SHA3-256d threads=%u\n", nthreads);
    std::fflush(stdout);

    std::atomic<bool> found{false};
    std::atomic<uint64_t> total{0};
    std::atomic<uint32_t> win_nonce{0};
    const std::clock_t t0 = std::clock();

    auto worker = [&](unsigned tid) {
        // Slice off just the header; GetPoWHash needs no transactions.
        CBlockHeader hdr = genesis;
        uint64_t local = 0;
        for (uint64_t i = start + tid; i <= std::numeric_limits<uint32_t>::max() && !found.load(std::memory_order_relaxed); i += nthreads) {
            hdr.nNonce = (uint32_t)i;
            ++local;
            if (CheckProofOfWorkImpl(hdr.GetPoWHash(), nBits, params)) {
                if (!found.exchange(true)) win_nonce.store((uint32_t)i);
                break;
            }
            if (tid == 0 && (local & 0x3ffff) == 0x3ffff) {
                const double secs = double(std::clock() - t0) / CLOCKS_PER_SEC / nthreads;
                std::printf("  ...~%llu hashes, %.0fs\n", (unsigned long long)(local * nthreads), secs);
                std::fflush(stdout);
            }
        }
        total += local;
    };

    std::vector<std::thread> pool;
    for (unsigned t = 0; t < nthreads; ++t) pool.emplace_back(worker, t);
    for (auto& th : pool) th.join();

    if (!found.load()) { std::printf("no solution in the 32-bit nonce range\n"); return 1; }

    CBlock win = genesis;
    win.nNonce = win_nonce.load();

    // Self-check single-threaded (detects any shared-state concurrency corruption).
    const bool valid = CheckProofOfWorkImpl(win.GetPoWHash(), nBits, params);
    std::printf("self-check: single_thread_valid=%d\n", valid ? 1 : 0);

    std::printf("FOUND nNonce=%u (~%llu hashes total)\n", win.nNonce, (unsigned long long)total.load());
    std::printf("nBits=%08x\n", nBits);
    std::printf("hashMerkleRoot=%s\n", win.hashMerkleRoot.ToString().c_str());
    std::printf("hashGenesisBlock=%s\n", win.GetHash().ToString().c_str());
    std::printf("powHash=%s\n", win.GetPoWHash().ToString().c_str());
    std::printf("powLimit=%s\n", params.powLimit.ToString().c_str());
    return 0;
}
