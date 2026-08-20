// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// consensus/merkle.h ComputeMerkleRoot tests + cross-check CLI.
// Standalone for now (own main); folds into the test framework when it lands.
//
//   no args        run the built-in checks, exit non-zero on any failure
//   --root <hex>   concatenated 32-byte leaves (N*64 hex chars); prints the
//                  forward hex of the Merkle root (== python SHA3-256 reference)

#include <consensus/merkle.h>
#include <crypto/hex_base.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

uint256 Leaf(const std::string& hex64)
{
    auto b = ParseHex<unsigned char>(hex64);
    return uint256{std::span<const unsigned char>(b)};
}

std::string FwdHex(const uint256& h)
{
    return HexStr(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(h.data()), h.size()));
}

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 3 && std::strcmp(argv[1], "--root") == 0) {
        const std::string hex = argv[2];
        std::vector<uint256> leaves;
        for (size_t i = 0; i + 64 <= hex.size(); i += 64) {
            leaves.push_back(Leaf(hex.substr(i, 64)));
        }
        std::printf("%s\n", FwdHex(ComputeMerkleRoot(std::move(leaves))).c_str());
        return 0;
    }

    const uint256 a = Leaf(std::string(64, '1'));
    const uint256 b = Leaf(std::string(64, '2'));
    const uint256 c = Leaf(std::string(64, '3'));

    // Empty -> all-zero root.
    Check("empty -> zero", ComputeMerkleRoot({}).IsNull());

    // One leaf -> that leaf.
    Check("single leaf", ComputeMerkleRoot({a}) == a);

    // Two leaves -> SHA3-256(a || b).
    Check("two leaves", ComputeMerkleRoot({a, b}) == Hash(a, b));

    // Three leaves -> last is duplicated: root = H(H(a,b), H(c,c)).
    Check("three leaves (dup last)",
          ComputeMerkleRoot({a, b, c}) == Hash(Hash(a, b), Hash(c, c)));

    // Four leaves -> balanced.
    {
        const uint256 d = Leaf(std::string(64, '4'));
        Check("four leaves", ComputeMerkleRoot({a, b, c, d}) == Hash(Hash(a, b), Hash(c, d)));
    }

    // CVE-2012-2459 mutation detection.
    {
        bool m = false;
        ComputeMerkleRoot({a, a}, &m);
        Check("mutation detected on [a,a]", m);
        m = false;
        ComputeMerkleRoot({a, b}, &m);
        Check("no mutation on [a,b]", !m);
    }

    // Block-level Merkle roots over real transactions.
    {
        CBlock block;
        std::vector<uint256> txids;
        for (uint32_t i = 0; i < 5; ++i) {
            CMutableTransaction mtx;
            mtx.version = 1;
            mtx.nLockTime = i; // make each transaction distinct
            CTransactionRef ref = MakeTransactionRef(std::move(mtx));
            txids.push_back(ref->GetHash().ToUint256());
            block.vtx.push_back(ref);
        }
        Check("BlockMerkleRoot == ComputeMerkleRoot(txids)",
              BlockMerkleRoot(block) == ComputeMerkleRoot(txids));

        // A merkle path folds back to the root for every transaction position.
        {
            const uint256 root = BlockMerkleRoot(block);
            bool path_ok = true;
            for (uint32_t p = 0; p < block.vtx.size(); ++p) {
                const std::vector<uint256> branch = TransactionMerklePath(block, p);
                uint256 h = block.vtx[p]->GetHash().ToUint256();
                uint32_t pos = p;
                for (const uint256& sib : branch) {
                    h = (pos & 1) ? Hash(sib, h) : Hash(h, sib);
                    pos >>= 1;
                }
                if (h != root) path_ok = false;
            }
            Check("merkle path reconstructs root", path_ok);
        }

        CBlock one;
        CMutableTransaction cb;
        cb.version = 1;
        one.vtx.push_back(MakeTransactionRef(std::move(cb)));
        Check("single-tx block root == its txid",
              BlockMerkleRoot(one) == one.vtx[0]->GetHash().ToUint256());
        // The coinbase's witness hash counts as 0, so a coinbase-only block has
        // a zero witness merkle root.
        Check("coinbase-only witness root is zero", BlockWitnessMerkleRoot(one).IsNull());
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
