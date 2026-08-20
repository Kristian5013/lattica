// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// primitives/transaction tests + txid cross-check CLI.
// Standalone for now (own main); folds into the test framework when it lands.
//
//   no args     run the built-in checks, exit non-zero on any failure
//   --txid      forward hex of the fixed test transaction's txid (no-witness)

#include <consensus/amount.h>
#include <crypto/hex_base.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <uint256.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

// A fixed transaction used both by the built-in checks and the --txid CLI.
CMutableTransaction MakeFixedTx()
{
    CMutableTransaction mtx;
    mtx.version = 1;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript();
    mtx.vin[0].nSequence = 0xffffffff;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 50 * COIN;
    mtx.vout[0].scriptPubKey = CScript() << OP_1;
    mtx.nLockTime = 0;
    return mtx;
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
    if (argc == 2 && std::strcmp(argv[1], "--txid") == 0) {
        std::printf("%s\n", FwdHex(CTransaction(MakeFixedTx()).GetHash().ToUint256()).c_str());
        return 0;
    }

    const CMutableTransaction mtx = MakeFixedTx();
    const CTransaction tx(mtx);

    // txid is deterministic.
    Check("txid deterministic", CTransaction(mtx).GetHash().ToUint256() == tx.GetHash().ToUint256());

    // No witness present -> HasWitness false, and wtxid == txid.
    Check("no witness", !tx.HasWitness());
    Check("wtxid == txid (no witness)", tx.GetWitnessHash().ToUint256() == tx.GetHash().ToUint256());

    // Output value sum.
    Check("GetValueOut == 50 LTA", tx.GetValueOut() == 50 * COIN);

    // COutPoint null handling.
    Check("COutPoint() null", COutPoint().IsNull());
    Check("COutPoint(h,0) not null", !COutPoint(Txid::FromUint256(uint256::ONE), 0).IsNull());

    // The SegWit property: adding witness changes wtxid but NOT txid.
    {
        CMutableTransaction mw = MakeFixedTx();
        mw.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>{0xaa, 0xbb});
        const CTransaction txw(mw);
        Check("has witness", txw.HasWitness());
        Check("witness keeps txid", txw.GetHash().ToUint256() == tx.GetHash().ToUint256());
        Check("witness changes wtxid", txw.GetWitnessHash().ToUint256() != txw.GetHash().ToUint256());
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
