// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// What coin selection budgets for a transaction, against what the signed
// transaction actually weighs.
//
// The wallet funds a transaction before it can sign one, so it adds up an
// estimate: a constant for the fixed parts of a transaction, the size of each
// output, and a per-input figure that the descriptor derives from the largest
// satisfaction its script can take. If that total ever comes out below the
// signed size, coin selection funds less than the transaction needs and
// CreateTransactionInternal rejects its own work as an internal bug -- which is
// exactly what every spend on this chain did, over a single byte.
//
// The byte is Bitcoin's witness discount. Its constant reads "4 nVersion, 4
// nLocktime, 1 input count, 1 witness overhead", and that last 1 is the segwit
// marker and flag: two weight units, half a vbyte, rounded up to one. A vbyte
// here is a byte -- WITNESS_SCALE_FACTOR is 1 -- so the two cost two, and the
// estimate was short by one on every transaction that spent a witness program.
//
// So the check below is the one that matters and it is an inequality: the
// estimate must never fall under the signed size. It is reported alongside the
// slack, because an estimate that is exact is what keeps fees honest, and a
// large slack would say something else had gone wrong.

#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <util/translation.h>
#include <wallet/spend.h>

#include <cstdio>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

int g_fail = 0;
bool Check(const std::string& name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name.c_str());
    if (!ok) ++g_fail;
    return ok;
}

constexpr CAmount AMOUNT = 50 * COIN;

//! The fixed overhead coin selection budgets, as wallet/spend.cpp counts it.
//! Kept here as the literal it is over there, so that changing one without the
//! other fails rather than silently under-funds.
constexpr int64_t TX_NOINPUTS_CONSTANT = 11;

struct Case {
    const char* name;
    CScript spk;
    FlatSigningProvider provider;
    //! Whether the satisfaction has one possible size. A lattice signature does;
    //! an ECDSA one is DER, whose length depends on the R and S that came out,
    //! so an estimate for it can only be an upper bound.
    bool fixed_size{false};
};

//! Spend `spk` to two outputs and sign it, returning the signed transaction.
bool SignSpend(const Case& c, const CScript& out_spk, CMutableTransaction& spend)
{
    CMutableTransaction credit;
    credit.vin.resize(1);
    credit.vin[0].prevout.SetNull();
    credit.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    credit.vout.resize(1);
    credit.vout[0].nValue = AMOUNT;
    credit.vout[0].scriptPubKey = c.spk;

    spend = CMutableTransaction{};
    spend.vin.resize(1);
    spend.vin[0].prevout.hash = CTransaction(credit).GetHash();
    spend.vin[0].prevout.n = 0;
    // Two outputs: what is being paid, and the change. This is the shape the
    // wallet's estimate is written for.
    spend.vout.resize(2);
    spend.vout[0].nValue = AMOUNT / 2;
    spend.vout[0].scriptPubKey = out_spk;
    spend.vout[1].nValue = AMOUNT / 2 - 10000;
    spend.vout[1].scriptPubKey = out_spk;

    SignatureData sigdata;
    MutableTransactionSignatureCreator creator(spend, 0, AMOUNT, SignOptions{});
    if (!ProduceSignature(c.provider, creator, c.spk, sigdata)) return false;
    UpdateInput(spend.vin[0], sigdata);
    return true;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};

    static_assert(WITNESS_SCALE_FACTOR == 1,
                  "the constant above is chosen for a chain with no witness discount; "
                  "restoring the discount means restoring Bitcoin's 10");

    const CKey secp = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CKey falcon = GenerateRandomKey(CKey::FALCON512_SIZE);
    const CKey mldsa = GenerateRandomKey(CKey::MLDSA44_SIZE);

    std::vector<Case> cases;

    // pkh: no witness at all, so no marker and no flag. The estimate should
    // stand clear of the signed size here rather than meet it.
    {
        Case c{"pkh", {}, {}};
        const CPubKey pub = secp.GetPubKey();
        c.spk = GetScriptForDestination(PKHash(pub));
        c.provider.keys[pub.GetID()] = secp;
        c.provider.pubkeys[pub.GetID()] = pub;
        cases.push_back(std::move(c));
    }
    // wpkh: witness v0, the case Bitcoin's constant was written for.
    {
        Case c{"wpkh", {}, {}};
        const CPubKey pub = secp.GetPubKey();
        c.spk = GetScriptForDestination(WitnessV0KeyHash(pub));
        c.provider.keys[pub.GetID()] = secp;
        c.provider.pubkeys[pub.GetID()] = pub;
        cases.push_back(std::move(c));
    }
    // sh(wpkh): a scriptSig and a witness together.
    {
        Case c{"sh(wpkh)", {}, {}};
        const CPubKey pub = secp.GetPubKey();
        const CScript redeem = GetScriptForDestination(WitnessV0KeyHash(pub));
        c.spk = GetScriptForDestination(ScriptHash(redeem));
        c.provider.keys[pub.GetID()] = secp;
        c.provider.pubkeys[pub.GetID()] = pub;
        c.provider.scripts[CScriptID(redeem)] = redeem;
        cases.push_back(std::move(c));
    }
    // The two witness v2 types: the ones whose spends the shortfall blocked.
    for (const auto& [name, key] : {std::pair{"pqpkh(Falcon-512)", falcon},
                                    std::pair{"pqpkh(ML-DSA-44)", mldsa}}) {
        Case c{name, {}, {}, /*fixed_size=*/true};
        const CPubKey pub = key.GetPubKey();
        c.spk = GetScriptForDestination(WitnessV2KeyHash(pub));
        c.provider.keys[pub.GetID()] = key;
        c.provider.pubkeys[pub.GetID()] = pub;
        cases.push_back(std::move(c));
    }

    // Pay to a witness v2 output, the default this wallet hands out.
    const CScript out_spk = GetScriptForDestination(WitnessV2KeyHash(mldsa.GetPubKey()));
    const int64_t out_size = ::GetSerializeSize(CTxOut(AMOUNT / 2, out_spk));

    for (const Case& c : cases) {
        const CTxOut txo(AMOUNT, c.spk);

        const int est_input = wallet::CalculateMaximumSignedInputSize(
            txo, COutPoint(), &c.provider, /*can_grind_r=*/false, /*coin_control=*/nullptr);
        if (!Check(std::string(c.name) + ": the input has an estimated size", est_input > 0)) continue;

        CMutableTransaction spend;
        if (!Check(std::string(c.name) + ": ...and a signature is produced for it", SignSpend(c, out_spk, spend))) continue;

        // What coin selection would have budgeted: the fixed overhead, the
        // output count, the two outputs, and the input.
        const int64_t estimated = TX_NOINPUTS_CONSTANT + GetSizeOfCompactSize(1) + 2 * out_size + est_input;
        const int64_t actual = GetVirtualTransactionSize(CTransaction(spend));
        const int64_t slack = estimated - actual;

        std::printf("       estimate %lld, signed %lld, slack %lld\n",
                    (long long)estimated, (long long)actual, (long long)slack);
        Check(std::string(c.name) + ": ...that the estimate covers", slack >= 0);

        // Where the satisfaction has one possible size, the estimate is not
        // merely an upper bound but the answer, and that is worth pinning: it
        // is what leaves the shortfall nowhere to hide. A byte of slack here
        // would mean the estimate had drifted from what signing produces.
        //
        // secp256k1 cannot be held to that. Its signature is DER, one or two
        // bytes shorter whenever R or S comes out short, so the estimate takes
        // the longest and the transaction usually comes in under. A legacy
        // input adds two bytes for a marker and flag its transaction has not
        // got, and one more for a witness stack count, both of which the
        // estimator counts on purpose rather than reason about a transaction it
        // has not finished building.
        if (c.fixed_size) {
            Check(std::string(c.name) + ": ...exactly, to the byte", slack == 0);
        } else {
            Check(std::string(c.name) + ": ...without drifting far above it", slack <= 4);
        }
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
