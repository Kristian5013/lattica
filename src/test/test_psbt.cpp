// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// PSBT over the three signature schemes.
//
// BIP174 does not describe a signature scheme; it describes places -- a spent
// output, a map of public key to partial signature, a witnessScript, a map of
// public key to key origin. All of them are scheme-neutral, so witness v2 needs
// no field type of its own: a key-hash spend fills witness_utxo, partial_sigs
// and hd_keypaths, and a script spend adds witness_script.
//
// What is not neutral is the length of a public key, and Core bounds it in two
// places by naming its own two: "SIZE or COMPRESSED_SIZE", 65 or 33. Here SIZE
// is the longest of three keys rather than the uncompressed form, so spelling it
// Core's way reads as "1312 or 33" and silently refuses every Falcon-512 key.
// The checks below round-trip a partial signature and a key origin for all three
// schemes, which is what catches that.

#include <consensus/amount.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <uint256.h>
#include <util/translation.h>

#include <cstdio>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

int g_fail = 0;
bool Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
    return ok;
}

constexpr CAmount AMOUNT = 50 * COIN;

//! An unsigned PSBT spending one output of `spk`.
PartiallySignedTransaction PsbtSpending(const CScript& spk)
{
    CMutableTransaction credit;
    credit.vin.resize(1);
    credit.vin[0].prevout.SetNull();
    credit.vin[0].scriptSig = CScript() << OP_0 << OP_0;
    credit.vout.resize(1);
    credit.vout[0].nValue = AMOUNT;
    credit.vout[0].scriptPubKey = spk;

    CMutableTransaction spend;
    spend.vin.resize(1);
    spend.vin[0].prevout.hash = CTransaction(credit).GetHash();
    spend.vin[0].prevout.n = 0;
    spend.vout.resize(1);
    spend.vout[0].nValue = AMOUNT - 1000;
    spend.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // PSBTv2: the constructor lays out inputs and outputs from the transaction.
    PartiallySignedTransaction psbt{spend};
    psbt.inputs[0].witness_utxo = credit.vout[0];
    return psbt;
}

//! Serialize and read back, which is where a length bound would bite.
bool RoundTrips(const PartiallySignedTransaction& psbt, PartiallySignedTransaction& back)
{
    DataStream ss;
    ss << psbt;
    try {
        ss >> back;
    } catch (const std::ios_base::failure& e) {
        std::printf("       deserialize failed: %s\n", e.what());
        return false;
    }
    return true;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};

    const CKey secp = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CKey falcon = GenerateRandomKey(CKey::FALCON512_SIZE);
    const CKey mldsa = GenerateRandomKey(CKey::MLDSA44_SIZE);

    // ---- A partial signature and a key origin survive the round trip for every
    // scheme. Falcon-512 is the one Core's bound would drop.
    for (const auto& [name, key] : {std::pair{"secp256k1", secp},
                                    std::pair{"Falcon-512", falcon},
                                    std::pair{"ML-DSA-44", mldsa}}) {
        const CPubKey pub = key.GetPubKey();
        PartiallySignedTransaction psbt = PsbtSpending(CScript() << OP_TRUE);

        // A real signature, not a blob: the deserializer checks the encoding,
        // and for secp256k1 that means DER. CheckSignatureEncoding lets a
        // lattice signature through on its length, so this is the one place the
        // three schemes are not interchangeable in a fixture.
        std::vector<unsigned char> sig;
        Check((std::string(name) + ": the fixture signature is made").c_str(),
              key.Sign(uint256::ONE, sig));
        sig.push_back(SIGHASH_ALL);
        psbt.inputs[0].partial_sigs[pub.GetID()] = SigPair(pub, sig);

        KeyOriginInfo origin;
        origin.fingerprint = {0xde, 0xad, 0xbe, 0xef};
        origin.path = {0x80000000 + 88, 0x80000000, 0, 3};
        psbt.inputs[0].hd_keypaths[pub] = origin;

        PartiallySignedTransaction back{CMutableTransaction{}};
        if (!Check((std::string(name) + ": a PSBT carrying its key round-trips").c_str(),
                   RoundTrips(psbt, back))) {
            continue;
        }
        Check((std::string(name) + ": ...keeping the partial signature").c_str(),
              back.inputs[0].partial_sigs.size() == 1 &&
              back.inputs[0].partial_sigs.begin()->second.first == pub &&
              back.inputs[0].partial_sigs.begin()->second.second == sig);
        Check((std::string(name) + ": ...and the key origin").c_str(),
              back.inputs[0].hd_keypaths.size() == 1 &&
              back.inputs[0].hd_keypaths.begin()->first == pub &&
              back.inputs[0].hd_keypaths.begin()->second == origin);
    }

    // ---- Signing a witness v2 input through PSBT, end to end.
    for (const auto& [name, key] : {std::pair{"Falcon-512", falcon}, std::pair{"ML-DSA-44", mldsa}}) {
        const CPubKey pub = key.GetPubKey();
        const CScript spk = GetScriptForDestination(WitnessV2KeyHash(pub));

        FlatSigningProvider provider;
        provider.keys[pub.GetID()] = key;
        provider.pubkeys[pub.GetID()] = pub;

        PartiallySignedTransaction psbt = PsbtSpending(spk);
        PrecomputedTransactionData txdata;
        const CMutableTransaction unsigned_tx = *psbt.GetUnsignedTx();
        txdata.Init(CTransaction(unsigned_tx), {psbt.inputs[0].witness_utxo}, /*force=*/true);

        common::PSBTFillOptions options;
        options.sign = true;
        const auto res = SignPSBTInput(provider, psbt, /*index=*/0, &txdata, options);
        if (!Check((std::string(name) + ": SignPSBTInput signs a witness v2 input").c_str(), res.has_value())) {
            continue;
        }
        Check((std::string(name) + ": ...and the input is complete").c_str(), PSBTInputSigned(psbt.inputs[0]));
        Check((std::string(name) + ": ...with a two-item final witness").c_str(),
              psbt.inputs[0].final_script_witness.stack.size() == 2 &&
              psbt.inputs[0].final_script_witness.stack[0].size() == pub.SignatureSize() + 1 &&
              psbt.inputs[0].final_script_witness.stack[1].size() == pub.size());

        // ...and the signed PSBT still round-trips, then finalizes into a
        // transaction the interpreter accepts.
        PartiallySignedTransaction back{CMutableTransaction{}};
        if (Check((std::string(name) + ": the signed PSBT round-trips").c_str(), RoundTrips(psbt, back))) {
            CMutableTransaction final_tx;
            Check((std::string(name) + ": ...and finalizes").c_str(),
                  FinalizeAndExtractPSBT(back, final_tx));
            MutableTransactionSignatureChecker checker(&final_tx, 0, AMOUNT, MissingDataBehavior::ASSERT_FAIL);
            ScriptError err = SCRIPT_ERR_OK;
            const bool ok = VerifyScript(final_tx.vin[0].scriptSig, spk, &final_tx.vin[0].scriptWitness,
                                         STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err);
            if (!Check((std::string(name) + ": ...into a transaction that verifies").c_str(), ok)) {
                std::printf("       %s\n", ScriptErrorString(err).c_str());
            }
        }
    }

    // ---- pqsh: the witnessScript travels in the field BIP174 already has.
    {
        const CPubKey pub = mldsa.GetPubKey();
        const CScript witnessScript = GetScriptForDestination(PKHash(pub.GetID()));
        const CScript spk = GetScriptForDestination(WitnessV2ScriptHash(witnessScript));

        FlatSigningProvider provider;
        provider.keys[pub.GetID()] = mldsa;
        provider.pubkeys[pub.GetID()] = pub;
        provider.scripts[CScriptID(witnessScript)] = witnessScript;

        PartiallySignedTransaction psbt = PsbtSpending(spk);
        PrecomputedTransactionData txdata;
        const CMutableTransaction unsigned_tx = *psbt.GetUnsignedTx();
        txdata.Init(CTransaction(unsigned_tx), {psbt.inputs[0].witness_utxo}, /*force=*/true);

        common::PSBTFillOptions options;
        options.sign = true;
        const auto res = SignPSBTInput(provider, psbt, 0, &txdata, options);
        if (Check("pqsh: SignPSBTInput signs a witness v2 script input", res.has_value())) {
            Check("pqsh: ...and the input is complete", PSBTInputSigned(psbt.inputs[0]));
            PartiallySignedTransaction back{CMutableTransaction{}};
            if (Check("pqsh: the signed PSBT round-trips", RoundTrips(psbt, back))) {
                CMutableTransaction final_tx;
                Check("pqsh: ...and finalizes", FinalizeAndExtractPSBT(back, final_tx));
                MutableTransactionSignatureChecker checker(&final_tx, 0, AMOUNT, MissingDataBehavior::ASSERT_FAIL);
                ScriptError err = SCRIPT_ERR_OK;
                Check("pqsh: ...into a transaction that verifies",
                      VerifyScript(final_tx.vin[0].scriptSig, spk, &final_tx.vin[0].scriptWitness,
                                   STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err));
            }
        }
    }

    // ---- A key of no scheme's length is refused rather than read as one.
    {
        PartiallySignedTransaction psbt = PsbtSpending(CScript() << OP_TRUE);
        DataStream ss;
        ss << psbt;
        // 65 is Bitcoin's uncompressed key and 64 is nothing at all; neither is
        // a length any scheme here uses, so neither may be read as a public key.
        Check("a public key of no scheme's length is not a valid size",
              !CPubKey::ValidSize(size_t{64}) && !CPubKey::ValidSize(size_t{65}));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
