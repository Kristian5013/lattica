// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// The signing path (script/sign.cpp), end to end: build a scriptPubKey, hand a
// signing provider the key, and let ProduceSignature reach a witness the script
// interpreter accepts.
//
// Witness v2 is the reason this file exists. The interpreter, the solver and the
// descriptors all knew about v2 well before sign.cpp did: SignStep had no case
// for either v2 output type and CreateSig stood on an assert of BASE or
// WITNESS_V0, so the wallet could recognise a post-quantum output and never
// spend it. Nothing short of producing a signature and verifying it catches
// that, which is what the checks below do.
//
// The secp256k1 cases are here as the control: they must keep working unchanged.

#include <consensus/amount.h>
#include <hash.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>

#include <util/translation.h>

#include <cstdio>
#include <string>
#include <vector>

// Defined per-executable, as Core does in its test setup.
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

//! A one-in one-out transaction spending `spk`, ready to be signed.
CMutableTransaction SpendOf(const CScript& spk)
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
    return spend;
}

//! Sign `spk` with what `provider` holds, and verify the result against the
//! interpreter. Returns whether both halves succeeded.
bool SignAndVerify(const SigningProvider& provider, const CScript& spk, ScriptError& err, SignatureData& sigdata)
{
    CMutableTransaction tx = SpendOf(spk);
    MutableTransactionSignatureCreator creator(tx, 0, AMOUNT, SignOptions{});
    if (!ProduceSignature(provider, creator, spk, sigdata)) return false;
    UpdateInput(tx.vin[0], sigdata);

    MutableTransactionSignatureChecker checker(&tx, 0, AMOUNT, MissingDataBehavior::ASSERT_FAIL);
    err = SCRIPT_ERR_OK;
    return VerifyScript(tx.vin[0].scriptSig, spk, &tx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &err);
}

//! The size ProduceSignature would need, as the dummy creator estimates it.
int64_t DummySatisfactionSize(const SigningProvider& provider, const CScript& spk)
{
    CMutableTransaction tx = SpendOf(spk);
    SignatureData sigdata;
    if (!ProduceSignature(provider, DUMMY_SIGNATURE_CREATOR, spk, sigdata)) return -1;
    int64_t total = sigdata.scriptSig.size();
    for (const auto& item : sigdata.scriptWitness.stack) total += item.size();
    return total;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};

    const CKey mldsa = GenerateRandomKey(CKey::MLDSA44_SIZE);
    const CPubKey p_mldsa = mldsa.GetPubKey();
    const CKey falcon = GenerateRandomKey(CKey::FALCON512_SIZE);
    const CPubKey p_falcon = falcon.GetPubKey();
    const CKey secp = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CPubKey p_secp = secp.GetPubKey();

    // ---- The control: witness v0, which worked before any of this.
    {
        FlatSigningProvider provider;
        provider.keys[p_secp.GetID()] = secp;
        provider.pubkeys[p_secp.GetID()] = p_secp;
        const CScript spk = GetScriptForDestination(WitnessV0KeyHash(p_secp));

        ScriptError err;
        SignatureData sigdata;
        if (Check("P2WPKH signs and verifies", SignAndVerify(provider, spk, err, sigdata))) {
            Check("...with a two-item witness", sigdata.scriptWitness.stack.size() == 2);
            Check("...and an empty scriptSig", sigdata.scriptSig.empty());
        } else {
            std::printf("       %s\n", ScriptErrorString(err).c_str());
        }
    }

    // ---- Witness v2, key hash. The scheme is the length of the key, and the
    // whole point is that a 2420-byte signature reaches the stack at all.
    for (const auto& [name, key, pub, siglen] : {
             std::tuple{"ML-DSA-44", mldsa, p_mldsa, CPubKey::MLDSA44_SIGNATURE_SIZE},
             std::tuple{"Falcon-512", falcon, p_falcon, CPubKey::FALCON512_SIGNATURE_SIZE}}) {
        FlatSigningProvider provider;
        provider.keys[pub.GetID()] = key;
        provider.pubkeys[pub.GetID()] = pub;
        const CScript spk = GetScriptForDestination(WitnessV2KeyHash(pub));

        std::vector<std::vector<unsigned char>> sols;
        Check((std::string(name) + ": the output is a witness v2 key hash").c_str(),
              Solver(spk, sols) == TxoutType::WITNESS_V2_KEYHASH);

        ScriptError err;
        SignatureData sigdata;
        if (Check((std::string(name) + ": pqpkh signs and verifies").c_str(),
                  SignAndVerify(provider, spk, err, sigdata))) {
            Check((std::string(name) + ": ...with signature and key on the witness stack").c_str(),
                  sigdata.scriptWitness.stack.size() == 2 &&
                  sigdata.scriptWitness.stack[0].size() == siglen + 1 &&
                  sigdata.scriptWitness.stack[1].size() == pub.size());
            Check((std::string(name) + ": ...and an empty scriptSig").c_str(), sigdata.scriptSig.empty());
        } else {
            std::printf("       %s\n", ScriptErrorString(err).c_str());
        }

        // Without the key nothing can be produced, and the key that is missing
        // must be named rather than the failure being silent.
        FlatSigningProvider pubkey_only;
        pubkey_only.pubkeys[pub.GetID()] = pub;
        SignatureData nosig;
        CMutableTransaction tx = SpendOf(spk);
        MutableTransactionSignatureCreator creator(tx, 0, AMOUNT, SignOptions{});
        Check((std::string(name) + ": without the key nothing is produced").c_str(),
              !ProduceSignature(pubkey_only, creator, spk, nosig));
        Check((std::string(name) + ": ...and the missing key is named").c_str(),
              nosig.missing_sigs.size() == 1 && nosig.missing_sigs[0] == pub.GetID());
    }

    // ---- Witness v2, script hash: pqsh(pkh(K)).
    {
        FlatSigningProvider provider;
        provider.keys[p_mldsa.GetID()] = mldsa;
        provider.pubkeys[p_mldsa.GetID()] = p_mldsa;
        const CScript witnessScript = GetScriptForDestination(PKHash(p_mldsa.GetID()));
        provider.scripts[CScriptID(witnessScript)] = witnessScript;
        const CScript spk = GetScriptForDestination(WitnessV2ScriptHash(witnessScript));

        std::vector<std::vector<unsigned char>> sols;
        Check("pqsh: the output is a witness v2 script hash",
              Solver(spk, sols) == TxoutType::WITNESS_V2_SCRIPTHASH);

        ScriptError err;
        SignatureData sigdata;
        if (Check("pqsh(pkh) signs and verifies", SignAndVerify(provider, spk, err, sigdata))) {
            Check("...with signature, key and witnessScript on the stack",
                  sigdata.scriptWitness.stack.size() == 3 &&
                  sigdata.scriptWitness.stack.back() ==
                      std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));
            Check("...and the witnessScript is recorded", sigdata.witness_script == witnessScript);
        } else {
            std::printf("       %s\n", ScriptErrorString(err).c_str());
        }

        // The witnessScript is found by RIPEMD160 of the program, which is what
        // the descriptor and the address encoder both commit to. Take it away
        // and the script must be reported missing.
        FlatSigningProvider no_script;
        no_script.keys[p_mldsa.GetID()] = mldsa;
        no_script.pubkeys[p_mldsa.GetID()] = p_mldsa;
        SignatureData nosig;
        CMutableTransaction tx = SpendOf(spk);
        MutableTransactionSignatureCreator creator(tx, 0, AMOUNT, SignOptions{});
        Check("pqsh: without the witnessScript nothing is produced",
              !ProduceSignature(no_script, creator, spk, nosig));
        Check("pqsh: ...and the missing witnessScript is named",
              !nosig.missing_witness_script.IsNull());
    }

    // ---- Witness v2, multisig under pqsh, mixing the two lattice schemes.
    {
        FlatSigningProvider provider;
        for (const auto& [k, p] : {std::pair{mldsa, p_mldsa}, std::pair{falcon, p_falcon}}) {
            provider.keys[p.GetID()] = k;
            provider.pubkeys[p.GetID()] = p;
        }
        const CScript witnessScript = GetScriptForMultisig(2, {p_mldsa, p_falcon});
        provider.scripts[CScriptID(witnessScript)] = witnessScript;
        const CScript spk = GetScriptForDestination(WitnessV2ScriptHash(witnessScript));

        ScriptError err;
        SignatureData sigdata;
        if (Check("pqsh(multi) over two schemes signs and verifies",
                  SignAndVerify(provider, spk, err, sigdata))) {
            // The dummy element CHECKMULTISIG pops, two signatures, the script.
            Check("...with a four-item witness", sigdata.scriptWitness.stack.size() == 4);
            Check("...carrying one signature of each scheme",
                  sigdata.scriptWitness.stack[1].size() + sigdata.scriptWitness.stack[2].size() ==
                      CPubKey::MLDSA44_SIGNATURE_SIZE + CPubKey::FALCON512_SIGNATURE_SIZE + 2);
        } else {
            std::printf("       %s\n", ScriptErrorString(err).c_str());
        }
    }

    // ---- P2SH-wrapped witness v2: the reason v2 may be wrapped at all is that
    // it gives a holder of post-quantum funds an address old software can pay.
    {
        FlatSigningProvider provider;
        provider.keys[p_mldsa.GetID()] = mldsa;
        provider.pubkeys[p_mldsa.GetID()] = p_mldsa;
        const CScript redeem = GetScriptForDestination(WitnessV2KeyHash(p_mldsa));
        provider.scripts[CScriptID(redeem)] = redeem;
        const CScript spk = GetScriptForDestination(ScriptHash(redeem));

        ScriptError err;
        SignatureData sigdata;
        if (Check("sh(pqpkh) signs and verifies", SignAndVerify(provider, spk, err, sigdata))) {
            Check("...with the redeemScript in the scriptSig and the rest in the witness",
                  !sigdata.scriptSig.empty() && sigdata.scriptWitness.stack.size() == 2);
        } else {
            std::printf("       %s\n", ScriptErrorString(err).c_str());
        }
    }

    // ---- The dummy creator sizes a signature by the scheme of the key, which
    // is what every fee estimate rests on. Core's dummy is always a 71- or
    // 72-byte DER encoding; here that is right for one scheme out of three, and
    // wrong by a factor of thirty for another.
    {
        FlatSigningProvider secp_p, mldsa_p, falcon_p;
        secp_p.pubkeys[p_secp.GetID()] = p_secp;
        mldsa_p.pubkeys[p_mldsa.GetID()] = p_mldsa;
        falcon_p.pubkeys[p_falcon.GetID()] = p_falcon;

        const int64_t s = DummySatisfactionSize(secp_p, GetScriptForDestination(WitnessV0KeyHash(p_secp)));
        const int64_t m = DummySatisfactionSize(mldsa_p, GetScriptForDestination(WitnessV2KeyHash(p_mldsa)));
        const int64_t f = DummySatisfactionSize(falcon_p, GetScriptForDestination(WitnessV2KeyHash(p_falcon)));

        // DUMMY_SIGNATURE_CREATOR is the low-R one: 32 + 32 + 7 DER bytes with
        // the sighash byte already counted, then the 33-byte key.
        if (!Check("the dummy P2WPKH satisfaction is Bitcoin's 104 bytes", s == 71 + 33)) {
            std::printf("       got %lld\n", (long long)s);
        }
        Check("the dummy ML-DSA satisfaction is its own 3733 bytes",
              m == CPubKey::MLDSA44_SIGNATURE_SIZE + 1 + CPubKey::MLDSA44_SIZE);
        Check("the dummy Falcon satisfaction is its own 1564 bytes",
              f == CPubKey::FALCON512_SIGNATURE_SIZE + 1 + CPubKey::FALCON512_SIZE);

        // ...and with no public key to go on, the witness version still names
        // the scheme: only the lattice ones are spendable under v2.
        FlatSigningProvider empty;
        empty.scripts[CScriptID(GetScriptForDestination(WitnessV2KeyHash(p_mldsa)))] =
            GetScriptForDestination(WitnessV2KeyHash(p_mldsa));
        CMutableTransaction tx = SpendOf(GetScriptForDestination(WitnessV2KeyHash(p_mldsa)));
        SignatureData sd;
        std::vector<unsigned char> sig;
        Check("with no key at hand a v2 signature is still sized for a lattice one",
              DUMMY_SIGNATURE_CREATOR.CreateSig(empty, sig, p_mldsa.GetID(), CScript(), SigVersion::WITNESS_V2) &&
              sig.size() == CPubKey::MLDSA44_SIGNATURE_SIZE + 1);
        sig.clear();
        Check("...and a v0 one for a curve signature",
              DUMMY_SIGNATURE_CREATOR.CreateSig(empty, sig, p_secp.GetID(), CScript(), SigVersion::WITNESS_V0) &&
              sig.size() <= CPubKey::SECP256K1_SIGNATURE_SIZE);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
