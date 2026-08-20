// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the script interpreter: the stack machine (arithmetic, OP_EQUAL,
// conditionals), the SHA3 hash opcodes (OP_HASH160/OP_HASH256) with the
// SHA256/RIPEMD160/SHA1 opcodes disabled, and two end-to-end spends signed with
// a real ML-DSA-44 key — a legacy P2PKH (SigVersion::BASE) and a P2WPKH-analog
// (SigVersion::WITNESS_V0, sighash over the BIP-143 preimage) — each with the
// tampered-signature case rejected.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <hash.h>
#include <crypto/ripemd160.h>
#include <crypto/sha3.h>
#include <uint256.h>

extern "C" {
#include "api.h"
}

#include <cstdio>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

using valtype = std::vector<unsigned char>;

// Local copy of the interpreter's truthiness rule (CastToBool is internal).
bool TopTrue(const valtype& v)
{
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] != 0) return !(i == v.size() - 1 && v[i] == 0x80);
    }
    return false;
}

// Evaluate a standalone script with an empty initial stack and no real checker.
bool Eval(const CScript& script, std::vector<valtype>& stack, ScriptError* err = nullptr)
{
    BaseSignatureChecker base;
    return EvalScript(stack, script, SCRIPT_VERIFY_NONE, base, SigVersion::BASE, err);
}

// (scheme byte || raw key) — the on-stack public key form.
valtype PubkeyStack(SigScheme scheme, const valtype& rawkey)
{
    valtype v;
    v.push_back((unsigned char)scheme);
    v.insert(v.end(), rawkey.begin(), rawkey.end());
    return v;
}

valtype Hash160Vec(const valtype& data)
{
    uint160 h = Hash160(data);
    return valtype(h.begin(), h.end());
}

} // namespace

int main()
{
    // ---- Stack machine ----
    {
        std::vector<valtype> stack;
        // 1 2 ADD 3 EQUAL -> true
        CScript s = CScript() << OP_1 << OP_2 << OP_ADD << OP_3 << OP_EQUAL;
        bool ok = Eval(s, stack);
        Check("1 2 ADD 3 EQUAL evaluates", ok && stack.size() == 1 && TopTrue(stack.back()));
    }
    {
        std::vector<valtype> stack;
        // IF/ELSE: 1 IF 10 ELSE 20 ENDIF -> 10
        CScript s = CScript() << OP_1 << OP_IF << OP_10 << OP_ELSE << OP_16 << OP_ENDIF;
        bool ok = Eval(s, stack);
        Check("IF branch taken", ok && stack.size() == 1 && CScriptNum(stack.back(), false).getint() == 10);
    }

    // ---- SHA3 hash opcodes ----
    {
        std::vector<valtype> stack;
        valtype data{'t', 'e', 's', 't'};
        CScript s = CScript() << data << OP_HASH160;
        bool ok = Eval(s, stack);
        // Independent RIPEMD160(SHA3-256(data)).
        unsigned char inner[SHA3_256::OUTPUT_SIZE];
        SHA3_256().Write(std::span<const unsigned char>(data.data(), data.size())).Finalize(inner);
        unsigned char expected[CRIPEMD160::OUTPUT_SIZE];
        CRIPEMD160().Write(inner, sizeof(inner)).Finalize(expected);
        bool match = ok && stack.size() == 1 && stack.back().size() == 20 &&
                     std::equal(stack.back().begin(), stack.back().end(), expected);
        Check("OP_HASH160 == RIPEMD160(SHA3-256)", match);
    }
    {
        std::vector<valtype> stack;
        valtype data{'t', 'e', 's', 't'};
        CScript s = CScript() << data << OP_HASH256;
        bool ok = Eval(s, stack);
        unsigned char full[SHA3_256::OUTPUT_SIZE];
        SHA3_256().Write(std::span<const unsigned char>(data.data(), data.size())).Finalize(full);
        bool match = ok && stack.size() == 1 && stack.back().size() == 32 &&
                     std::equal(stack.back().begin(), stack.back().end(), full);
        Check("OP_HASH256 == SHA3-256(x)", match);
    }
    {
        std::vector<valtype> stack;
        ScriptError err = SCRIPT_ERR_OK;
        CScript s = CScript() << valtype{1, 2, 3} << OP_SHA256;
        bool ok = Eval(s, stack, &err);
        Check("OP_SHA256 disabled", !ok && err == SCRIPT_ERR_DISABLED_OPCODE);
    }

    // ---- A real ML-DSA-44 key ----
    constexpr size_t PK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
    constexpr size_t SK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
    constexpr size_t SIGMAX = PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;
    valtype pk(PK), sk(SK);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), sk.data());
    const valtype pubkey_stack = PubkeyStack(SigScheme::ML_DSA_44, pk);
    const valtype pkh = Hash160Vec(pubkey_stack);

    auto sign = [&](const uint256& sighash, unsigned char hashtype) {
        valtype sig(SIGMAX);
        size_t siglen = 0;
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig.data(), &siglen,
            sighash.begin(), sighash.size(), sk.data());
        sig.resize(siglen);
        sig.push_back(hashtype); // trailing sighash-type byte
        return sig;
    };

    // A spending transaction with one input and one output.
    auto make_tx = [&]() {
        CMutableTransaction mtx;
        mtx.version = 2;
        CTxIn in;
        uint256 prev;
        for (unsigned i = 0; i < uint256::size(); ++i) prev.begin()[i] = (unsigned char)(i + 1);
        in.prevout = COutPoint(Txid::FromUint256(prev), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        mtx.vin.push_back(in);
        CTxOut out;
        out.nValue = 9 * 100000000LL;
        out.scriptPubKey = CScript() << OP_TRUE;
        mtx.vout.push_back(out);
        return mtx;
    };

    // ---- ML-DSA signing is witness-only (option A) ----
    // A legacy (BASE) scriptSig cannot carry an ML-DSA signature: the 2421-byte
    // push exceeds MAX_SCRIPT_ELEMENT_SIZE (520), so bare/P2SH CHECKSIG with an
    // ML-DSA key is rejected at the push. Spending goes through the witness,
    // where a stack item may be up to MAX_WITNESS_ITEM (3600) bytes.
    {
        CScript spk = CScript() << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;
        CMutableTransaction mtx = make_tx();
        const uint256 sighash = SignatureHash(spk, mtx, 0, SIGHASH_ALL, /*amount=*/0, SigVersion::BASE);
        valtype sig = sign(sighash, SIGHASH_ALL);
        CScript scriptSig = CScript() << sig << pubkey_stack;

        MutableTransactionSignatureChecker checker(&mtx, 0, 0, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = VerifyScript(scriptSig, spk, nullptr, SCRIPT_VERIFY_P2SH, checker, &err);
        Check("legacy ML-DSA scriptSig rejected (witness-only; PUSH_SIZE)",
              !ok && err == SCRIPT_ERR_PUSH_SIZE);
    }

    // ---- End-to-end P2WPKH-analog (SigVersion::WITNESS_V0) ----
    {
        const int64_t amount = 50 * 100000000LL;
        CScript spk = CScript() << OP_0 << pkh; // witness v0 keyhash program
        // The implied P2PKH script is the scriptCode the checker signs over.
        CScript exec_script = CScript() << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;

        CMutableTransaction mtx = make_tx();
        const uint256 sighash = SignatureHash(exec_script, mtx, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0);
        valtype sig = sign(sighash, SIGHASH_ALL);

        CScriptWitness witness;
        witness.stack.push_back(sig);
        witness.stack.push_back(pubkey_stack);

        const script_verify_flags flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        MutableTransactionSignatureChecker checker(&mtx, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = VerifyScript(CScript(), spk, &witness, flags, checker, &err);
        Check("P2WPKH (WITNESS_V0) verifies", ok);
        if (!ok) std::printf("    witness verify error: %s\n", ScriptErrorString(err).c_str());

        // Tampered signature -> fail.
        CScriptWitness badwit;
        valtype bad = sig; bad[7] ^= 0x10;
        badwit.stack.push_back(bad);
        badwit.stack.push_back(pubkey_stack);
        ScriptError err2 = SCRIPT_ERR_OK;
        bool bad_ok = VerifyScript(CScript(), spk, &badwit, flags, checker, &err2);
        Check("P2WPKH rejects tampered sig", !bad_ok);

        // Wrong amount -> different sighash -> fail (binds the value, BIP143).
        MutableTransactionSignatureChecker checker_badamt(&mtx, 0, amount + 1, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err3 = SCRIPT_ERR_OK;
        bool amt_ok = VerifyScript(CScript(), spk, &witness, flags, checker_badamt, &err3);
        Check("P2WPKH binds the input amount", !amt_ok);
    }

    // ---- P2WSH scripts with in-script ML-DSA keys (multisig, HTLC) ----
    // A WITNESS_V0 script body may push elements up to MAX_WITNESS_ITEM (3600 B),
    // so a witnessScript can embed ML-DSA public keys (1313 B). Before this fix the
    // 520 B MAX_SCRIPT_ELEMENT_SIZE made every such script unspendable at execution.
    valtype pk2v(PK), sk2v(SK);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk2v.data(), sk2v.data());
    const valtype pubkey_stack2 = PubkeyStack(SigScheme::ML_DSA_44, pk2v);

    auto sign_with = [&](const valtype& sk_, const uint256& h, unsigned char ht) {
        valtype sig(SIGMAX);
        size_t siglen = 0;
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig.data(), &siglen, h.begin(), h.size(), sk_.data());
        sig.resize(siglen);
        sig.push_back(ht);
        return sig;
    };
    auto p2wsh_spk = [&](const CScript& ws) {
        unsigned char h[SHA3_256::OUTPUT_SIZE];
        SHA3_256().Write(std::span<const unsigned char>(ws.data(), ws.size())).Finalize(h);
        return CScript() << OP_0 << valtype(h, h + sizeof(h));
    };
    const script_verify_flags wflags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                                       SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    const int64_t amt = 50 * 100000000LL;

    // (A) 2-of-2 ML-DSA multisig: two 1313-byte in-script pubkeys.
    {
        CScript ws = CScript() << OP_2 << pubkey_stack << pubkey_stack2 << OP_2 << OP_CHECKMULTISIG;
        CScript spk = p2wsh_spk(ws);
        CMutableTransaction mtx = make_tx();
        const uint256 sh = SignatureHash(ws, mtx, 0, SIGHASH_ALL, amt, SigVersion::WITNESS_V0);
        valtype s1 = sign_with(sk, sh, SIGHASH_ALL);
        valtype s2 = sign_with(sk2v, sh, SIGHASH_ALL);

        CScriptWitness w;
        w.stack.push_back(valtype());               // CHECKMULTISIG NULLDUMMY
        w.stack.push_back(s1);
        w.stack.push_back(s2);
        w.stack.emplace_back(ws.begin(), ws.end()); // the witnessScript

        MutableTransactionSignatureChecker checker(&mtx, 0, amt, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = VerifyScript(CScript(), spk, &w, wflags, checker, &err);
        Check("P2WSH 2-of-2 ML-DSA multisig verifies (in-script PQ pubkeys)", ok);
        if (!ok) std::printf("    err: %s\n", ScriptErrorString(err).c_str());

        CScriptWitness wb;
        valtype bad = s2; bad[9] ^= 0x20;
        wb.stack.push_back(valtype());
        wb.stack.push_back(s1);
        wb.stack.push_back(bad);
        wb.stack.emplace_back(ws.begin(), ws.end());
        ScriptError e2 = SCRIPT_ERR_OK;
        bool okb = VerifyScript(CScript(), spk, &wb, wflags, checker, &e2);
        Check("P2WSH multisig rejects a bad signature", !okb);
    }

    // (B) HTLC clause: SHA3 hashlock branch + CLTV refund branch, each guarded by
    //     an in-script ML-DSA pubkey. Spend the redeem (preimage) path.
    {
        valtype preimage(32);
        for (size_t i = 0; i < preimage.size(); ++i) preimage[i] = (unsigned char)(0xA0 + i);
        unsigned char H[SHA3_256::OUTPUT_SIZE];
        SHA3_256().Write(std::span<const unsigned char>(preimage.data(), preimage.size())).Finalize(H);
        valtype Hvec(H, H + sizeof(H));

        CScript ws = CScript()
            << OP_IF
                << OP_HASH256 << Hvec << OP_EQUALVERIFY << pubkey_stack
            << OP_ELSE
                << CScriptNum(500000) << OP_CHECKLOCKTIMEVERIFY << OP_DROP << pubkey_stack2
            << OP_ENDIF
            << OP_CHECKSIG;
        CScript spk = p2wsh_spk(ws);
        CMutableTransaction mtx = make_tx();
        const uint256 sh = SignatureHash(ws, mtx, 0, SIGHASH_ALL, amt, SigVersion::WITNESS_V0);
        valtype s1 = sign_with(sk, sh, SIGHASH_ALL);

        CScriptWitness w;
        w.stack.push_back(s1);          // bottom: signature for OP_CHECKSIG
        w.stack.push_back(preimage);    // OP_HASH256 input
        w.stack.push_back(valtype{1});  // OP_IF selector: take the redeem branch
        w.stack.emplace_back(ws.begin(), ws.end());

        MutableTransactionSignatureChecker checker(&mtx, 0, amt, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = VerifyScript(CScript(), spk, &w, wflags, checker, &err);
        Check("P2WSH HTLC redeemed via SHA3 hashlock + ML-DSA sig", ok);
        if (!ok) std::printf("    err: %s\n", ScriptErrorString(err).c_str());

        CScriptWitness wb;
        valtype badpre = preimage; badpre[0] ^= 0xFF;
        wb.stack.push_back(s1);
        wb.stack.push_back(badpre);
        wb.stack.push_back(valtype{1});
        wb.stack.emplace_back(ws.begin(), ws.end());
        ScriptError e2 = SCRIPT_ERR_OK;
        bool okb = VerifyScript(CScript(), spk, &wb, wflags, checker, &e2);
        Check("P2WSH HTLC rejects a wrong preimage", !okb);
    }

    // (B2) 3-of-3 ML-DSA multisig: the witnessScript is ~3951 B (> the 3600 the
    //      standardness limit used to be) yet consensus-valid — the witnessScript
    //      body is bounded by MAX_SCRIPT_SIZE (10000), not MAX_WITNESS_ITEM, so
    //      multi-key scripts work and only relay (policy) caps their size.
    {
        valtype pk3v(PK), sk3v(SK);
        PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk3v.data(), sk3v.data());
        const valtype pubkey_stack3 = PubkeyStack(SigScheme::ML_DSA_44, pk3v);

        CScript ws = CScript() << OP_3 << pubkey_stack << pubkey_stack2 << pubkey_stack3 << OP_3 << OP_CHECKMULTISIG;
        CScript spk = p2wsh_spk(ws);
        CMutableTransaction mtx = make_tx();
        const uint256 sh = SignatureHash(ws, mtx, 0, SIGHASH_ALL, amt, SigVersion::WITNESS_V0);

        CScriptWitness w;
        w.stack.push_back(valtype());
        w.stack.push_back(sign_with(sk, sh, SIGHASH_ALL));
        w.stack.push_back(sign_with(sk2v, sh, SIGHASH_ALL));
        w.stack.push_back(sign_with(sk3v, sh, SIGHASH_ALL));
        w.stack.emplace_back(ws.begin(), ws.end());

        MutableTransactionSignatureChecker checker(&mtx, 0, amt, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        bool ok = VerifyScript(CScript(), spk, &w, wflags, checker, &err);
        Check("P2WSH 3-of-3 ML-DSA multisig verifies (witnessScript >3600 B is consensus-valid)",
              ok && ws.size() > 3600);
        if (!ok) std::printf("    err: %s (ws=%zu)\n", ScriptErrorString(err).c_str(), ws.size());
    }

    // (C) Boundary: an in-script WITNESS_V0 push of exactly MAX_WITNESS_ITEM is
    //     allowed; one byte more is PUSH_SIZE.
    {
        auto run_push = [&](size_t n) {
            CScript ws = CScript() << valtype(n, 0x00) << OP_DROP << OP_1;
            CScript spk = p2wsh_spk(ws);
            CMutableTransaction mtx = make_tx();
            CScriptWitness w;
            w.stack.emplace_back(ws.begin(), ws.end());
            BaseSignatureChecker base;
            ScriptError err = SCRIPT_ERR_OK;
            bool ok = VerifyScript(CScript(), spk, &w, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS, base, &err);
            return std::make_pair(ok, err);
        };
        auto at_max = run_push(MAX_WITNESS_ITEM);
        Check("WITNESS_V0 in-script push of MAX_WITNESS_ITEM allowed", at_max.first);
        auto over = run_push(MAX_WITNESS_ITEM + 1);
        Check("WITNESS_V0 in-script push over MAX_WITNESS_ITEM is PUSH_SIZE",
              !over.first && over.second == SCRIPT_ERR_PUSH_SIZE);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
