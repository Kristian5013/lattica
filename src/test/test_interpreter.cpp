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
#include <key.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <hash.h>
#include <crypto/ripemd160.h>
#include <crypto/sha3.h>
#include <uint256.h>

extern "C" {
#include "api.h"
}

#include <cassert>
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
//! A public key as it appears on the stack: the scheme's own bytes, nothing in
//! front. The scheme follows from the length, so this is now just a copy — kept
//! as a named helper so the call sites still say which scheme they mean.
valtype PubkeyStack(SigScheme scheme, const valtype& rawkey)
{
    assert(rawkey.size() == SchemePublicKeySize(scheme));
    return rawkey;
}

valtype Hash160Vec(const valtype& data)
{
    uint160 h = Hash160(data);
    return valtype(h.begin(), h.end());
}

} // namespace

int main()
{
    // secp256k1 key generation and signing need the global signing context.
    ECC_Context ecc_context{};

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

    // ---- End-to-end P2WPKH with a secp256k1 key ----
    //
    // The same output type and the same branch of the interpreter, with a
    // different scheme: the witness program is Hash160(scheme byte || key), and
    // CheckSig picks the verifier from that leading byte. This exercises
    // crypto-agility through the consensus engine rather than at the primitive.
    {
        const CKey sk_secp = GenerateRandomKey(SigScheme::SECP256K1);
        const CPubKey pub_secp = sk_secp.GetPubKey();
        const valtype pubkey_secp(pub_secp.begin(), pub_secp.end());
        const valtype pkh_secp = Hash160Vec(pubkey_secp);

        const int64_t amount = 50 * 100000000LL;
        CScript spk = CScript() << OP_0 << pkh_secp;
        CScript exec_script = CScript() << OP_DUP << OP_HASH160 << pkh_secp << OP_EQUALVERIFY << OP_CHECKSIG;

        CMutableTransaction mtx = make_tx();
        const uint256 sighash = SignatureHash(exec_script, mtx, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0);
        std::vector<unsigned char> sig;
        sk_secp.Sign(sighash, sig);
        sig.push_back(SIGHASH_ALL);

        CScriptWitness witness;
        witness.stack.push_back(sig);
        witness.stack.push_back(pubkey_secp);

        const script_verify_flags flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        MutableTransactionSignatureChecker checker(&mtx, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), spk, &witness, flags, checker, &err);
        Check("P2WPKH with a secp256k1 key verifies", ok);
        if (!ok) std::printf("    witness verify error: %s\n", ScriptErrorString(err).c_str());

        // 99 bytes of witness against ML-DSA's 3741 for the same spend.
        Check("secp witness is sig 65 + pubkey 33",
              sig.size() == 65 && pubkey_secp.size() == 33);

        {
            CScriptWitness bad = witness;
            bad.stack[0][5] ^= 0x01;
            ScriptError e = SCRIPT_ERR_OK;
            Check("P2WPKH secp rejects a tampered signature",
                  !VerifyScript(CScript(), spk, &bad, flags, checker, &e));
        }

        // Malleating s to n-s keeps the signature mathematically valid but must
        // be refused by consensus, so a third party cannot rewrite the txid.
        {
            static const unsigned char N[32] = {
                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B, 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};
            CScriptWitness mal = witness;
            int borrow = 0;
            for (int i = 31; i >= 0; --i) {
                const int d = int(N[i]) - int(sig[32 + i]) - borrow;
                mal.stack[0][32 + i] = static_cast<unsigned char>(d & 0xff);
                borrow = (d < 0) ? 1 : 0;
            }
            ScriptError e = SCRIPT_ERR_OK;
            Check("P2WPKH secp rejects the high-S malleation",
                  !VerifyScript(CScript(), spk, &mal, flags, checker, &e));
        }

        // An ML-DSA key hashes to a different program, so it cannot spend this one.
        {
            ScriptError e = SCRIPT_ERR_OK;
            CScriptWitness wrong;
            wrong.stack.push_back(sign(sighash, SIGHASH_ALL));
            wrong.stack.push_back(pubkey_stack);
            Check("P2WPKH secp rejects an ML-DSA key for the same program",
                  !VerifyScript(CScript(), spk, &wrong, flags, checker, &e));
        }
    }

    // ---- End-to-end P2WPKH with a Falcon-512 key ----
    //
    // The third scheme through the same branch, and the one where the witness
    // is a compromise rather than an extreme: 1570 bytes against secp's 99 and
    // ML-DSA's 3741.
    {
        const CKey sk_f = GenerateRandomKey(SigScheme::FALCON_512);
        const CPubKey pub_f = sk_f.GetPubKey();
        const valtype pubkey_f(pub_f.begin(), pub_f.end());
        const valtype pkh_f = Hash160Vec(pubkey_f);

        const int64_t amount = 50 * 100000000LL;
        CScript spk = CScript() << OP_0 << pkh_f;
        CScript exec_script = CScript() << OP_DUP << OP_HASH160 << pkh_f << OP_EQUALVERIFY << OP_CHECKSIG;

        CMutableTransaction mtx = make_tx();
        const uint256 sighash = SignatureHash(exec_script, mtx, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0);
        std::vector<unsigned char> sig;
        sk_f.Sign(sighash, sig);
        sig.push_back(SIGHASH_ALL);

        CScriptWitness witness;
        witness.stack.push_back(sig);
        witness.stack.push_back(pubkey_f);

        const script_verify_flags flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
        MutableTransactionSignatureChecker checker(&mtx, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), spk, &witness, flags, checker, &err);
        Check("P2WPKH with a Falcon-512 key verifies", ok);
        if (!ok) std::printf("    witness verify error: %s\n", ScriptErrorString(err).c_str());

        Check("falcon witness is sig 667 + pubkey 897",
              sig.size() == 667 && pubkey_f.size() == 897);

        // Both items stay under MAX_WITNESS_ITEM, so Falcon needs no change to
        // the consensus limits that ML-DSA already forced.
        Check("falcon witness items fit MAX_WITNESS_ITEM",
              sig.size() <= MAX_WITNESS_ITEM && pubkey_f.size() <= MAX_WITNESS_ITEM);

        {
            CScriptWitness bad = witness;
            bad.stack[0][100] ^= 0x01;
            ScriptError e = SCRIPT_ERR_OK;
            Check("P2WPKH falcon rejects a tampered signature",
                  !VerifyScript(CScript(), spk, &bad, flags, checker, &e));
        }
        {
            // Truncating the padding must fail: the fixed length is the whole
            // reason the padded variant was vendored.
            CScriptWitness shortened = witness;
            shortened.stack[0].erase(shortened.stack[0].begin() + 600);
            ScriptError e = SCRIPT_ERR_OK;
            Check("P2WPKH falcon rejects a short signature",
                  !VerifyScript(CScript(), spk, &shortened, flags, checker, &e));
        }
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

    // (A2) Mixed-scheme 2-of-2: one ML-DSA key and one secp256k1 key in the same
    // witnessScript. This is the capability that comes from tagging the SCHEME
    // ON THE KEY rather than on the witness version: CHECKMULTISIG dispatches
    // per pubkey from its leading byte, so one output can require a signature
    // from a post-quantum key AND a legacy one. A design that picks the scheme
    // from the witness version — Bitcoin's — cannot express this at all, since
    // every key under one version shares one algorithm.
    {
        const CKey sk_secp = GenerateRandomKey(SigScheme::SECP256K1);
        const CPubKey pub_secp = sk_secp.GetPubKey();
        const valtype pubkey_secp(pub_secp.begin(), pub_secp.end());

        CScript ws = CScript() << OP_2 << pubkey_stack << pubkey_secp << OP_2 << OP_CHECKMULTISIG;
        CScript spk = p2wsh_spk(ws);
        CMutableTransaction mtx = make_tx();
        const uint256 sh = SignatureHash(ws, mtx, 0, SIGHASH_ALL, amt, SigVersion::WITNESS_V0);

        valtype s_mldsa = sign_with(sk, sh, SIGHASH_ALL);
        std::vector<unsigned char> s_secp;
        sk_secp.Sign(sh, s_secp);
        s_secp.push_back(SIGHASH_ALL);

        CScriptWitness w;
        w.stack.push_back(valtype());                       // NULLDUMMY
        w.stack.push_back(s_mldsa);                         // must match key order
        w.stack.push_back(valtype(s_secp.begin(), s_secp.end()));
        w.stack.emplace_back(ws.begin(), ws.end());

        MutableTransactionSignatureChecker checker(&mtx, 0, amt, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), spk, &w, wflags, checker, &err);
        Check("P2WSH 2-of-2 mixing ML-DSA and secp256k1 verifies", ok);
        if (!ok) std::printf("    mixed multisig error: %s\n", ScriptErrorString(err).c_str());

        // Swapping the two signatures must fail: CHECKMULTISIG requires them in
        // key order, and neither scheme verifies under the other's key.
        {
            CScriptWitness sw = w;
            std::swap(sw.stack[1], sw.stack[2]);
            ScriptError e = SCRIPT_ERR_OK;
            Check("P2WSH mixed multisig rejects swapped signatures",
                  !VerifyScript(CScript(), spk, &sw, wflags, checker, &e));
        }
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
