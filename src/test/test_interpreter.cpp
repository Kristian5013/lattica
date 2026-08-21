// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Script interpreter tests, restarted after the post-quantum schemes moved from
// witness v0 to witness v2. The file that stood here built every fixture as
// ML-DSA under v0, which is no longer a spendable combination; it is being
// written again a piece at a time.
//
// Two pieces so far. The hash opcodes, three of the five Bitcoin defines being
// live here:
//
//   OP_HASH256    SHA3-256, the chain hash
//   OP_HASH160    RIPEMD-160 of it, which is what every address commits to
//   OP_SHA256     Bitcoin's SHA-256 — not a chain hash, but the primitive every
//                 HTLC is written against, and a cross-chain swap needs both
//                 sides to hash one preimage the same way
//   OP_RIPEMD160  disabled; reachable through OP_HASH160 where it is wanted
//   OP_SHA1       disabled; broken
//
// OP_SHA256 is checked against a constant that does not come from this tree, so
// the test fails if it is ever quietly rewired to the chain hash.
//
// And a witness v2 spend end to end, which is the case a version-dispatch gap
// used to abort the node on: EvalChecksig had no WITNESS_V2 branch, so every
// post-quantum CHECKSIG fell through to assert(false).

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;

int g_fail = 0;
bool Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
    return ok;
}

//! Run a script on an empty stack and hand back what it left, plus the error.
std::pair<bool, std::vector<valtype>> Run(const CScript& script, ScriptError& err)
{
    std::vector<valtype> stack;
    const BaseSignatureChecker checker;
    const bool ok = EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::BASE, &err);
    return {ok, stack};
}

valtype FromHex(const std::string& hex)
{
    valtype out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return c - 'A' + 10;
        };
        out.push_back(static_cast<unsigned char>(nib(hex[i]) * 16 + nib(hex[i + 1])));
    }
    return out;
}

valtype Hash160Vec(const valtype& data)
{
    const uint160 h{Hash160(data)};
    return valtype(h.begin(), h.end());
}

//! A one-input, one-output transaction to hang a witness spend on.
CMutableTransaction MakeSpend(CAmount value)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = value;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return mtx;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};

    const valtype preimage{'a', 'b', 'c'};

    // ---- OP_SHA256 is SHA-256, checked against FIPS 180-4's own vector rather
    // than against anything this tree computes.
    {
        ScriptError err;
        auto [ok, stack] = Run(CScript() << preimage << OP_SHA256, err);
        const valtype want = FromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        Check("OP_SHA256 runs", ok && stack.size() == 1);
        Check("OP_SHA256(\"abc\") is the FIPS 180-4 vector", ok && stack.size() == 1 && stack[0] == want);
    }
    {
        // And the empty string, whose digest is the most-quoted constant there is.
        ScriptError err;
        auto [ok, stack] = Run(CScript() << valtype{} << OP_SHA256, err);
        const valtype want = FromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        Check("OP_SHA256(\"\") is e3b0c442...", ok && stack.size() == 1 && stack[0] == want);
    }

    // ---- OP_HASH256 is the chain hash, and so is NOT SHA-256. A swap of the
    // two would leave every other check passing, so it is pinned directly.
    {
        ScriptError err;
        auto [ok, stack] = Run(CScript() << preimage << OP_HASH256, err);
        uint256 want;
        CHash256().Write(preimage).Finalize(want);
        Check("OP_HASH256 is SHA3-256", ok && stack.size() == 1 &&
              std::memcmp(stack[0].data(), want.begin(), 32) == 0);

        const valtype sha256_of_abc = FromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        Check("OP_HASH256 is not SHA-256", ok && stack.size() == 1 && stack[0] != sha256_of_abc);
    }

    // ---- OP_HASH160 must agree with Hash160(), which is what PKH, CScriptID
    // and the witness v0 and v2 key-hash programs all commit to. A second
    // definition of it anywhere makes every key-hash spend fail on EQUALVERIFY.
    {
        ScriptError err;
        auto [ok, stack] = Run(CScript() << preimage << OP_HASH160, err);
        Check("OP_HASH160 is Hash160 from hash.h",
              ok && stack.size() == 1 && stack[0] == Hash160Vec(preimage));
    }

    // ---- The two that stay disabled, and the error they give.
    for (const auto& [name, op] : {std::pair{"OP_RIPEMD160", OP_RIPEMD160}, std::pair{"OP_SHA1", OP_SHA1}}) {
        ScriptError err;
        auto [ok, stack] = Run(CScript() << preimage << op, err);
        Check((std::string(name) + " is disabled").c_str(), !ok && err == SCRIPT_ERR_DISABLED_OPCODE);
    }

    // ---- The shape a hashlock actually takes: OP_SHA256 <digest> OP_EQUAL,
    // which is the HTLC branch of every cross-chain swap. OP_EQUAL leaves {1}
    // for true and the empty vector for false.
    {
        uint256 digest;
        CSHA256().Write(preimage.data(), preimage.size()).Finalize(digest.begin());
        const valtype want(digest.begin(), digest.end());

        ScriptError err;
        auto [ok, stack] = Run(CScript() << preimage << OP_SHA256 << want << OP_EQUAL, err);
        Check("a SHA-256 hashlock opens with the right preimage",
              ok && stack.size() == 1 && stack.back() == valtype{1});

        ScriptError err2;
        auto [ok2, stack2] = Run(CScript() << valtype{'a', 'b', 'd'} << OP_SHA256 << want << OP_EQUAL, err2);
        Check("...and stays shut with the wrong one",
              ok2 && stack2.size() == 1 && stack2.back().empty());
    }

    // ---- A witness v2 spend, end to end.
    //
    // This is the whole point of witness v2 and it is also the case that used to
    // abort the node rather than fail: three of the interpreter's dispatches
    // over SigVersion had no WITNESS_V2 arm, so a post-quantum CHECKSIG reached
    // assert(false). Nothing short of executing one catches that.
    const script_verify_flags witness_flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    const CAmount amount = 50 * COIN;

    const CKey mldsa = GenerateRandomKey(CKey::MLDSA44_SIZE);
    const CPubKey p_mldsa = mldsa.GetPubKey();
    const valtype key_mldsa(p_mldsa.begin(), p_mldsa.end());

    const CKey secp = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CPubKey p_secp = secp.GetPubKey();
    const valtype key_secp(p_secp.begin(), p_secp.end());

    //! Sign the implied key-hash script for a program under `version` and hand
    //! back the two-item witness a key-hash spend takes.
    auto witness_for = [&](const CKey& key, const valtype& pubkey, int version,
                           SigVersion sigversion, CMutableTransaction& mtx) {
        const valtype pkh = Hash160Vec(pubkey);
        const CScript exec_script = CScript() << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;
        const uint256 sighash = SignatureHash(exec_script, mtx, 0, SIGHASH_ALL, amount, sigversion);
        valtype sig;
        key.Sign(sighash, sig);
        sig.push_back(SIGHASH_ALL);
        CScriptWitness witness;
        witness.stack.push_back(sig);
        witness.stack.push_back(pubkey);
        return std::make_pair(CScript() << CScript::EncodeOP_N(version) << pkh, witness);
    };

    {
        CMutableTransaction mtx = MakeSpend(amount - 1000);
        auto [spk, witness] = witness_for(mldsa, key_mldsa, 2, SigVersion::WITNESS_V2, mtx);

        MutableTransactionSignatureChecker checker(&mtx, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), spk, &witness, witness_flags, checker, &err);
        if (!Check("witness v2 ML-DSA key-hash spend verifies", ok)) {
            std::printf("       %s\n", ScriptErrorString(err).c_str());
        }
        Check("...and the witness is a 2421-byte signature and a 1312-byte key",
              witness.stack[0].size() == CPubKey::MLDSA44_SIGNATURE_SIZE + 1 &&
              witness.stack[1].size() == CPubKey::MLDSA44_SIZE);

        // A tampered signature must fail rather than abort.
        CScriptWitness bad = witness;
        bad.stack[0][7] ^= 0x10;
        ScriptError err2 = SCRIPT_ERR_OK;
        Check("...and a tampered signature is refused",
              !VerifyScript(CScript(), spk, &bad, witness_flags, checker, &err2));
    }

    // ---- The version names the scheme, and that is consensus in both
    // directions: a lattice key is refused under v0, and a curve key under v2.
    {
        CMutableTransaction mtx = MakeSpend(amount - 1000);
        auto [spk, witness] = witness_for(mldsa, key_mldsa, 0, SigVersion::WITNESS_V0, mtx);
        MutableTransactionSignatureChecker checker(&mtx, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), spk, &witness, witness_flags, checker, &err);
        // An ML-DSA signature is 2421 bytes with its sighash byte, which is over
        // the 520-byte item limit witness v0 keeps from Bitcoin, so it never
        // reaches the scheme rule. Either refusal is the right one.
        Check("an ML-DSA key cannot be spent under witness v0",
              !ok && (err == SCRIPT_ERR_PUSH_SIZE || err == SCRIPT_ERR_PUBKEYTYPE));
    }
    {
        CMutableTransaction mtx = MakeSpend(amount - 1000);
        auto [spk, witness] = witness_for(secp, key_secp, 2, SigVersion::WITNESS_V2, mtx);
        MutableTransactionSignatureChecker checker(&mtx, 0, amount, MissingDataBehavior::ASSERT_FAIL);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(CScript(), spk, &witness, witness_flags, checker, &err);
        Check("a secp256k1 key cannot be spent under witness v2",
              !ok && err == SCRIPT_ERR_PUBKEYTYPE);
    }

    // ---- OP_CHECKSIGADD belongs to tapscript and must not leak into v2.
    {
        ScriptError err;
        std::vector<valtype> stack{valtype{}, valtype{}, valtype(32, 0x02)};
        const BaseSignatureChecker checker;
        const bool ok = EvalScript(stack, CScript() << OP_CHECKSIGADD, SCRIPT_VERIFY_NONE,
                                   checker, SigVersion::WITNESS_V2, &err);
        Check("OP_CHECKSIGADD is a bad opcode under witness v2",
              !ok && err == SCRIPT_ERR_BAD_OPCODE);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
