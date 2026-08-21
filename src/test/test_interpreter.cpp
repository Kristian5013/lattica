// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Script interpreter tests, restarted after the post-quantum schemes moved from
// witness v0 to witness v2. The file that stood here built every fixture as
// ML-DSA under v0, which is no longer a spendable combination; it is being
// written again a piece at a time, and this is the first piece.
//
// The hash opcodes. Three of the five Bitcoin defines are live here and two are
// not, and which is which is a consensus decision worth pinning:
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

#include <crypto/sha256.h>
#include <hash.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>

#include <cstdio>
#include <cstring>
#include <string>
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

} // namespace

int main()
{
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

        valtype sha256_of_abc = FromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        Check("OP_HASH256 is not SHA-256", ok && stack.size() == 1 && stack[0] != sha256_of_abc);
    }

    // ---- OP_HASH160 must agree with Hash160(), which is what PKH, CScriptID
    // and the witness v0 and v2 key-hash programs all commit to. A second
    // definition of it anywhere makes every P2WPKH spend fail on EQUALVERIFY.
    {
        ScriptError err;
        auto [ok, stack] = Run(CScript() << preimage << OP_HASH160, err);
        const uint160 want{Hash160(preimage)};
        Check("OP_HASH160 is Hash160 from hash.h", ok && stack.size() == 1 &&
              stack[0].size() == 20 && std::memcmp(stack[0].data(), want.begin(), 20) == 0);
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

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
