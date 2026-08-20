// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the signature cache (script/sigcache): a real ML-DSA-44 signature
// verified through CachingTransactionSignatureChecker (first call does the
// verify and stores; a read-only checker then finds it cached), a tampered
// signature rejected, and ComputeEntry/Get/Set round-trip.

#include <script/sigcache.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <hash.h>
#include <uint256.h>

extern "C" {
#include "api.h"
}

#include <cstdio>
#include <span>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}
using valtype = std::vector<unsigned char>;
} // namespace

int main()
{
    constexpr size_t PK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
    constexpr size_t SK = PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
    constexpr size_t SIGMAX = PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;

    valtype pk(PK), sk(SK);
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk.data(), sk.data());
    valtype pubkey_stack; pubkey_stack.push_back((unsigned char)SigScheme::ML_DSA_44);
    pubkey_stack.insert(pubkey_stack.end(), pk.begin(), pk.end());
    valtype pkh(Hash160(pubkey_stack).begin(), Hash160(pubkey_stack).end());

    // A P2WPKH spend: scriptCode is the implied P2PKH script, sighash over BIP-143.
    CScript exec_script = CScript() << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;
    const int64_t amount = 50 * 100000000LL;

    CMutableTransaction mtx;
    mtx.version = 2;
    CTxIn in; uint256 prev; for (unsigned i = 0; i < uint256::size(); ++i) prev.begin()[i] = (unsigned char)(i + 1);
    in.prevout = COutPoint(Txid::FromUint256(prev), 0);
    mtx.vin.push_back(in);
    mtx.vout.push_back(CTxOut(9 * 100000000LL, CScript() << OP_TRUE));
    const CTransaction tx{mtx};

    const uint256 sighash = SignatureHash(exec_script, tx, 0, SIGHASH_ALL, amount, SigVersion::WITNESS_V0);
    valtype sig(SIGMAX); size_t siglen = 0;
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig.data(), &siglen, sighash.begin(), sighash.size(), sk.data());
    sig.resize(siglen);
    valtype sig_ht = sig; sig_ht.push_back(SIGHASH_ALL);

    SignatureCache cache(DEFAULT_SIGNATURE_CACHE_BYTES);
    PrecomputedTransactionData txdata(tx);

    // First verify: store=true -> real ML-DSA verify, then cached.
    {
        CachingTransactionSignatureChecker checker(&tx, 0, amount, /*store=*/true, cache, txdata);
        bool ok = checker.CheckSig(sig_ht, pubkey_stack, exec_script, SigVersion::WITNESS_V0);
        Check("caching checker verifies (store)", ok);
    }

    // Second verify: a read-only checker should find it already cached and pass.
    {
        CachingTransactionSignatureChecker checker(&tx, 0, amount, /*store=*/false, cache, txdata);
        bool ok = checker.CheckSig(sig_ht, pubkey_stack, exec_script, SigVersion::WITNESS_V0);
        Check("read-only checker hits cache", ok);
    }

    // Tampered signature -> reject (and not cached).
    {
        valtype bad = sig_ht; bad[9] ^= 0x20;
        CachingTransactionSignatureChecker checker(&tx, 0, amount, true, cache, txdata);
        bool ok = checker.CheckSig(bad, pubkey_stack, exec_script, SigVersion::WITNESS_V0);
        Check("caching checker rejects tampered sig", !ok);
    }

    // ComputeEntry/Set/Get round-trip.
    {
        CPubKey cpk(std::span<const unsigned char>(pubkey_stack.data(), pubkey_stack.size()));
        uint256 entry;
        cache.ComputeEntry(entry, sighash, sig, cpk);
        Check("ComputeEntry deterministic", [&]{ uint256 e2; cache.ComputeEntry(e2, sighash, sig, cpk); return e2 == entry; }());
        Check("entry already present (stored during first verify)", cache.Get(entry, /*erase=*/false));
        uint256 fresh; for (unsigned i = 0; i < uint256::size(); ++i) fresh.begin()[i] = (unsigned char)(0xA0 + i);
        Check("fresh entry absent", !cache.Get(fresh, false));
        cache.Set(fresh);
        Check("fresh entry present after Set", cache.Get(fresh, false));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
