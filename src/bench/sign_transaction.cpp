// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <addresstype.h>
#include <bench/bench.h>
#include <coins.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <uint256.h>
#include <util/check.h>
#include <util/translation.h>

#include <map>
#include <vector>

// Sign a single-input P2WPKH transaction with ML-DSA. Lattica is witness-only
// with no Taproot, so Core's P2TR/Schnorr signing benches do not apply.
static void SignTransactionMLDSA(benchmark::Bench& bench)
{
    FlatSigningProvider keystore;
    std::vector<CScript> prev_spks;

    // Create a bunch of keys / UTXOs to avoid signing with the same key repeatedly.
    for (int i = 0; i < 32; i++) {
        CKey privkey = GenerateRandomKey();
        CPubKey pubkey = privkey.GetPubKey();
        CKeyID key_id = pubkey.GetID();
        keystore.keys.emplace(key_id, privkey);
        keystore.pubkeys.emplace(key_id, pubkey);
        prev_spks.push_back(GetScriptForDestination(WitnessV0KeyHash(pubkey)));
    }

    // Simple 1-input tx with an artificial outpoint (no outputs needed for SIGHASH_ALL).
    COutPoint prevout{/*hashIn=*/Txid::FromUint256(uint256::ONE), /*nIn=*/1337};
    CMutableTransaction unsigned_tx;
    unsigned_tx.vin.emplace_back(prevout);

    int iter = 0;
    bench.minEpochIterations(10).run([&] {
        CMutableTransaction tx{unsigned_tx};
        std::map<COutPoint, Coin> coins;
        const CScript& prev_spk = prev_spks[(iter++) % prev_spks.size()];
        coins[prevout] = Coin(CTxOut(10000, prev_spk), /*nHeightIn=*/100, /*fCoinBaseIn=*/false);
        std::map<int, bilingual_str> input_errors;
        bool complete = SignTransaction(tx, &keystore, coins, SIGHASH_ALL, input_errors);
        assert(complete);
    });
}

BENCHMARK(SignTransactionMLDSA);
