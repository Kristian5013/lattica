// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Everything a peer can hand a node as bytes.
//
// A deserializer is the one piece of a node that has no choice about what it
// reads: it runs before any rule can reject anything, on whatever arrived. Two
// failures matter here and they are different. Reading out of bounds is the
// sanitizer's to catch. Accepting an encoding that would not have been written
// is subtler and worse -- two encodings of one transaction are two transaction
// ids, and two ids are a chain split -- so where an object should have exactly
// one encoding, the round trip is asserted rather than assumed.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <addresstype.h>
#include <chainparams.h>
#include <key_io.h>
#include <primitives/block.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <streams.h>

#include <string>
#include <vector>

FUZZ_TARGET(transaction)
{
    FuzzedDataProvider provider = MakeProvider(buffer);
    DataStream stream = ConsumeStream(provider);

    CMutableTransaction tx;
    try {
        stream >> TX_WITH_WITNESS(tx);
    } catch (const std::ios_base::failure&) {
        return;
    }

    const CTransaction ctx{tx};
    (void)ctx.GetHash();
    (void)ctx.GetWitnessHash();
    (void)ctx.IsCoinBase();
    (void)ctx.HasWitness();
    (void)GetVirtualTransactionSize(ctx);

    // A transaction has one encoding. If it did not, its id would not name it.
    DataStream written;
    written << TX_WITH_WITNESS(ctx);
    DataStream reread{std::vector<std::byte>{written.begin(), written.end()}};
    CMutableTransaction back;
    reread >> TX_WITH_WITNESS(back);
    DataStream again;
    again << TX_WITH_WITNESS(CTransaction{back});
    Assert(std::equal(written.begin(), written.end(), again.begin(), again.end()));
    Assert(CTransaction{back}.GetHash() == ctx.GetHash());
}

FUZZ_TARGET(block_header)
{
    FuzzedDataProvider provider = MakeProvider(buffer);
    DataStream stream = ConsumeStream(provider);

    CBlockHeader header;
    try {
        stream >> header;
    } catch (const std::ios_base::failure&) {
        return;
    }

    // Both hashes: one names the block, the other is what proof of work is
    // measured against, and they are not the same function on this chain.
    (void)header.GetHash();
    (void)header.GetPoWHash();
    (void)header.IsNull();

    DataStream written;
    written << header;
    Assert(written.size() == 80);
}

FUZZ_TARGET(block)
{
    FuzzedDataProvider provider = MakeProvider(buffer);
    DataStream stream = ConsumeStream(provider);

    CBlock block;
    try {
        stream >> TX_WITH_WITNESS(block);
    } catch (const std::ios_base::failure&) {
        return;
    }

    (void)block.GetHash();
    (void)block.GetPoWHash();
    (void)block.ToString();
}

FUZZ_TARGET(script)
{
    FuzzedDataProvider provider = MakeProvider(buffer);
    const std::vector<unsigned char> bytes = provider.ConsumeRemainingBytes<unsigned char>();
    const CScript script{bytes.begin(), bytes.end()};

    // Walking the script is where a bad push length would run off the end.
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> push;
    while (pc < script.end()) {
        if (!script.GetOp(pc, opcode, push)) break;
    }

    (void)script.GetSigOpCount(/*fAccurate=*/false);
    (void)script.GetSigOpCount(/*fAccurate=*/true);
    (void)script.IsPayToScriptHash();
    (void)script.IsPushOnly();
    (void)script.HasValidOps();

    int version{0};
    std::vector<unsigned char> program;
    (void)script.IsWitnessProgram(version, program);

    std::vector<std::vector<unsigned char>> solutions;
    (void)Solver(script, solutions);

    CTxDestination dest;
    if (ExtractDestination(script, dest)) {
        // A script that names a destination must be the script that destination
        // names; otherwise an address would not identify what it is paid to.
        Assert(GetScriptForDestination(dest) == script);
        (void)EncodeDestination(dest, Params());
    }
}

FUZZ_TARGET(address_decode)
{
    FuzzedDataProvider provider = MakeProvider(buffer);
    const std::string input = provider.ConsumeRandomLengthString(1024);

    std::string error;
    std::vector<int> locations;
    const CTxDestination dest = DecodeDestination(input, Params(), error, &locations);

    if (IsValidDestination(dest)) {
        Assert(error.empty());
        // Whatever decoded must encode back to something that decodes the same.
        const std::string again = EncodeDestination(dest, Params());
        Assert(!again.empty());
        Assert(DecodeDestination(again, Params()) == dest);
    } else {
        Assert(!error.empty());
    }

    // The extended-key readers take the same untrusted string.
    (void)DecodeExtKey(input, Params());
    (void)DecodeExtPubKey(input, Params());
    (void)DecodeSecret(input, Params());
}

FUZZ_TARGET(descriptor_parse)
{
    FuzzedDataProvider provider = MakeProvider(buffer);
    const std::string input = provider.ConsumeRandomLengthString(2048);

    FlatSigningProvider keys;
    std::string error;
    const auto parsed = Parse(input, keys, error, /*require_checksum=*/false);
    if (parsed.empty()) {
        Assert(!error.empty());
        return;
    }
    for (const auto& desc : parsed) {
        Assert(desc != nullptr);
        (void)desc->IsRange();
        (void)desc->IsSolvable();
        (void)desc->IsSingleType();
        (void)desc->GetOutputType();
        (void)desc->MaxSatisfactionWeight(true);
        (void)desc->MaxSatisfactionElems();
        // A descriptor that parsed must print, and what it prints must parse to
        // the same thing: this is the property a wallet backup depends on.
        const std::string printed = desc->ToString();
        if (!printed.empty()) {
            FlatSigningProvider keys2;
            std::string error2;
            const auto reparsed = Parse(printed, keys2, error2, /*require_checksum=*/false);
            Assert(!reparsed.empty());
            Assert(reparsed[0]->ToString() == printed);
        }
    }
}
