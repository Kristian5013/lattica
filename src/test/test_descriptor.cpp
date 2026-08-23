// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for descriptor.cpp: BIP380's checksum, the cache of derived extended
// public keys, and the descriptor language itself.
//
// The checksum is defined over the descriptor string and has nothing to do with
// what this chain hashes, so it must agree with Bitcoin's exactly -- a wallet
// backup written by one and read by the other would otherwise be rejected. It
// is pinned against BIP380's own vector, which comes from the specification and
// not from this code.
//
// The language differs from Bitcoin's in four places, and the checks below are
// arranged around them: which scheme a key expression may name in which context,
// the pqpkh()/pqsh() witness v2 expressions, satisfaction sizes that are the
// scheme's own rather than ECDSA's, and extended keys having no public form.

#include <script/descriptor.h>

#include <chainparams.h>
#include <crypto/sha3.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <kernel/chainparams.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
bool Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
    return ok;
}

//! Parse one descriptor, expecting exactly one result.
std::unique_ptr<Descriptor> ParseOne(const std::string& str, FlatSigningProvider& out, std::string& error)
{
    auto descs = Parse(str, out, error, /*require_checksum=*/false);
    if (descs.size() != 1) return nullptr;
    return std::move(descs[0]);
}

//! Parse and expand at a position, returning the single scriptPubKey.
bool ExpandOne(const std::string& str, int pos, CScript& script, FlatSigningProvider& keys)
{
    std::string error;
    FlatSigningProvider parse_out;
    auto desc = ParseOne(str, parse_out, error);
    if (!desc) return false;
    keys.Merge(std::move(parse_out));
    std::vector<CScript> scripts;
    if (!desc->Expand(pos, keys, scripts, keys)) return false;
    if (scripts.size() != 1) return false;
    script = scripts[0];
    return true;
}

//! Whether parsing fails, and its message mentions `needle`.
bool FailsWith(const std::string& str, const std::string& needle)
{
    std::string error;
    FlatSigningProvider out;
    auto descs = Parse(str, out, error, /*require_checksum=*/false);
    if (!descs.empty()) return false;
    return error.find(needle) != std::string::npos;
}

} // namespace

int main()
{
    ECC_Context ecc_context{};
    SelectParams(ChainType::MAIN);

    // ---- BIP380's vector. The specification gives raw(deadbeef) the checksum
    // 89f8spxm; anything else means the polynomial or the charset has drifted.
    {
        const std::string got = GetDescriptorChecksum("raw(deadbeef)");
        if (!Check("raw(deadbeef) has BIP380's checksum", got == "89f8spxm")) {
            std::printf("       got '%s', want '89f8spxm'\n", got.c_str());
        }
    }

    // ---- A descriptor that already carries its checksum keeps it.
    {
        Check("a correct checksum is returned unchanged",
              GetDescriptorChecksum("raw(deadbeef)#89f8spxm") == "89f8spxm");
        Check("a wrong checksum yields nothing",
              GetDescriptorChecksum("raw(deadbeef)#89f8spxn").empty());
        Check("a checksum of the wrong length yields nothing",
              GetDescriptorChecksum("raw(deadbeef)#89f8spx").empty());
        Check("two '#' yield nothing",
              GetDescriptorChecksum("raw(deadbeef)#89f8spxm#89f8spxm").empty());
    }

    // ---- Characters outside the input charset have no checksum at all, which
    // is what stops a descriptor with a stray byte from being silently accepted.
    {
        Check("a character outside the charset yields nothing",
              GetDescriptorChecksum(std::string("raw(deadbeef)") + '\x01').empty());
    }

    // ---- The property the algorithm exists for: every single-character change
    // in the payload changes the checksum. Walk one position through the whole
    // input charset and confirm no collision.
    {
        const std::string base = "raw(deadbeef)";
        const std::string want = GetDescriptorChecksum(base);
        const std::string charset =
            "0123456789()[],'/*abcdefgh@:$%{}"
            "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
            "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
        int collisions = 0, tried = 0;
        for (char c : charset) {
            if (c == '#') continue; // would be read as the checksum separator
            std::string mutated = base;
            mutated[6] = c;
            if (mutated == base) continue;
            ++tried;
            if (GetDescriptorChecksum(mutated) == want) ++collisions;
        }
        Check("a one-character change always changes the checksum", tried > 80 && collisions == 0);
    }

    // ---- The cache, whose job is to let a ranged descriptor expand without the
    // private key. Here that is a lookup of nodes already derived and not a
    // derivation, because every step of this key tree is hardened.
    {
        DescriptorCache cache;
        CExtPubKey xpub;
        Check("an empty cache has no parent", !cache.GetCachedParentExtPubKey(0, xpub));
        Check("nor a derived key", !cache.GetCachedDerivedExtPubKey(0, 0, xpub));
        Check("nor a last hardened one", !cache.GetCachedLastHardenedExtPubKey(0, xpub));

        CExtPubKey a;
        a.nDepth = 1;
        a.nChild = 7;
        cache.CacheParentExtPubKey(0, a);
        CExtPubKey back;
        Check("a cached parent comes back", cache.GetCachedParentExtPubKey(0, back) && back == a);
        Check("...and only under its own index", !cache.GetCachedParentExtPubKey(1, back));

        cache.CacheDerivedExtPubKey(0, 5, a);
        Check("a derived key comes back at its index", cache.GetCachedDerivedExtPubKey(0, 5, back) && back == a);
        Check("...and not at another", !cache.GetCachedDerivedExtPubKey(0, 6, back));
    }

    // ---- MergeAndDiff returns what the other cache knew and this one did not,
    // and refuses a contradiction rather than overwriting.
    {
        DescriptorCache mine, theirs;
        CExtPubKey a, b;
        a.nDepth = 1;
        b.nDepth = 2;
        mine.CacheParentExtPubKey(0, a);
        theirs.CacheParentExtPubKey(0, a);
        theirs.CacheParentExtPubKey(1, b);

        const DescriptorCache diff = mine.MergeAndDiff(theirs);
        CExtPubKey got;
        Check("the diff holds only what was new", !diff.GetCachedParentExtPubKey(0, got) &&
              diff.GetCachedParentExtPubKey(1, got) && got == b);
        Check("and the merge took it", mine.GetCachedParentExtPubKey(1, got) && got == b);

        DescriptorCache conflicting;
        conflicting.CacheParentExtPubKey(0, b); // same index, different key
        bool threw = false;
        try {
            mine.MergeAndDiff(conflicting);
        } catch (const std::runtime_error&) {
            threw = true;
        }
        Check("a contradicting cache is refused, not merged", threw);
    }

    // Key material for the language checks below: one key per scheme.
    const CKey secp_key = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CPubKey secp_pub = secp_key.GetPubKey();
    const std::string secp_hex = HexStr(secp_pub);

    const CKey falcon_key = GenerateRandomKey(CKey::FALCON512_SIZE);
    const CPubKey falcon_pub = falcon_key.GetPubKey();
    const std::string falcon_hex = HexStr(falcon_pub);

    const CKey mldsa_key = GenerateRandomKey(CKey::MLDSA44_SIZE);
    const CPubKey mldsa_pub = mldsa_key.GetPubKey();
    const std::string mldsa_hex = HexStr(mldsa_pub);

    const CKey mldsa_key2 = GenerateRandomKey(CKey::MLDSA44_SIZE);
    const std::string mldsa_hex2 = HexStr(mldsa_key2.GetPubKey());

    // ---- Which scheme belongs in which context. The witness version names the
    // scheme, so the expression a key sits in decides its length; the partition
    // is total and both directions of it are refused.
    {
        std::string error;
        FlatSigningProvider out;
        Check("wpkh() takes a secp256k1 key", ParseOne("wpkh(" + secp_hex + ")", out, error) != nullptr);
        Check("wpkh() refuses an ML-DSA key",
              FailsWith("wpkh(" + mldsa_hex + ")", "spendable only under witness v2"));
        Check("wsh(pkh()) refuses a Falcon key",
              FailsWith("wsh(pkh(" + falcon_hex + "))", "spendable only under witness v2"));
        Check("bare pk() refuses a Falcon key",
              FailsWith("pk(" + falcon_hex + ")", "spendable only under witness v2"));
        Check("sh(multi()) refuses an ML-DSA key",
              FailsWith("sh(multi(1," + mldsa_hex + "))", "spendable only under witness v2"));

        Check("pqpkh() takes an ML-DSA key", ParseOne("pqpkh(" + mldsa_hex + ")", out, error) != nullptr);
        Check("pqpkh() takes a Falcon key", ParseOne("pqpkh(" + falcon_hex + ")", out, error) != nullptr);
        Check("pqpkh() refuses a secp256k1 key",
              FailsWith("pqpkh(" + secp_hex + ")", "cannot be spent under witness v2"));
        Check("pqsh(pkh()) refuses a secp256k1 key",
              FailsWith("pqsh(pkh(" + secp_hex + "))", "cannot be spent under witness v2"));
    }

    // ---- Placement. pqpkh() and pqsh() sit where wpkh() and wsh() do: at the
    // top and inside sh(), so that a holder of post-quantum funds has a base58
    // address old software can pay.
    {
        std::string error;
        FlatSigningProvider out;
        Check("sh(pqpkh()) parses", ParseOne("sh(pqpkh(" + mldsa_hex + "))", out, error) != nullptr);
        Check("sh(pqsh(pkh())) parses", ParseOne("sh(pqsh(pkh(" + mldsa_hex + ")))", out, error) != nullptr);
        Check("pqsh() is refused inside wsh()",
              FailsWith("wsh(pqsh(pkh(" + mldsa_hex + ")))", "Can only have pqsh"));
        Check("pqpkh() is refused inside pqsh()",
              FailsWith("pqsh(pqpkh(" + mldsa_hex + "))", "Can only have pqpkh"));
    }

    // ---- Expansion. pqpkh(K) is the witness v2 key hash, which the solver must
    // read back as one.
    {
        FlatSigningProvider keys;
        keys.keys[mldsa_pub.GetID()] = mldsa_key;
        CScript spk;
        if (Check("pqpkh() expands", ExpandOne("pqpkh(" + mldsa_hex + ")", 0, spk, keys))) {
            std::vector<std::vector<unsigned char>> solutions;
            Check("...to a witness v2 key hash", Solver(spk, solutions) == TxoutType::WITNESS_V2_KEYHASH);
            Check("...over Hash160 of the key",
                  spk == (CScript() << OP_2 << ToByteVector(mldsa_pub.GetID())));
            Check("...and the key is in the provider", keys.pubkeys.contains(mldsa_pub.GetID()));
        }
    }

    // ---- pqsh(SCRIPT) is the witness v2 script hash: SHA3-256 of the script,
    // where witness v0 takes SHA-256 of it.
    {
        FlatSigningProvider keys;
        keys.keys[mldsa_pub.GetID()] = mldsa_key;
        CScript spk;
        if (Check("pqsh(pkh()) expands", ExpandOne("pqsh(pkh(" + mldsa_hex + "))", 0, spk, keys))) {
            const CScript inner = GetScriptForDestination(PKHash(mldsa_pub.GetID()));
            uint256 hash;
            SHA3_256().Write(inner).Finalize(hash);
            Check("...to OP_2 over the SHA3-256 of the script",
                  spk == (CScript() << OP_2 << ToByteVector(hash)));
            std::vector<std::vector<unsigned char>> solutions;
            Check("...which the solver reads as a witness v2 script hash",
                  Solver(spk, solutions) == TxoutType::WITNESS_V2_SCRIPTHASH);
            Check("...and the witnessScript is in the provider",
                  keys.scripts.contains(CScriptID(inner)));
        }
    }

    // ---- A multisig under pqsh() may mix the two lattice schemes; only
    // secp256k1 is excluded, because witness v2 cannot spend it.
    {
        std::string error;
        FlatSigningProvider out;
        auto desc = ParseOne("pqsh(multi(2," + falcon_hex + "," + mldsa_hex + "," + mldsa_hex2 + "))", out, error);
        if (Check("pqsh(multi()) over two schemes parses", desc != nullptr)) {
            Check("...and is single-type", desc->IsSingleType());
            // Two schemes in one script means no single output type.
            Check("...with no single output type", !desc->GetOutputType().has_value());
        }
        auto uniform = ParseOne("pqsh(multi(2," + mldsa_hex + "," + mldsa_hex2 + "))", out, error);
        if (Check("pqsh(multi()) over one scheme parses", uniform != nullptr)) {
            Check("...and names that scheme as its output type",
                  uniform->GetOutputType() == OutputType::MLDSA44);
        }
    }

    // ---- Satisfaction sizes are the scheme's own. Core's constant is a 71- or
    // 72-byte ECDSA signature; an ML-DSA-44 one is 2420 bytes, and a fee estimate
    // built on the wrong constant is out by a factor of thirty.
    {
        std::string error;
        FlatSigningProvider out;
        auto wpkh = ParseOne("wpkh(" + secp_hex + ")", out, error);
        auto pq_mldsa = ParseOne("pqpkh(" + mldsa_hex + ")", out, error);
        auto pq_falcon = ParseOne("pqpkh(" + falcon_hex + ")", out, error);
        if (wpkh && pq_mldsa && pq_falcon) {
            const auto w = wpkh->MaxSatisfactionWeight(/*use_max_sig=*/true);
            const auto m = pq_mldsa->MaxSatisfactionWeight(/*use_max_sig=*/true);
            const auto f = pq_falcon->MaxSatisfactionWeight(/*use_max_sig=*/true);
            Check("wpkh() satisfies in Bitcoin's 107 bytes", w == 1 + 72 + 1 + 33);
            // 3 + 2421 for the signature (OP_PUSHDATA2-sized CompactSize) and
            // 3 + 1312 for the key.
            Check("pqpkh(ML-DSA) satisfies in 2424 + 1315 bytes", m == (3 + 2421) + (3 + 1312));
            Check("pqpkh(Falcon) satisfies in 670 + 900 bytes", f == (3 + 667) + (3 + 897));
            Check("the post-quantum satisfactions are far larger", m.has_value() && w.has_value() && *m > 30 * *w);
        }
        // A mixed multisig charges for the threshold signatures that cost the
        // most, not for the threshold times any one of them.
        auto mixed = ParseOne("pqsh(multi(2," + falcon_hex + "," + mldsa_hex + "," + mldsa_hex2 + "))", out, error);
        if (Check("a mixed pqsh(multi()) sizes its satisfaction", mixed != nullptr)) {
            const auto sat = mixed->MaxSatisfactionWeight(/*use_max_sig=*/true);
            // Dummy element, then the two ML-DSA signatures, then the script.
            const int64_t sigs = 1 + 2 * (3 + 2421);
            const int64_t script_size = 1 + (3 + 897) + (3 + 1312) + (3 + 1312) + 1 + 1;
            Check("...at the two largest signatures plus the script",
                  sat == GetSizeOfCompactSize(script_size) + script_size + sigs);
        }
    }

    // ---- Inference: given the keys, a scriptPubKey must come back as the
    // descriptor that produced it.
    {
        FlatSigningProvider keys;
        keys.keys[mldsa_pub.GetID()] = mldsa_key;
        keys.pubkeys[mldsa_pub.GetID()] = mldsa_pub;

        const CScript spk = CScript() << OP_2 << ToByteVector(mldsa_pub.GetID());
        auto inferred = InferDescriptor(spk, keys);
        if (Check("a witness v2 key hash is inferred", inferred != nullptr)) {
            Check("...as pqpkh()", inferred->ToString().rfind("pqpkh(", 0) == 0);
            Check("...naming the same key", inferred->ToString().find(mldsa_hex) != std::string::npos);
            Check("...and it is solvable", inferred->IsSolvable());
        }

        const CScript inner = GetScriptForDestination(PKHash(mldsa_pub.GetID()));
        keys.scripts[CScriptID(inner)] = inner;
        uint256 hash;
        SHA3_256().Write(inner).Finalize(hash);
        const CScript v2sh = CScript() << OP_2 << ToByteVector(hash);
        auto inferred_sh = InferDescriptor(v2sh, keys);
        if (Check("a witness v2 script hash is inferred", inferred_sh != nullptr)) {
            Check("...as pqsh(pkh())", inferred_sh->ToString().rfind("pqsh(pkh(", 0) == 0);
        }

        // Without the key the script is unknown, and inference must fall back
        // rather than invent a pqpkh() it cannot solve.
        FlatSigningProvider empty;
        auto blind = InferDescriptor(spk, empty);
        if (Check("a witness v2 key hash with no key still infers", blind != nullptr)) {
            Check("...but not as a solvable descriptor", !blind->IsSolvable());
        }
    }

    // ---- Round trip: what a descriptor prints must parse back to the same
    // scripts, checksum and all.
    {
        const std::vector<std::string> strs{
            "pqpkh(" + mldsa_hex + ")",
            "pqsh(pkh(" + falcon_hex + "))",
            "sh(pqpkh(" + falcon_hex + "))",
            "pqsh(multi(2," + mldsa_hex + "," + mldsa_hex2 + "))",
            "wpkh(" + secp_hex + ")",
            "sh(wsh(pkh(" + secp_hex + ")))",
        };
        bool all_ok = true;
        for (const auto& s : strs) {
            std::string error;
            FlatSigningProvider out;
            auto desc = ParseOne(s, out, error);
            if (!desc) { all_ok = false; continue; }
            const std::string printed = desc->ToString();
            FlatSigningProvider out2;
            auto again = ParseOne(printed, out2, error);
            if (!again || again->ToString() != printed) { all_ok = false; continue; }
            // The printed form carries a checksum, and it must be the right one.
            if (GetDescriptorChecksum(printed).empty()) all_ok = false;
        }
        Check("every descriptor round-trips through its own string", all_ok);
    }

    // ---- sh() must know whether what it wraps is satisfied from the witness.
    // Core reads that off the output type being bech32, which cannot tell a
    // witness v2 program from a legacy script.
    {
        std::string error;
        FlatSigningProvider out;
        auto sh_pq = ParseOne("sh(pqpkh(" + mldsa_hex + "))", out, error);
        auto sh_legacy = ParseOne("sh(pkh(" + secp_hex + "))", out, error);
        if (Check("sh(pqpkh()) and sh(pkh()) both parse", sh_pq && sh_legacy)) {
            Check("sh(pqpkh()) is a P2SH-segwit output", sh_pq->GetOutputType() == OutputType::P2SH_SEGWIT);
            Check("sh(pkh()) is a legacy output", sh_legacy->GetOutputType() == OutputType::LEGACY);
        }
    }

    // ---- Extended keys. Derivation here is hardened at every step for all
    // three schemes, so a key expression is written with the xprv, has no public
    // form, and says so.
    {
        unsigned char seed[32];
        for (int i = 0; i < 32; ++i) seed[i] = (unsigned char)(i + 1);
        CExtKey master;
        master.SetSeed(seed, CKey::MLDSA44_SIZE);
        const std::string xprv = EncodeExtKey(master, Params());
        Check("an extended key encodes", !xprv.empty());

        std::string error;
        FlatSigningProvider out;
        auto desc = ParseOne("pqpkh(" + xprv + "/0h/*)", out, error);
        if (Check("a ranged pqpkh() over an xprv parses", desc != nullptr)) {
            Check("...and is ranged", desc->IsRange());
            // The secret went to the provider and the expression keeps the public
            // half, as in Core -- except that what travels is the whole extended
            // key, a node's secret here being the seed the key expands out of.
            Check("...leaving the extended key with the provider",
                  out.extkeys.size() == 1 && out.extkeys.begin()->second == master);
            Check("...and printing as an xpub",
                  desc->ToString().find(EncodeExtPubKey(master.Neuter(), Params())) != std::string::npos);
            // Every step is hardened, so it can never expand from public data.
            Check("...and cannot expand itself", !desc->CanSelfExpand());
            Check("...and has the private keys", desc->HavePrivateKeys(out));

            FlatSigningProvider keys0, keys1;
            std::vector<CScript> s0, s1;
            DescriptorCache cache;
            const bool e0 = desc->Expand(0, out, s0, keys0, &cache);
            const bool e1 = desc->Expand(1, out, s1, keys1, &cache);
            if (Check("...expanding at two positions", e0 && e1 && s0.size() == 1 && s1.size() == 1)) {
                Check("...gives two different scripts", s0[0] != s1[0]);
                std::vector<std::vector<unsigned char>> solutions;
                Check("...both witness v2 key hashes",
                      Solver(s0[0], solutions) == TxoutType::WITNESS_V2_KEYHASH &&
                      Solver(s1[0], solutions) == TxoutType::WITNESS_V2_KEYHASH);
                Check("...and the derived key is 1312 bytes",
                      keys0.pubkeys.size() == 1 && keys0.pubkeys.begin()->second.size() == CPubKey::MLDSA44_SIZE);
            }

            // The cache is what makes a wallet without its key work. It is a
            // lookup of nodes already derived, so a position never expanded
            // before is out of reach rather than derivable.
            FlatSigningProvider cached_keys;
            std::vector<CScript> sc;
            Check("...the cache reproduces position 0",
                  desc->ExpandFromCache(0, cache, sc, cached_keys) && sc.size() == 1 && sc[0] == s0[0]);
            std::vector<CScript> sc2;
            FlatSigningProvider cached_keys2;
            Check("...and cannot reach a position it never held",
                  !desc->ExpandFromCache(7, cache, sc2, cached_keys2));

            // ExpandPrivate hands out the derived secret, which is the only way
            // the signer gets one.
            FlatSigningProvider priv;
            desc->ExpandPrivate(0, out, priv);
            Check("...and ExpandPrivate yields the derived secret",
                  priv.keys.size() == 1 && priv.keys.begin()->second.size() == CKey::MLDSA44_SIZE);
        }

        // A secp256k1 tree behaves the same way: the tree, not the scheme, is
        // what makes derivation hardened.
        CExtKey secp_master;
        secp_master.SetSeed(seed, CKey::SECP256K1_SIZE);
        FlatSigningProvider secp_out;
        auto secp_desc = ParseOne("wpkh(" + EncodeExtKey(secp_master, Params()) + "/0/*)", secp_out, error);
        if (Check("a ranged wpkh() over a secp256k1 xprv parses", secp_desc != nullptr)) {
            Check("...and cannot expand itself either", !secp_desc->CanSelfExpand());
        }

        // The xpub form parses, and is what the descriptor prints. What it cannot
        // do is expand on its own: without the extended key it has nothing to
        // derive from and no cache to read.
        const CExtPubKey xpub = secp_master.Neuter();
        FlatSigningProvider pub_out;
        auto pub_desc = ParseOne("wpkh(" + EncodeExtPubKey(xpub, Params()) + "/0/*)", pub_out, error);
        if (Check("a ranged wpkh() over an xpub parses", pub_desc != nullptr)) {
            Check("...leaving no key behind", pub_out.extkeys.empty() && pub_out.keys.empty());
            std::vector<CScript> s;
            FlatSigningProvider k;
            Check("...and cannot expand without the extended key", !pub_desc->Expand(0, pub_out, s, k));
            // Hand it the extended key and the same expression expands.
            FlatSigningProvider with_key;
            with_key.extkeys.emplace(xpub.pubkey.GetID(), secp_master);
            std::vector<CScript> s2;
            FlatSigningProvider k2;
            Check("...and expands once it is given one", pub_desc->Expand(0, with_key, s2, k2) && s2.size() == 1);
            // ...to the very same script the xprv spelling produces.
            std::vector<CScript> s3;
            FlatSigningProvider k3;
            Check("...to the same script the xprv spelling gives",
                  secp_desc && secp_desc->Expand(0, secp_out, s3, k3) && s3.size() == 1 && s2.size() == 1 && s2[0] == s3[0]);
        }
    }

    // ---- A constant secp256k1 key can be written as WIF; a lattice key cannot,
    // WIF being a 32-byte scalar's envelope, and falls back to its public form.
    {
        std::string error;
        FlatSigningProvider out;
        auto secp_desc = ParseOne("wpkh(" + EncodeSecret(secp_key, Params()) + ")", out, error);
        if (Check("wpkh() takes a WIF secret", secp_desc != nullptr)) {
            Check("...putting the key in the provider", out.keys.contains(secp_pub.GetID()));
            std::string priv;
            Check("...and printing it back as WIF",
                  secp_desc->ToPrivateString(out, priv) && priv.find(EncodeSecret(secp_key, Params())) != std::string::npos);
        }

        FlatSigningProvider pq;
        pq.keys[mldsa_pub.GetID()] = mldsa_key;
        auto pq_desc = ParseOne("pqpkh(" + mldsa_hex + ")", pq, error);
        if (Check("pqpkh() over a constant key parses", pq_desc != nullptr)) {
            std::string priv;
            const bool any = pq_desc->ToPrivateString(pq, priv);
            Check("...and its private form is the public one, there being no WIF",
                  !any && priv.find(mldsa_hex) != std::string::npos);
        }
    }

    // ---- DescriptorID is a stable identifier of the string.
    {
        std::string error;
        FlatSigningProvider out;
        auto a = ParseOne("pqpkh(" + mldsa_hex + ")", out, error);
        auto b = ParseOne("pqpkh(" + mldsa_hex + ")", out, error);
        auto c = ParseOne("pqpkh(" + falcon_hex + ")", out, error);
        if (Check("three descriptors parse for the id check", a && b && c)) {
            Check("the same descriptor has the same id", DescriptorID(*a) == DescriptorID(*b));
            Check("a different one has a different id", DescriptorID(*a) != DescriptorID(*c));
        }
    }

    // ---- Twenty ML-DSA keys are 26300 bytes of script, past MAX_SCRIPT_SIZE.
    // Bitcoin's 20-key ceiling was written for 33-byte keys and never binds
    // there, so the byte limit has to be checked separately.
    {
        std::string big = "pqsh(multi(1";
        for (int i = 0; i < 20; ++i) big += "," + mldsa_hex;
        big += "))";
        Check("a pqsh(multi()) past MAX_SCRIPT_SIZE is refused", FailsWith(big, "too large"));

        std::string ok = "pqsh(multi(2," + mldsa_hex + "," + mldsa_hex2 + "))";
        std::string error;
        FlatSigningProvider out;
        Check("...while a two-key one is fine", ParseOne(ok, out, error) != nullptr);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
