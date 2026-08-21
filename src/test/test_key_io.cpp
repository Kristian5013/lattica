// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for address encoding (key_io.cpp), which now covers every format from
// P2PKH to witness v2:
//
//   base58check   P2PKH and P2SH, the checksum being four bytes of SHA3-256
//   bech32        witness v0, per BIP173
//   bech32m       witness v1 (Taproot), witness v2, the anchor, and any version
//                 above them, per BIP350
//
// The v0 framing is pinned against BIP173's own canonical address, so a change
// to the bit conversion or the checksum shows up against a constant that does
// not come from this tree.

#include <addresstype.h>
#include <bech32.h>
#include <key.h>
#include <kernel/chainparams.h>
#include <key_io.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstdio>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}
} // namespace

int main()
{
    ECC_Context ecc_context{};

    // Known-answer: the BIP173 P2WPKH example bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    // has program 751e76e8199196d454941c45d1b3a323f1433bd6. Reproduce key_io's v0
    // framing (version byte 0 + 8->5 bit conversion + bech32) with hrp "bc".
    {
        const std::vector<unsigned char> prog = {
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
            0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6};
        std::vector<unsigned char> data = {0};
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, prog.begin(), prog.end());
        const std::string addr = bech32::Encode(bech32::Encoding::BECH32, "bc", data);
        Check("v0 framing matches canonical BIP173 P2WPKH address",
              addr == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    const std::unique_ptr<const CChainParams> regtest = CChainParams::RegTest();
    const std::unique_ptr<const CChainParams> main = CChainParams::Main();

    const CKey key = GenerateRandomKey();
    const CPubKey pub = key.GetPubKey();
    const CKey secp = GenerateRandomKey(CKey::SECP256K1_SIZE);
    const CPubKey pub_secp = secp.GetPubKey();

    // ---- base58check: P2PKH and P2SH. These are secp256k1's formats, a 520-byte
    // push being unable to hold a lattice signature, so the key here is a curve one.
    {
        const std::string addr = EncodeDestination(PKHash(pub_secp), *main);
        Check("P2PKH has a base58 address on mainnet", !addr.empty() && addr[0] == 'L');
        const CTxDestination back = DecodeDestination(addr, *main);
        Check("P2PKH decodes back to PKHash", std::holds_alternative<PKHash>(back));
        Check("P2PKH re-encodes to the same address", EncodeDestination(back, *main) == addr);
        Check("P2PKH address is valid", IsValidDestinationString(addr, *main));
    }
    {
        const CScript redeem = CScript() << OP_TRUE;
        const std::string addr = EncodeDestination(ScriptHash(redeem), *main);
        Check("P2SH has a base58 address on mainnet", !addr.empty() && addr[0] == 'M');
        const CTxDestination back = DecodeDestination(addr, *main);
        Check("P2SH decodes back to ScriptHash", std::holds_alternative<ScriptHash>(back));
        Check("P2SH re-encodes to the same address", EncodeDestination(back, *main) == addr);
    }
    {
        // The routing between base58 and bech32 must not be decided by comparing
        // the first HRP-many characters, as Core does. Bitcoin can: its base58
        // addresses begin with '1' or '3' and never collide with "bc". Here the
        // mainnet HRP is "la" and a P2PKH address begins with 'L', so one address
        // in thirty begins "La" and that comparison sends it to the bech32 branch,
        // from which it never returns. Grind one such address deliberately rather
        // than waiting for a random key to produce it.
        std::string colliding;
        for (unsigned i = 0; i < 4096 && colliding.empty(); ++i) {
            uint160 h;
            std::fill(h.begin(), h.end(), 0);
            h.begin()[0] = static_cast<unsigned char>(i & 0xff);
            h.begin()[1] = static_cast<unsigned char>((i >> 8) & 0xff);
            const std::string a = EncodeDestination(PKHash(h), *main);
            if (a.size() > 2 && (a[1] == 'a' || a[1] == 'A')) colliding = a;
        }
        Check("a P2PKH address beginning with the HRP's letters exists", !colliding.empty());
        if (!colliding.empty()) {
            Check("...and it still decodes to a PKHash",
                  std::holds_alternative<PKHash>(DecodeDestination(colliding, *main)));
        }
    }
    {
        // The checksum is four bytes of the chain hash. Corrupt one character of
        // the payload and the address must stop decoding.
        std::string addr = EncodeDestination(PKHash(pub_secp), *main);
        addr[5] = (addr[5] == 'a') ? 'b' : 'a';
        std::string err;
        Check("a corrupted base58 address fails its checksum",
              std::holds_alternative<CNoDestination>(DecodeDestination(addr, *main, err)) && !err.empty());
    }

    // ---- bech32: witness v0.
    {
        const CTxDestination dest = WitnessV0KeyHash(pub_secp);
        const std::string addr = EncodeDestination(dest, *regtest);
        Check("P2WPKH address is non-empty and uses the regtest HRP", addr.rfind("lart1", 0) == 0);
        const CTxDestination back = DecodeDestination(addr, *regtest);
        Check("P2WPKH decodes back to WitnessV0KeyHash", std::holds_alternative<WitnessV0KeyHash>(back));
        Check("P2WPKH re-encodes to the same address", EncodeDestination(back, *regtest) == addr);
        Check("P2WPKH address is valid", IsValidDestinationString(addr, *regtest));
    }
    {
        const CScript witnessScript = CScript() << OP_TRUE;
        const CTxDestination dest = WitnessV0ScriptHash(witnessScript);
        const std::string addr = EncodeDestination(dest, *regtest);
        Check("P2WSH address uses regtest HRP", addr.rfind("lart1", 0) == 0 && addr.size() > 40);
        const CTxDestination back = DecodeDestination(addr, *regtest);
        Check("P2WSH decodes back to WitnessV0ScriptHash", std::holds_alternative<WitnessV0ScriptHash>(back));
        Check("P2WSH re-encodes to the same address", EncodeDestination(back, *regtest) == addr);
    }

    // ---- bech32m: witness v1 (Taproot).
    {
        const XOnlyPubKey xonly{pub_secp};
        const CTxDestination dest = WitnessV1Taproot(xonly);
        const std::string addr = EncodeDestination(dest, *regtest);
        Check("taproot address uses regtest HRP", addr.rfind("lart1p", 0) == 0);
        const CTxDestination back = DecodeDestination(addr, *regtest);
        Check("taproot decodes back to WitnessV1Taproot", std::holds_alternative<WitnessV1Taproot>(back));
        Check("taproot re-encodes to the same address", EncodeDestination(back, *regtest) == addr);
        Check("taproot address is valid", IsValidDestinationString(addr, *regtest));
        // A version above 0 must carry the bech32m checksum, so the same payload
        // under bech32 must not decode.
        std::vector<unsigned char> data = {1};
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, xonly.begin(), xonly.end());
        const std::string wrong = bech32::Encode(bech32::Encoding::BECH32, regtest->Bech32HRP(), data);
        std::string err;
        DecodeDestination(wrong, *regtest, err);
        Check("a v1 address with a bech32 checksum is refused", err.find("Bech32m") != std::string::npos);
    }

    // ---- bech32m: witness v2, the post-quantum pair.
    {
        const CTxDestination dest = WitnessV2KeyHash(pub);
        const std::string addr = EncodeDestination(dest, *regtest);
        Check("witness v2 keyhash address uses regtest HRP", addr.rfind("lart1z", 0) == 0);
        const CTxDestination back = DecodeDestination(addr, *regtest);
        Check("witness v2 keyhash decodes back", std::holds_alternative<WitnessV2KeyHash>(back));
        Check("witness v2 keyhash re-encodes the same", EncodeDestination(back, *regtest) == addr);
        Check("witness v2 keyhash address is valid", IsValidDestinationString(addr, *regtest));
    }
    {
        const CScript witnessScript = CScript() << OP_TRUE;
        const CTxDestination dest = WitnessV2ScriptHash(witnessScript);
        const std::string addr = EncodeDestination(dest, *regtest);
        Check("witness v2 scripthash address uses regtest HRP", addr.rfind("lart1z", 0) == 0);
        const CTxDestination back = DecodeDestination(addr, *regtest);
        Check("witness v2 scripthash decodes back", std::holds_alternative<WitnessV2ScriptHash>(back));
        Check("witness v2 scripthash re-encodes the same", EncodeDestination(back, *regtest) == addr);
    }
    {
        // The two v2 lengths are the whole of the version's vocabulary; anything
        // else is left to the upgradable branch rather than guessed at.
        std::vector<unsigned char> data = {2};
        const std::vector<unsigned char> odd(24, 0x11);
        ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, odd.begin(), odd.end());
        const std::string addr = bech32::Encode(bech32::Encoding::BECH32M, regtest->Bech32HRP(), data);
        std::string err;
        DecodeDestination(addr, *regtest, err);
        Check("a v2 program of another length is refused", err.find("program size") != std::string::npos);
    }

    // ---- Pay-to-anchor (witness v1, two bytes, bech32m).
    {
        const std::string addr = EncodeDestination(PayToAnchor(), *regtest);
        Check("anchor address is non-empty (bech32m)", !addr.empty() && addr.rfind("lart1", 0) == 0);
        const CTxDestination back = DecodeDestination(addr, *regtest);
        Check("anchor decodes back to PayToAnchor", std::holds_alternative<PayToAnchor>(back));
        Check("anchor is a valid destination string", IsValidDestinationString(addr, *regtest));
    }

    // ---- Networks do not accept each other's addresses, in either direction.
    {
        const std::string main_addr = EncodeDestination(WitnessV0KeyHash(pub_secp), *main);
        Check("mainnet P2WPKH uses the main HRP", main_addr.rfind("la1", 0) == 0);
        Check("mainnet address is invalid on regtest", !IsValidDestinationString(main_addr, *regtest));
        Check("decoding cross-network yields CNoDestination",
              std::holds_alternative<CNoDestination>(DecodeDestination(main_addr, *regtest)));

        const std::string regtest_addr = EncodeDestination(WitnessV0KeyHash(pub_secp), *regtest);
        Check("regtest address is invalid on mainnet", !IsValidDestinationString(regtest_addr, *main));
    }

    // ---- A destination with no address at all.
    {
        Check("garbage string is invalid", !IsValidDestinationString("not an address", *regtest));
        Check("P2PK has no address", EncodeDestination(PubKeyDestination(pub), *regtest).empty());
        Check("CNoDestination has no address", EncodeDestination(CNoDestination(), *regtest).empty());
    }

    // ---- WIF. Bitcoin's envelope for a 32-byte scalar, and so secp256k1's alone.
    {
        const std::string wif = EncodeSecret(secp, *main);
        Check("a secp256k1 key has a WIF", !wif.empty());
        const CKey back = DecodeSecret(wif, *main);
        Check("WIF round-trips to the same key", back.IsValid() && back == secp);
        Check("...and to the same public key", back.IsValid() && back.GetPubKey() == pub_secp);
        Check("a WIF from another network does not decode", !DecodeSecret(wif, *regtest).IsValid());
        Check("an ML-DSA key has no WIF", EncodeSecret(key, *main).empty());
        Check("garbage is not a WIF", !DecodeSecret("not a wif", *main).IsValid());
    }

    // ---- Error reporting via the error_str / error_locations overload.
    {
        const std::string addr = EncodeDestination(WitnessV0KeyHash(pub_secp), *regtest);
        std::string err = "x";
        DecodeDestination(addr, *regtest, err);
        Check("valid address leaves error_str empty", err.empty());

        // An address for another network names both HRPs, in either direction.
        std::string err2;
        DecodeDestination(EncodeDestination(WitnessV0KeyHash(pub_secp), *regtest), *main, err2);
        Check("regtest address on mainnet names both HRPs",
              err2.find("expected la, got lart") != std::string::npos);

        std::string err3;
        DecodeDestination(EncodeDestination(WitnessV0KeyHash(pub_secp), *main), *regtest, err3);
        Check("mainnet address on regtest names both HRPs",
              err3.find("expected lart, got la") != std::string::npos);

        // Corrupt the last data character -> checksum fails -> bech32 error location.
        std::string bad = addr;
        bad.back() = (bad.back() == 'q') ? 'p' : 'q';
        std::string err4;
        std::vector<int> locs;
        const CTxDestination d = DecodeDestination(bad, *regtest, err4, &locs);
        Check("corrupted address reports an error and is no destination",
              !err4.empty() && std::holds_alternative<CNoDestination>(d));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
