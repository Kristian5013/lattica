// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// hash.h (HashWriter / Hash, SHA3-256 consensus hash) tests + cross-check CLI.
// Standalone for now (own main); folds into the test framework when it lands.
//
//   no args        run the built-in checks, exit non-zero on any failure
//   --hash <hex>   forward hex of Hash(ParseHex(hex))  (== python sha3_256 digest)

#include <crypto/hex_base.h>
#include <crypto/ripemd160.h>
#include <hash.h>
#include <serialize.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

// Forward (non-reversed) hex of a uint256's bytes == the raw SHA3-256 digest,
// which is what python hashlib.sha3_256().hexdigest() produces.
std::string FwdHex(const uint256& h)
{
    return HexStr(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(h.data()), h.size()));
}

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc == 3 && std::strcmp(argv[1], "--hash") == 0) {
        std::printf("%s\n", FwdHex(Hash(ParseHex<unsigned char>(argv[2]))).c_str());
        return 0;
    }

    // Hash() == SHA3-256 (NIST KATs, forward digest).
    Check("Hash(empty)", FwdHex(Hash(std::vector<unsigned char>{})) ==
          "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    {
        std::vector<unsigned char> abc{'a', 'b', 'c'};
        Check("Hash(abc)", FwdHex(Hash(abc)) ==
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    }

    // Two-arg Hash(a, b) == Hash(a || b).
    {
        std::vector<unsigned char> a{1, 2, 3}, b{4, 5, 6}, ab{1, 2, 3, 4, 5, 6};
        Check("Hash(a,b)==Hash(ab)", Hash(a, b) == Hash(ab));
    }

    // HashWriter << serialized object == Hash of the serialized bytes.
    {
        HashWriter w;
        w << uint32_t{0x01020304};
        // serialized little-endian bytes of 0x01020304 are {04,03,02,01}
        std::vector<unsigned char> le{0x04, 0x03, 0x02, 0x01};
        Check("HashWriter << u32 == Hash(LE bytes)", w.GetHash() == Hash(le));
    }

    // HashWriter on a string matches Hash of its raw bytes (no length prefix via write()).
    {
        std::vector<unsigned char> bytes{'t', 'e', 's', 't'};
        HashWriter w;
        w.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()));
        Check("HashWriter.write == Hash", w.GetHash() == Hash(bytes));
    }

    // GetCheapHash is the first 64 bits (LE) of the hash.
    {
        std::vector<unsigned char> data{9, 8, 7, 6, 5};
        uint256 h = Hash(data);
        HashWriter w;
        w.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()));
        uint64_t cheap = w.GetCheapHash();
        Check("GetCheapHash==ReadLE64(hash)", cheap == h.GetUint64(0));
    }

    // uint256::FromHex round-trips the reverse-display GetHex of a real hash.
    {
        uint256 h = Hash(std::vector<unsigned char>{'x'});
        auto back = uint256::FromHex(h.GetHex());
        Check("GetHex/FromHex round-trip", back && *back == h);
    }

    // Hash160 = RIPEMD160(SHA3-256(x)): a hash of the digest, not a slice of it.
    {
        std::vector<unsigned char> data{'s', 'c', 'r', 'i', 'p', 't'};
        uint160 h160 = Hash160(data);
        uint256 h256 = Hash(data);
        unsigned char expected[CRIPEMD160::OUTPUT_SIZE];
        CRIPEMD160().Write(h256.begin(), h256.size()).Finalize(expected);
        Check("Hash160 == RIPEMD160(SHA3-256)",
              h160.size() == CRIPEMD160::OUTPUT_SIZE &&
                  std::memcmp(h160.begin(), expected, CRIPEMD160::OUTPUT_SIZE) == 0);
        // The truncated construction this replaced would have made it a prefix.
        Check("Hash160 is not SHA3-256[:20]",
              std::memcmp(h160.begin(), h256.begin(), CRIPEMD160::OUTPUT_SIZE) != 0);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
