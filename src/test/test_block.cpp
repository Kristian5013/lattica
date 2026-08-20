// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// primitives/block (80-byte CBlockHeader) tests + hash CLI.
// Standalone for now (own main); folds into the test framework when it lands.
//
//   no args     run the built-in checks, exit non-zero on any failure
//   --hash      forward hex of the fixed header's identity hash (SHA3-256)

#include <crypto/hex_base.h>
#include <hash.h>
#include <primitives/block.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <span>
#include <string>
#include <vector>

namespace {

uint256 RawUint256(unsigned char first)
{
    std::array<unsigned char, 32> b{};
    b[0] = first;
    return uint256{std::span<const unsigned char>(b)};
}

CBlockHeader MakeHeader()
{
    CBlockHeader h;
    h.nVersion = 1;
    h.hashPrevBlock = RawUint256(0x01);
    h.hashMerkleRoot = RawUint256(0x02);
    h.nTime = 0x11223344;
    h.nBits = 0x1f00ffff;
    h.nNonce = 0xdeadbeef;
    return h;
}

struct TestStream {
    std::vector<std::byte> buf;
    size_t pos = 0;
    void write(std::span<const std::byte> src) { buf.insert(buf.end(), src.begin(), src.end()); }
    void read(std::span<std::byte> dst)
    {
        if (pos + dst.size() > buf.size()) throw std::ios_base::failure("read past end");
        std::memcpy(dst.data(), buf.data() + pos, dst.size());
        pos += dst.size();
    }
    template <typename T> TestStream& operator<<(const T& obj) { ::Serialize(*this, obj); return *this; }
    template <typename T> TestStream& operator>>(T&& obj) { ::Unserialize(*this, obj); return *this; }
};

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
    if (argc == 2 && std::strcmp(argv[1], "--hash") == 0) {
        std::printf("%s\n", FwdHex(MakeHeader().GetHash()).c_str());
        return 0;
    }

    const CBlockHeader h = MakeHeader();

    // Standard 80-byte Bitcoin header (no trailing fields).
    Check("header size == 80", GetSerializeSize(h) == 80);

    // Identity hash is deterministic.
    Check("GetHash deterministic", MakeHeader().GetHash() == h.GetHash());

    // Proof-of-work hash is NIST SHA3-256d: one more SHA3-256 over the identity hash.
    Check("GetPoWHash == SHA3-256(GetHash)", h.GetPoWHash() == Hash(h.GetHash()));
    Check("GetPoWHash != GetHash", h.GetPoWHash() != h.GetHash());

    // Serialization round-trip.
    {
        TestStream s;
        Serialize(s, h);
        Check("header serializes to 80 bytes", s.buf.size() == 80);
        CBlockHeader h2;
        Unserialize(s, h2);
        Check("header round-trip", h2.GetHash() == h.GetHash() &&
                                   h2.nNonce == h.nNonce && s.pos == s.buf.size());
    }

    // Null handling.
    Check("default header IsNull", CBlockHeader().IsNull());
    Check("populated header not null", !h.IsNull());

    // CBlock wraps a header + transactions; an empty block carries the header.
    {
        CBlock block(h);
        Check("CBlock keeps header hash", block.GetHash() == h.GetHash());
        Check("CBlock empty vtx", block.vtx.empty());
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
