// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// compressor (script/amount compression) + Coin (UTXO entry) tests.
// Standalone for now (own main); folds into the test framework when it lands.

#include <coins.h>
#include <compressor.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <span>
#include <vector>

namespace {

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
    void ignore(size_t n)
    {
        if (pos + n > buf.size()) throw std::ios_base::failure("ignore past end");
        pos += n;
    }
    template <typename T> TestStream& operator<<(const T& obj) { ::Serialize(*this, obj); return *this; }
    template <typename T> TestStream& operator>>(T&& obj) { ::Unserialize(*this, obj); return *this; }
};

CScript P2PKH(uint8_t fill)
{
    CScript s;
    s << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, fill) << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}

CScript P2SH(uint8_t fill)
{
    CScript s;
    s << OP_HASH160 << std::vector<uint8_t>(20, fill) << OP_EQUAL;
    return s;
}

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

} // namespace

int main()
{
    // Amount compression: known answers + round-trip.
    Check("CompressAmount(0)", CompressAmount(0) == 0);
    Check("CompressAmount(1)", CompressAmount(1) == 1);
    Check("CompressAmount(COIN)==9", CompressAmount(static_cast<uint64_t>(COIN)) == 9);
    {
        bool ok = true;
        std::vector<uint64_t> amts = {0, 1, 5, 99, 100, 1234567,
                                      static_cast<uint64_t>(COIN),
                                      static_cast<uint64_t>(50 * COIN),
                                      static_cast<uint64_t>(MAX_MONEY)};
        for (uint64_t a : amts) {
            if (DecompressAmount(CompressAmount(a)) != a) ok = false;
        }
        Check("amount compression round-trip", ok);
    }

    // Script compression: P2PKH -> type 0, P2SH -> type 1, else uncompressed.
    {
        CompressedScript o;
        Check("P2PKH compresses (type 0, 21 B)", CompressScript(P2PKH(0xab), o) && o.size() == 21 && o[0] == 0x00);
    }
    {
        CompressedScript o;
        Check("P2SH compresses (type 1, 21 B)", CompressScript(P2SH(0xcd), o) && o.size() == 21 && o[0] == 0x01);
    }
    {
        CompressedScript o;
        CScript ns;
        ns << OP_1 << OP_2 << OP_ADD;
        Check("non-standard not compressed", !CompressScript(ns, o));
    }

    // Coin round-trips through its compressed serialization.
    {
        Coin c(CTxOut(50 * COIN, P2PKH(0x11)), 123456, true);
        TestStream s;
        c.Serialize(s);
        Coin c2;
        c2.Unserialize(s);
        Check("Coin P2PKH round-trip",
              c2.out.nValue == 50 * COIN && c2.out.scriptPubKey == P2PKH(0x11) &&
              c2.nHeight == 123456 && c2.fCoinBase && s.pos == s.buf.size());
    }
    {
        Coin c(CTxOut(COIN, P2SH(0x99)), 2, false);
        TestStream s;
        c.Serialize(s);
        Coin c2;
        c2.Unserialize(s);
        Check("Coin P2SH round-trip",
              c2.out.scriptPubKey == P2SH(0x99) && c2.nHeight == 2 && !c2.fCoinBase);
    }
    {
        CScript ns;
        ns << OP_1 << OP_2 << OP_ADD;
        Coin c(CTxOut(7, ns), 1, false);
        TestStream s;
        c.Serialize(s);
        Coin c2;
        c2.Unserialize(s);
        Check("Coin non-standard round-trip",
              c2.out.scriptPubKey == ns && c2.out.nValue == 7 && c2.nHeight == 1 &&
              !c2.fCoinBase && s.pos == s.buf.size());
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
