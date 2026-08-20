// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// serialize.h known-answer / round-trip tests.
// Standalone for now (own main); folds into the test framework when it lands.

#include <prevector.h>
#include <serialize.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// Minimal byte-buffer stream satisfying serialize.h's write()/read() interface.
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
};

std::string HexBuf(const std::vector<std::byte>& b)
{
    static constexpr char k[] = "0123456789abcdef";
    std::string s;
    for (std::byte by : b) {
        auto v = std::to_integer<uint8_t>(by);
        s.push_back(k[v >> 4]);
        s.push_back(k[v & 0x0f]);
    }
    return s;
}

std::string CS(uint64_t n)
{
    TestStream s;
    WriteCompactSize(s, n);
    return HexBuf(s.buf);
}

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

template <typename T>
bool RoundTrip(const T& in)
{
    TestStream s;
    Serialize(s, in);
    T out{};
    Unserialize(s, out);
    return out == in && s.pos == s.buf.size();
}

} // namespace

int main()
{
    // GetSizeOfCompactSize.
    Check("size cs 0", GetSizeOfCompactSize(0) == 1);
    Check("size cs 252", GetSizeOfCompactSize(252) == 1);
    Check("size cs 253", GetSizeOfCompactSize(253) == 3);
    Check("size cs 0xffff", GetSizeOfCompactSize(0xffff) == 3);
    Check("size cs 0x10000", GetSizeOfCompactSize(0x10000) == 5);
    Check("size cs 0xffffffff", GetSizeOfCompactSize(0xffffffffULL) == 5);
    Check("size cs 0x100000000", GetSizeOfCompactSize(0x100000000ULL) == 9);

    // CompactSize exact encodings.
    Check("cs 0", CS(0) == "00");
    Check("cs 252", CS(252) == "fc");
    Check("cs 253", CS(253) == "fdfd00");
    Check("cs 0xffff", CS(0xffff) == "fdffff");
    Check("cs 0x10000", CS(0x10000) == "fe00000100");
    Check("cs 0xffffffff", CS(0xffffffffULL) == "feffffffff");
    Check("cs 0x100000000", CS(0x100000000ULL) == "ff0000000001000000");

    // CompactSize round-trip.
    {
        bool ok = true;
        for (uint64_t n : {0ull, 1ull, 252ull, 253ull, 254ull, 0xffffull, 0x10000ull,
                           0xabcdefull, 0xffffffffull, 0x100000000ull, 0x123456789aull}) {
            TestStream s;
            WriteCompactSize(s, n);
            if (ReadCompactSize(s, /*range_check=*/false) != n || s.pos != s.buf.size()) ok = false;
        }
        Check("compactsize round-trip", ok);
    }

    // Little-endian integer layout.
    {
        TestStream s;
        Serialize(s, uint32_t{0x01020304});
        Check("u32 little-endian", HexBuf(s.buf) == "04030201");
    }

    // Round-trips of fundamental + container types.
    Check("u8 round-trip", RoundTrip<uint8_t>(0xab));
    Check("u16 round-trip", RoundTrip<uint16_t>(0xbeef));
    Check("u64 round-trip", RoundTrip<uint64_t>(0x1122334455667788ull));
    Check("i32 round-trip", RoundTrip<int32_t>(-12345));
    Check("i64 round-trip", RoundTrip<int64_t>(-1234567890123ll));
    Check("string round-trip", RoundTrip<std::string>("hello lattica"));
    Check("empty string round-trip", RoundTrip<std::string>(""));
    Check("vector round-trip", RoundTrip<std::vector<uint8_t>>({1, 2, 3, 255, 0, 128}));
    {
        prevector<28, unsigned char> pv;
        for (int i = 0; i < 40; ++i) pv.push_back(static_cast<unsigned char>(i)); // spills past STATIC_SIZE
        Check("prevector round-trip", RoundTrip(pv));
    }

    // GetSerializeSize.
    Check("size string5", GetSerializeSize(std::string("abcde")) == 6); // 1 (compactsize) + 5
    Check("size u32", GetSerializeSize(uint32_t{0}) == 4);
    Check("size vector3", GetSerializeSize(std::vector<uint8_t>{1, 2, 3}) == 4); // 1 + 3

    // Non-canonical CompactSize is rejected.
    {
        TestStream s;
        const std::byte nc[] = {std::byte{0xfd}, std::byte{0xfc}, std::byte{0x00}}; // 252 in 3-byte form
        s.write(nc);
        bool threw = false;
        try { ReadCompactSize(s); } catch (const std::ios_base::failure&) { threw = true; }
        Check("non-canonical cs throws", threw);
    }

    // The DoS range check rejects sizes above MAX_SIZE (0x02000000).
    {
        TestStream s;
        WriteCompactSize(s, 0x100000000ull);
        bool threw = false;
        try { ReadCompactSize(s); } catch (const std::ios_base::failure&) { threw = true; }
        Check("oversize cs throws", threw);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
