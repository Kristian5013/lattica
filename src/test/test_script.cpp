// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// script/script.h (CScript, CScriptNum, CScriptID) tests.
// Standalone for now (own main); folds into the test framework when it lands.

#include <crypto/hex_base.h>
#include <hash.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <span>
#include <string>
#include <vector>

namespace {

std::string SHex(const CScript& s)
{
    return HexStr(std::span<const uint8_t>(s.data(), s.size()));
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
};

int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

} // namespace

int main()
{
    // Opcode building.
    Check("opcodes", SHex(CScript() << OP_DUP << OP_HASH160 << OP_EQUAL) == "76a987");

    // Small integers become OP_0 / OP_1..OP_16 / OP_1NEGATE.
    Check("small ints", SHex(CScript() << 0 << 1 << 16 << -1) == "00" "51" "60" "4f");

    // Direct data push (<= 75 bytes uses the length byte as opcode).
    Check("data push", SHex(CScript() << std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}) == "04deadbeef");

    // << int64 and << CScriptNum push the same encoding for big numbers.
    {
        CScript x; x << int64_t{1000};
        CScript y; y << CScriptNum(1000);
        Check("<<int == <<CScriptNum", x == y && SHex(x) == "02e803"); // 1000 = 0x03e8 LE
    }

    // CScriptNum value + minimal-encoding round-trip.
    {
        bool ok = true;
        for (int64_t n : {int64_t{0}, int64_t{1}, int64_t{-1}, int64_t{16}, int64_t{127},
                          int64_t{128}, int64_t{-128}, int64_t{1000}, int64_t{-1000},
                          int64_t{0x7fffffff}, int64_t{-0x7fffffff}}) {
            if (CScriptNum(n).GetInt64() != n) ok = false;
            auto vch = CScriptNum(n).getvch();
            if (CScriptNum(vch, /*fRequireMinimal=*/true).GetInt64() != n) ok = false;
        }
        Check("CScriptNum round-trip", ok);
    }

    // GetOp walks opcodes and push data.
    {
        CScript s;
        s << OP_DUP << std::vector<uint8_t>{0x01, 0x02, 0x03} << OP_EQUAL;
        CScript::const_iterator pc = s.begin();
        opcodetype op;
        std::vector<unsigned char> data;
        bool ok = true;
        ok = ok && s.GetOp(pc, op, data) && op == OP_DUP && data.empty();
        ok = ok && s.GetOp(pc, op, data) && op == static_cast<opcodetype>(3) &&
             data == std::vector<unsigned char>{0x01, 0x02, 0x03};
        ok = ok && s.GetOp(pc, op, data) && op == OP_EQUAL;
        ok = ok && !s.GetOp(pc, op, data); // end
        Check("GetOp iteration", ok);
    }

    // Serialization round-trip (CScript serializes as a length-prefixed byte blob).
    {
        CScript s;
        s << OP_1 << std::vector<uint8_t>{0xaa, 0xbb} << OP_CHECKSIG;
        TestStream ss;
        Serialize(ss, s);
        CScript s2;
        Unserialize(ss, s2);
        Check("script serialize round-trip", s == s2 && ss.pos == ss.buf.size());
    }

    // CScriptID = Hash160(script) = RIPEMD160(SHA3-256(script)).
    {
        CScript s;
        s << OP_1 << OP_2 << OP_ADD;
        CScriptID id(s);
        Check("CScriptID == Hash160(script)", id == CScriptID(Hash160(s)));
    }

    // P2SH pattern detection.
    {
        CScript p2sh;
        p2sh << OP_HASH160 << std::vector<uint8_t>(20, 0xab) << OP_EQUAL;
        Check("IsPayToScriptHash true", p2sh.IsPayToScriptHash());
        CScript not_p2sh;
        not_p2sh << OP_1;
        Check("IsPayToScriptHash false", !not_p2sh.IsPayToScriptHash());
    }

    // IsPushOnly.
    {
        CScript pushonly;
        pushonly << std::vector<uint8_t>{1, 2} << OP_5;
        Check("IsPushOnly true", pushonly.IsPushOnly());
        CScript notpush;
        notpush << OP_DUP;
        Check("IsPushOnly false", !notpush.IsPushOnly());
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
