// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Correctness test for the v2 transport packet cipher (V2Cipher): two instances run the
// ML-KEM handshake, agree on a session id and crossed garbage terminators, and exchange
// encrypted packets in both directions. A tampered key-agreement message must fail to
// produce a working channel.

#include <v2cipher.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

std::vector<std::byte> Bytes(std::string_view s)
{
    std::vector<std::byte> v(s.size());
    for (size_t i = 0; i < s.size(); ++i) v[i] = std::byte(static_cast<uint8_t>(s[i]));
    return v;
}

template <typename A, typename B>
bool SpanEq(A&& a, B&& b)
{
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin());
}

// Encrypt `contents` on `from`, decrypt on `to`, and confirm it round-trips.
bool RoundTrip(V2Cipher& from, V2Cipher& to, std::span<const std::byte> contents)
{
    const std::span<const std::byte> aad{};
    std::vector<std::byte> packet(contents.size() + V2Cipher::EXPANSION);
    from.Encrypt(contents, aad, /*ignore=*/false, packet);

    const uint32_t len = to.DecryptLength(std::span<const std::byte>(packet).first(V2Cipher::LENGTH_LEN));
    if (len != contents.size()) return false;

    std::vector<std::byte> out(len);
    bool ignore = true;
    if (!to.Decrypt(std::span<const std::byte>(packet).subspan(V2Cipher::LENGTH_LEN), aad, ignore, out)) return false;
    if (ignore) return false;
    return SpanEq(out, contents);
}
} // namespace

int main()
{
    const std::array<std::byte, 4> magic{std::byte{0xf1}, std::byte{0xc0}, std::byte{0x0c}, std::byte{0x19}};

    // --- Successful handshake ---------------------------------------------------------
    V2Cipher initiator(/*initiator=*/true, magic);
    V2Cipher responder(/*initiator=*/false, magic);

    // Initiator's encapsulation key is ready immediately; responder's ciphertext is not.
    auto ek = initiator.GetOurKeyShare();
    Check("initiator key-share is the ML-KEM ek size", ek.size() == V2Cipher::EK_LEN);
    Check("responder has no key-share before Initialize", responder.GetOurKeyShare().empty());
    Check("ciphers not ready pre-handshake", !static_cast<bool>(initiator) && !static_cast<bool>(responder));

    // Responder encapsulates to the ek, producing its ciphertext + deriving keys.
    Check("responder Initialize(ek)", responder.Initialize(ek));
    auto ct = responder.GetOurKeyShare();
    Check("responder key-share is the ML-KEM ct size", ct.size() == V2Cipher::CT_LEN);
    Check("responder ready after Initialize", static_cast<bool>(responder));

    // Initiator decapsulates the ciphertext, deriving the matching keys.
    Check("initiator Initialize(ct)", initiator.Initialize(ct));
    Check("initiator ready after Initialize", static_cast<bool>(initiator));

    // Both sides must agree on the session id and cross on the garbage terminators.
    Check("session ids match", SpanEq(initiator.GetSessionID(), responder.GetSessionID()));
    Check("initiator send-term == responder recv-term",
          SpanEq(initiator.GetSendGarbageTerminator(), responder.GetReceiveGarbageTerminator()));
    Check("responder send-term == initiator recv-term",
          SpanEq(responder.GetSendGarbageTerminator(), initiator.GetReceiveGarbageTerminator()));
    Check("send/recv terminators differ", !SpanEq(initiator.GetSendGarbageTerminator(), initiator.GetReceiveGarbageTerminator()));

    // --- Encrypted packets both ways --------------------------------------------------
    const auto msg1 = Bytes("lattica v2 transport: initiator says hello");
    const auto msg2 = Bytes("and the responder replies over the post-quantum channel");
    Check("initiator -> responder round-trip", RoundTrip(initiator, responder, msg1));
    Check("responder -> initiator round-trip", RoundTrip(responder, initiator, msg2));

    // A second packet keeps the stateful (rekeying) ciphers in sync.
    const auto msg3 = Bytes("second packet stays in sync");
    Check("initiator -> responder second packet", RoundTrip(initiator, responder, msg3));

    // Empty-payload packet (decoy-sized) still round-trips.
    Check("empty payload round-trip", RoundTrip(responder, initiator, std::span<const std::byte>{}));

    // --- Negative: independent handshakes must not share keys --------------------------
    {
        V2Cipher a(true, magic), b(false, magic);
        Check("b Initialize", b.Initialize(a.GetOurKeyShare()));
        Check("a Initialize", a.Initialize(b.GetOurKeyShare()));
        Check("independent session differs from the first", !SpanEq(a.GetSessionID(), initiator.GetSessionID()));
    }

    // --- Negative: a tampered ciphertext breaks the handshake -------------------------
    {
        V2Cipher a(true, magic), b(false, magic);
        Check("b Initialize (tamper case)", b.Initialize(a.GetOurKeyShare()));
        std::vector<std::byte> bad_ct(b.GetOurKeyShare().begin(), b.GetOurKeyShare().end());
        bad_ct[0] ^= std::byte{0xff};
        // ML-KEM implicit rejection: decapsulation still "succeeds" but yields a different
        // secret, so a derives keys that don't match b's — the channel must not work.
        Check("a Initialize (tampered ct accepted by KEM)", a.Initialize(bad_ct));
        Check("tampered handshake -> session ids DON'T match", !SpanEq(a.GetSessionID(), b.GetSessionID()));
        Check("tampered handshake -> packet does NOT decrypt", !RoundTrip(a, b, Bytes("should fail")));
    }

    // --- Negative: wrong-size key-agreement message rejected --------------------------
    {
        V2Cipher r(false, magic);
        std::array<std::byte, 10> too_small{};
        Check("responder rejects mis-sized ek", !r.Initialize(too_small));

        // The initiator's failure path (mis-sized ciphertext) is where the decapsulation key gets
        // wiped early; exercise it and confirm the cipher stays unusable.
        V2Cipher i(true, magic);
        Check("initiator rejects mis-sized ct", !i.Initialize(too_small));
        Check("initiator not ready after failed Initialize", !static_cast<bool>(i));
    }

    // An initiator that is destroyed without ever completing the handshake (the aborted-handshake
    // case the destructor cleanse targets) must not crash.
    {
        V2Cipher abandoned(true, magic);
        (void)abandoned.GetOurKeyShare();
        Check("initiator destructs cleanly without Initialize", true);
    }

    std::printf(g_fail ? "\nFAILED (%d)\n" : "\nOK\n", g_fail);
    return g_fail ? 1 : 0;
}
