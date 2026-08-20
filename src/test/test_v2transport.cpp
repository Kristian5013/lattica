// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// End-to-end test of the V2Transport state machine over the post-quantum (ML-KEM) handshake.
// Two transports are driven against each other byte-for-byte: the initiator sends its
// encapsulation key, the responder (which cannot reply until it has the full key) encapsulates
// and sends its ciphertext, both derive the session, exchange the garbage-terminator + version
// packets, and then carry encrypted application messages in both directions. This exercises the
// reactive-responder flow that diverges from BIP324 — the part that only compiling can't prove.

#include <net.h>

#include <chainparams.h>
#include <node/connection_types.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <util/translation.h>

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

// The translation hook is provided by the application; a node-less test binary supplies a null one.
const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

// Move every byte currently queued on `from` into `to`, marking it sent. Returns false if the
// receiver rejects the bytes (a broken transport).
bool Pump(Transport& from, Transport& to)
{
    while (true) {
        const auto [to_send, more, msg_type] = from.GetBytesToSend(false);
        if (to_send.empty()) break;
        std::span<const uint8_t> bytes = to_send;
        const size_t before = bytes.size();
        if (!to.ReceivedBytes(bytes)) return false;
        const size_t consumed = before - bytes.size();
        if (consumed == 0) break; // receiver can't currently take more
        from.MarkBytesSent(consumed);
    }
    return true;
}

// Run a full handshake exchange to completion (idempotent extra rounds are harmless).
bool Handshake(Transport& a, Transport& b)
{
    for (int round = 0; round < 4; ++round) {
        if (!Pump(a, b)) return false;
        if (!Pump(b, a)) return false;
    }
    return true;
}

// Send one application message `from` -> `to` and return the decoded message.
bool SendMessage(Transport& from, Transport& to, const std::string& type,
                 const std::vector<uint8_t>& payload, std::string& out_type, std::vector<uint8_t>& out_payload)
{
    CSerializedNetMsg msg;
    msg.m_type = type;
    msg.data = payload;
    if (!from.SetMessageToSend(msg)) return false;
    if (!Pump(from, to)) return false;
    if (!to.ReceivedMessageComplete()) return false;
    bool reject = false;
    CNetMessage got = to.GetReceivedMessage(NodeClock::time_point{}, reject);
    if (reject) return false;
    out_type = got.m_type;
    out_payload.assign(reinterpret_cast<const uint8_t*>(got.m_recv.data()),
                       reinterpret_cast<const uint8_t*>(got.m_recv.data()) + got.m_recv.size());
    return true;
}
} // namespace

int main()
{
    // V2Transport's constructor reads Params().MessageStart() to domain-separate the handshake.
    SelectParams(ChainType::REGTEST);

    // Initiator and responder, both with empty injected garbage (deterministic handshake).
    V2Transport initiator(/*nodeid=*/1, /*initiating=*/true, /*garbage=*/{});
    V2Transport responder(/*nodeid=*/2, /*initiating=*/false, /*garbage=*/{});

    Check("handshake pumps without error", Handshake(initiator, responder));

    const auto i_info = initiator.GetInfo();
    const auto r_info = responder.GetInfo();
    Check("initiator negotiated v2", i_info.transport_type == TransportProtocolType::V2);
    Check("responder negotiated v2", r_info.transport_type == TransportProtocolType::V2);
    Check("initiator has a session id", i_info.session_id.has_value());
    Check("responder has a session id", r_info.session_id.has_value());
    Check("session ids match", i_info.session_id == r_info.session_id);

    // Application message initiator -> responder.
    {
        const std::vector<uint8_t> payload{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};
        std::string type; std::vector<uint8_t> got;
        Check("initiator->responder send", SendMessage(initiator, responder, "ping", payload, type, got));
        Check("responder got type ping", type == "ping");
        Check("responder got payload", got == payload);
    }

    // Application message responder -> initiator (different type + size, exercises both directions).
    {
        const std::vector<uint8_t> payload{0xaa, 0xbb, 0xcc};
        std::string type; std::vector<uint8_t> got;
        Check("responder->initiator send", SendMessage(responder, initiator, "pong", payload, type, got));
        Check("initiator got type pong", type == "pong");
        Check("initiator got payload", got == payload);
    }

    // A second message the same way keeps the rekeying packet ciphers in sync.
    {
        const std::vector<uint8_t> payload(100, 0x5a);
        std::string type; std::vector<uint8_t> got;
        Check("initiator->responder second send", SendMessage(initiator, responder, "ping", payload, type, got));
        Check("responder got second payload", got == payload);
    }

    std::printf(g_fail ? "\nFAILED (%d)\n" : "\nOK\n", g_fail);
    return g_fail ? 1 : 0;
}
