// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <v2cipher.h>

#include <crypto/chacha20.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/mlkem.h>
#include <crypto/sha3.h>
#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace {

/** Transcript-binding SHA3-256 KDF: out = SHA3-256(SS ‖ ek ‖ ct ‖ magic ‖ tag).
 *  Folding the full handshake transcript (ek, ct) and the chain magic into every key
 *  means a tampered or cross-chain handshake produces non-matching keys, and the tag
 *  domain-separates the individual outputs. */
std::array<std::byte, 32> Kdf(std::span<const std::byte> ss,
                              std::span<const std::byte> ek,
                              std::span<const std::byte> ct,
                              std::span<const std::byte> magic,
                              std::string_view tag) noexcept
{
    auto uc = [](std::span<const std::byte> s) {
        return std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size());
    };
    unsigned char out[32];
    SHA3_256().Write(uc(ss)).Write(uc(ek)).Write(uc(ct)).Write(uc(magic))
        .Write({reinterpret_cast<const unsigned char*>(tag.data()), tag.size()})
        .Finalize(out);
    std::array<std::byte, 32> ret;
    std::memcpy(ret.data(), out, sizeof(out));
    return ret;
}

} // namespace

V2Cipher::V2Cipher(bool initiator, std::span<const std::byte> network_magic) noexcept
    : m_initiating{initiator}
{
    assert(network_magic.size() == m_network_magic.size());
    std::memcpy(m_network_magic.data(), network_magic.data(), m_network_magic.size());

    if (m_initiating) {
        // Generate the ephemeral ML-KEM keypair; the encapsulation key is what we send.
        std::array<uint8_t, mlkem::PUBLICKEY_SIZE> ek{};
        const bool ok = mlkem::Keypair(ek, m_decap_key);
        assert(ok);
        m_our_keyshare.resize(EK_LEN);
        std::memcpy(m_our_keyshare.data(), ek.data(), EK_LEN);
    }
}

V2Cipher::~V2Cipher() noexcept
{
    // Backstop for the ephemeral decapsulation key on any lifetime that doesn't run a successful
    // Initialize() to completion (aborted/failed handshake). For the responder it was never
    // populated, so this is a no-op there.
    memory_cleanse(m_decap_key.data(), m_decap_key.size());
}

bool V2Cipher::Initialize(std::span<const std::byte> their_msg) noexcept
{
    if (static_cast<bool>(*this)) return false; // already initialized

    std::array<uint8_t, mlkem::SHARED_SECRET_SIZE> ss{};
    std::array<std::byte, mlkem::SHARED_SECRET_SIZE> ss_bytes{};

    if (m_initiating) {
        // their_msg is the responder's ciphertext; decapsulate with our secret key. Wipe the
        // decapsulation key on every exit (it is no longer needed once decapsulation is attempted,
        // and must not linger on the failure paths).
        if (their_msg.size() != CT_LEN) {
            memory_cleanse(m_decap_key.data(), m_decap_key.size());
            return false;
        }
        std::array<uint8_t, mlkem::CIPHERTEXT_SIZE> ct{};
        std::memcpy(ct.data(), their_msg.data(), CT_LEN);
        const bool decapsulated = mlkem::Decapsulate(ss, ct, m_decap_key);
        memory_cleanse(m_decap_key.data(), m_decap_key.size());
        if (!decapsulated) return false;
        std::memcpy(ss_bytes.data(), ss.data(), ss.size());
        DeriveKeys(ss_bytes, m_our_keyshare, their_msg);
    } else {
        // their_msg is the initiator's encapsulation key; encapsulate to it. The resulting
        // ciphertext becomes our key-agreement message to send.
        if (their_msg.size() != EK_LEN) return false;
        std::array<uint8_t, mlkem::PUBLICKEY_SIZE> ek{};
        std::memcpy(ek.data(), their_msg.data(), EK_LEN);
        std::array<uint8_t, mlkem::CIPHERTEXT_SIZE> ct{};
        if (!mlkem::Encapsulate(ct, ss, ek)) return false;
        m_our_keyshare.resize(CT_LEN);
        std::memcpy(m_our_keyshare.data(), ct.data(), CT_LEN);
        std::memcpy(ss_bytes.data(), ss.data(), ss.size());
        DeriveKeys(ss_bytes, their_msg, m_our_keyshare);
    }

    // Wipe everything that could re-derive the session keys.
    memory_cleanse(ss.data(), ss.size());
    memory_cleanse(ss_bytes.data(), ss_bytes.size());
    memory_cleanse(m_decap_key.data(), m_decap_key.size());
    return true;
}

void V2Cipher::DeriveKeys(std::span<const std::byte> ss,
                          std::span<const std::byte> ek,
                          std::span<const std::byte> ct) noexcept
{
    const std::span<const std::byte> magic{m_network_magic};

    // initiator_* is the initiator->responder direction, responder_* the reverse. Each
    // side maps those onto its own send/recv pair by role.
    const bool side = m_initiating;
    auto k_il = Kdf(ss, ek, ct, magic, "initiator_L");
    auto k_ip = Kdf(ss, ek, ct, magic, "initiator_P");
    auto k_rl = Kdf(ss, ek, ct, magic, "responder_L");
    auto k_rp = Kdf(ss, ek, ct, magic, "responder_P");
    (side ? m_send_l_cipher : m_recv_l_cipher).emplace(k_il, REKEY_INTERVAL);
    (side ? m_send_p_cipher : m_recv_p_cipher).emplace(k_ip, REKEY_INTERVAL);
    (side ? m_recv_l_cipher : m_send_l_cipher).emplace(k_rl, REKEY_INTERVAL);
    (side ? m_recv_p_cipher : m_send_p_cipher).emplace(k_rp, REKEY_INTERVAL);

    // Two garbage terminators packed into one 32-byte derivation, split like BIP324:
    // the initiator sends the first half and expects the second.
    auto gt = Kdf(ss, ek, ct, magic, "garbage_terminators");
    std::copy(gt.begin(), gt.begin() + GARBAGE_TERMINATOR_LEN,
              (m_initiating ? m_send_garbage_terminator : m_recv_garbage_terminator).begin());
    std::copy(gt.end() - GARBAGE_TERMINATOR_LEN, gt.end(),
              (m_initiating ? m_recv_garbage_terminator : m_send_garbage_terminator).begin());

    m_session_id = Kdf(ss, ek, ct, magic, "session_id");

    memory_cleanse(k_il.data(), k_il.size());
    memory_cleanse(k_ip.data(), k_ip.size());
    memory_cleanse(k_rl.data(), k_rl.size());
    memory_cleanse(k_rp.data(), k_rp.size());
    memory_cleanse(gt.data(), gt.size());
}

void V2Cipher::Encrypt(std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore, std::span<std::byte> output) noexcept
{
    assert(output.size() == contents.size() + EXPANSION);

    // Encrypt length.
    std::byte len[LENGTH_LEN];
    len[0] = std::byte{(uint8_t)(contents.size() & 0xFF)};
    len[1] = std::byte{(uint8_t)((contents.size() >> 8) & 0xFF)};
    len[2] = std::byte{(uint8_t)((contents.size() >> 16) & 0xFF)};
    len[3] = std::byte{(uint8_t)((contents.size() >> 24) & 0xFF)};
    m_send_l_cipher->Crypt(len, output.first(LENGTH_LEN));

    // Encrypt plaintext.
    std::byte header[HEADER_LEN] = {ignore ? IGNORE_BIT : std::byte{0}};
    m_send_p_cipher->Encrypt(header, contents, aad, output.subspan(LENGTH_LEN));
}

uint32_t V2Cipher::DecryptLength(std::span<const std::byte> input) noexcept
{
    assert(input.size() == LENGTH_LEN);

    std::byte buf[LENGTH_LEN];
    // Decrypt length
    m_recv_l_cipher->Crypt(input, buf);
    // Convert to number.
    return uint32_t(buf[0]) + (uint32_t(buf[1]) << 8) + (uint32_t(buf[2]) << 16) + (uint32_t(buf[3]) << 24);
}

bool V2Cipher::Decrypt(std::span<const std::byte> input, std::span<const std::byte> aad, bool& ignore, std::span<std::byte> contents) noexcept
{
    assert(input.size() + LENGTH_LEN == contents.size() + EXPANSION);

    std::byte header[HEADER_LEN];
    if (!m_recv_p_cipher->Decrypt(input, aad, header, contents)) return false;

    ignore = (header[0] & IGNORE_BIT) == IGNORE_BIT;
    return true;
}
