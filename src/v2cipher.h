// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_V2CIPHER_H
#define LATTICA_V2CIPHER_H

#include <crypto/chacha20.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/mlkem.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

/** How many of BIP324's short message ids this codebase implements.
 *
 *  The short-id table is part of the packet framing, which follows BIP324 even
 *  though the key agreement does not; Core keeps this constant in bip324.h,
 *  which has no counterpart here. */
inline constexpr unsigned V2_SHORTIDS_IMPLEMENTED{38};

/** The Lattica v2 transport packet cipher: a post-quantum analog of BIP324.
 *
 * Key agreement is ML-KEM-768 — the initiator ships an ephemeral encapsulation key,
 * the responder encapsulates to it, both end up with the same shared secret. The four
 * session keys, the two garbage terminators, and the session id are derived from that
 * shared secret with a transcript-binding SHA3-256 KDF (the full ek and ct go into
 * every derivation, so a tampered handshake yields mismatched keys). The packet stream
 * itself is the same length-prefixed FSChaCha20 + FSChaCha20Poly1305 framing BIP324
 * uses, with one deliberate divergence: the length descriptor is 4 bytes rather than 3,
 * so that a full 32 MB block fits in a single packet (see LENGTH_LEN).
 *
 * The handshake is opportunistic and unauthenticated: it gives confidentiality and
 * forward secrecy against a passive adversary, not protection against an active MITM
 * (mutual authentication via an ML-DSA identity key is a future extension).
 */
class V2Cipher
{
public:
    // Packet-framing parameters (identical to BIP324).
    static constexpr unsigned SESSION_ID_LEN{32};
    static constexpr unsigned GARBAGE_TERMINATOR_LEN{16};
    static constexpr unsigned REKEY_INTERVAL{224};
    /** Width of the packet length descriptor.
     *
     * BIP324 uses 3 bytes, which caps a packet at 2^24-1 (~16.7 MB) — enough for Bitcoin,
     * where a block never exceeds 4 MB. Lattica has no witness discount, so a block runs to
     * MAX_BLOCK_SERIALIZED_SIZE (32 MB) and would not fit: Encrypt() would silently truncate
     * the length and desynchronise the peer's framing. The descriptor is therefore 4 bytes.
     * This is a wire-format divergence from BIP324 — v2 peers must agree on it. */
    static constexpr unsigned LENGTH_LEN{4};
    static constexpr unsigned HEADER_LEN{1};
    static constexpr unsigned EXPANSION = LENGTH_LEN + HEADER_LEN + FSChaCha20Poly1305::EXPANSION;
    static constexpr std::byte IGNORE_BIT{0x80};

    /** Key-agreement message sizes. The initiator sends an ML-KEM encapsulation key,
     *  the responder replies with an ML-KEM ciphertext. */
    static constexpr unsigned EK_LEN = mlkem::PUBLICKEY_SIZE;   // 1184, initiator -> responder
    static constexpr unsigned CT_LEN = mlkem::CIPHERTEXT_SIZE;  // 1088, responder -> initiator

private:
    std::optional<FSChaCha20> m_send_l_cipher;
    std::optional<FSChaCha20> m_recv_l_cipher;
    std::optional<FSChaCha20Poly1305> m_send_p_cipher;
    std::optional<FSChaCha20Poly1305> m_recv_p_cipher;

    const bool m_initiating;
    /** Network magic, mixed into the KDF so a handshake can't cross chains. */
    std::array<std::byte, 4> m_network_magic;

    /** Our key-agreement message to send: the encapsulation key (initiator, ready at
     *  construction) or the ciphertext (responder, produced in Initialize()). */
    std::vector<std::byte> m_our_keyshare;
    /** The initiator's ML-KEM decapsulation key, held until Initialize() consumes it. */
    std::array<uint8_t, mlkem::SECRETKEY_SIZE> m_decap_key{};

    std::array<std::byte, SESSION_ID_LEN> m_session_id;
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_send_garbage_terminator;
    std::array<std::byte, GARBAGE_TERMINATOR_LEN> m_recv_garbage_terminator;

    /** Derive the four stream-cipher keys, both garbage terminators, and the session id
     *  from the ML-KEM shared secret and the full handshake transcript (ek then ct). */
    void DeriveKeys(std::span<const std::byte> shared_secret,
                    std::span<const std::byte> ek,
                    std::span<const std::byte> ct) noexcept;

public:
    V2Cipher() = delete;

    /** Construct a v2 cipher. The initiator generates an ephemeral ML-KEM keypair, whose
     *  encapsulation key becomes the key-agreement message to send. network_magic must be
     *  4 bytes (the chain's message-start bytes); it domain-separates the KDF per chain. */
    V2Cipher(bool initiator, std::span<const std::byte> network_magic) noexcept;

    /** Cleanses the ephemeral ML-KEM decapsulation key. This is the one secret whose lifetime can
     *  exceed a completed Initialize() -- on an aborted handshake (no ciphertext ever arrives) the
     *  cipher is destroyed without Initialize(), and on a failed Initialize() it returns early --
     *  so the wipe is anchored in the destructor as well as on every Initialize() path. */
    ~V2Cipher() noexcept;

    /** Our key-agreement message: the encapsulation key (initiator, available now) or the
     *  ciphertext (responder, available only after Initialize()). */
    std::span<const std::byte> GetOurKeyShare() const noexcept { return m_our_keyshare; }

    /** Complete key agreement from the peer's key-agreement message. Call once.
     *   - initiator: their_msg is the responder's ciphertext (CT_LEN) -> decapsulate.
     *   - responder: their_msg is the initiator's encapsulation key (EK_LEN) -> encapsulate;
     *                the resulting ciphertext becomes GetOurKeyShare().
     *  Returns false if their_msg has the wrong size or the KEM operation fails. */
    bool Initialize(std::span<const std::byte> their_msg) noexcept;

    /** Whether key agreement has completed and the ciphers are ready. */
    explicit operator bool() const noexcept { return m_send_l_cipher.has_value(); }

    // The packet stream below is byte-for-byte the BIP324 framing.

    /** Encrypt a packet. Only after Initialize(). output.size() == contents.size() + EXPANSION. */
    void Encrypt(std::span<const std::byte> contents, std::span<const std::byte> aad, bool ignore, std::span<std::byte> output) noexcept;

    /** Decrypt the length of a packet. Only after Initialize(). input.size() == LENGTH_LEN. */
    uint32_t DecryptLength(std::span<const std::byte> input) noexcept;

    /** Decrypt a packet. Only after Initialize().
     *  input.size() + LENGTH_LEN == contents.size() + EXPANSION, and contents.size() must
     *  equal the length returned by DecryptLength. */
    bool Decrypt(std::span<const std::byte> input, std::span<const std::byte> aad, bool& ignore, std::span<std::byte> contents) noexcept;

    /** Get the Session ID. Only after Initialize(). */
    std::span<const std::byte> GetSessionID() const noexcept { return m_session_id; }

    /** Get the Garbage Terminator to send. Only after Initialize(). */
    std::span<const std::byte> GetSendGarbageTerminator() const noexcept { return m_send_garbage_terminator; }

    /** Get the expected Garbage Terminator to receive. Only after Initialize(). */
    std::span<const std::byte> GetReceiveGarbageTerminator() const noexcept { return m_recv_garbage_terminator; }
};

#endif // LATTICA_V2CIPHER_H
