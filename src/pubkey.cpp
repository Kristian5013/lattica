// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <pubkey.h>

#include <secp256k1.h>

extern "C" {
// ML-DSA-44 (PQClean). Reached through the vendored api.h, which is the one on
// this target's include path.
#include "api.h"

// Falcon-512 (PQClean falcon-padded-512). Declared rather than included, for
// the reason crypto/mlkem.cpp gives: three PQClean trees ship an "api.h", so a
// quoted include would resolve by link order.
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
    const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
}

#include <cstddef>
#include <cstdint>
#include <span>

// The vendored constants and the ones this class advertises must agree, or a
// key would be accepted at one length and verified at another.
static_assert(CPubKey::MLDSA44_SIZE == PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
              "ML-DSA-44 public key size disagrees with the vendored library");
static_assert(CPubKey::MLDSA44_SIGNATURE_SIZE == PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
              "ML-DSA-44 signature size disagrees with the vendored library");

unsigned int CPubKey::SignatureSize() const
{
    switch (size()) {
    case SECP256K1_SIZE: return SECP256K1_SIGNATURE_SIZE;
    case FALCON512_SIZE: return FALCON512_SIGNATURE_SIZE;
    case MLDSA44_SIZE:   return MLDSA44_SIGNATURE_SIZE;
    }
    return 0;
}

bool CPubKey::IsFullyValid() const
{
    switch (size()) {
    case SECP256K1_SIZE: {
        // The complete check: the bytes must decode to a point on the curve.
        secp256k1_pubkey pubkey;
        return secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, data(), size()) == 1;
    }
    case FALCON512_SIZE:
        // As far as the public API goes. The header byte carries the degree as
        // 0x00 | logn, so n = 512 is 0x09; whether every coefficient is below q
        // is decided by PQClean's decoder, which is not exposed.
        return data()[0] == 0x09;
    case MLDSA44_SIZE:
        // Any MLDSA44_SIZE bytes unpack to some (rho, t1), so the length is the
        // whole of the check and it has already been made.
        return true;
    }
    return false;
}

bool CPubKey::Verify(const uint256& hash, std::span<const unsigned char> sig) const
{
    switch (size()) {
    case MLDSA44_SIZE:
        // PQClean enforces the exact signature length internally and returns 0
        // on a valid signature.
        return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
                   sig.data(), sig.size(), hash.begin(), hash.size(), data()) == 0;
    case FALCON512_SIZE:
        // Likewise, and the padded variant accepts only its own fixed length —
        // which the vendored-library test pins.
        return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                   sig.data(), sig.size(), hash.begin(), hash.size(), data()) == 0;
    case SECP256K1_SIZE: {
        // Verification only, so the static context is enough: no global signing
        // context is needed anywhere in consensus code.
        if (sig.size() != SECP256K1_SIGNATURE_SIZE) return false;
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, data(), size())) {
            return false;
        }
        secp256k1_ecdsa_signature parsed;
        if (!secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, &parsed, sig.data())) {
            return false;
        }
        // Low-S is mandatory: normalize() reports whether it had to change the
        // signature, and a high-S one is rejected rather than fixed up. That
        // makes the 64 bytes a unique encoding and kills third-party
        // malleability of the txid.
        if (secp256k1_ecdsa_signature_normalize(secp256k1_context_static, nullptr, &parsed)) {
            return false;
        }
        return secp256k1_ecdsa_verify(secp256k1_context_static, &parsed, hash.begin(), &pubkey) == 1;
    }
    }
    return false;
}
