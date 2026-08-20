// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <pubkey.h>

#include <secp256k1.h>

extern "C" {
#include "api.h"

// Falcon-512 (PQClean falcon-padded-512). Declared rather than included, for
// the reason crypto/mlkem.cpp gives: three PQClean trees ship an "api.h".
int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
    const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
}

#include <cstddef>
#include <cstdint>
#include <span>

std::optional<SigScheme> SchemeFromPubKeySize(size_t len)
{
    if (len == 0) return std::nullopt;
    for (const SigScheme s : ALL_SIG_SCHEMES) {
        if (SchemePublicKeySize(s) == len) return s;
    }
    return std::nullopt;
}

bool IsKnownScheme(SigScheme s)
{
    switch (s) {
        case SigScheme::ML_DSA_44:
        case SigScheme::FALCON_512:
        case SigScheme::SECP256K1:
            return true;
    }
    return false;
}

size_t SchemePublicKeySize(SigScheme s)
{
    switch (s) {
        case SigScheme::ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES;
        case SigScheme::FALCON_512:
            return 897;
        case SigScheme::SECP256K1:
            // Compressed SEC only. An uncompressed (65-byte) form cannot exist:
            // GetLen() maps one scheme tag to exactly one length.
            return 33;
    }
    return 0;
}

size_t SchemeSignatureSize(SigScheme s)
{
    switch (s) {
        case SigScheme::ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES;
        case SigScheme::FALCON_512:
            // PQClean's falcon-PADDED-512: always exactly this, where plain
            // falcon-512 would be variable up to 752. See cmake/FALCON-512.cmake.
            return 666;
        case SigScheme::SECP256K1:
            // Fixed 64-byte compact (r||s), not DER. The script engine implements no
            // signature-encoding rules, and a fixed length keeps the whole BIP66
            // class of parser-disagreement bugs out of consensus. Low-S is
            // mandatory, so the encoding is unique per (key, message, nonce).
            return 64;
    }
    return 0;
}

size_t SchemeSecretKeySize(SigScheme s)
{
    switch (s) {
        case SigScheme::ML_DSA_44:
            return PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES;
        case SigScheme::FALCON_512:
            return 1281;
        case SigScheme::SECP256K1:
            return 32;
    }
    return 0;
}

int64_t SchemeSigOpCost(SigScheme s)
{
    switch (s) {
        case SigScheme::ML_DSA_44:
            return 1;
        case SigScheme::FALCON_512:
        case SigScheme::SECP256K1:
            // Provisional: ML-DSA-44 is the unit and an ECDSA verify is of the same
            // order. Worth measuring before this counter is actually wired into
            // block validation, where the ratio becomes consensus.
            return 1;
    }
    return 0;  // unknown scheme: contributes nothing (rejected without a verify)
}

bool CPubKey::Verify(const uint256& hash, std::span<const unsigned char> sig) const
{
    if (!IsValid())
        return false;
    switch (GetScheme()) {
        case SigScheme::ML_DSA_44:
            // PQClean enforces the exact signature length internally and returns
            // 0 on a valid signature; the public-key length is gated by IsValid()
            // (GetLen() requires the scheme's exact 1312-byte key, as the
            // conformance suite requires).
            return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
                       sig.data(), sig.size(), hash.begin(), hash.size(), data()) == 0;
        case SigScheme::FALCON_512:
            // PQClean checks the length itself and returns 0 on a valid
            // signature. The padded variant accepts only its own fixed length,
            // which the vendored-library test pins.
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(
                       sig.data(), sig.size(), hash.begin(), hash.size(), data()) == 0;
        case SigScheme::SECP256K1: {
            // Verification only, so the static context is enough — no global
            // signing context is needed anywhere in consensus code.
            if (sig.size() != SchemeSignatureSize(SigScheme::SECP256K1)) return false;
            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey,
                                           data(), size())) {
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
