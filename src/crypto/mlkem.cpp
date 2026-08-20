// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <crypto/mlkem.h>

// The PQClean ML-KEM-768 entry points. Declared here rather than via the vendored
// api.h because the ML-DSA-44 and ML-KEM-768 clean trees each ship an "api.h" on the
// shared include path; declaring the symbols directly avoids the ambiguity. The
// definitions live in the mldsa44 (PQClean) static library.
extern "C" {
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t* pk, uint8_t* sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);
}

namespace mlkem {

bool Keypair(std::span<uint8_t> pk, std::span<uint8_t> sk)
{
    if (pk.size() != PUBLICKEY_SIZE || sk.size() != SECRETKEY_SIZE) return false;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk.data(), sk.data()) == 0;
}

bool Encapsulate(std::span<uint8_t> ct, std::span<uint8_t> ss, std::span<const uint8_t> pk)
{
    if (ct.size() != CIPHERTEXT_SIZE || ss.size() != SHARED_SECRET_SIZE || pk.size() != PUBLICKEY_SIZE) return false;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct.data(), ss.data(), pk.data()) == 0;
}

bool Decapsulate(std::span<uint8_t> ss, std::span<const uint8_t> ct, std::span<const uint8_t> sk)
{
    if (ss.size() != SHARED_SECRET_SIZE || ct.size() != CIPHERTEXT_SIZE || sk.size() != SECRETKEY_SIZE) return false;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss.data(), ct.data(), sk.data()) == 0;
}

} // namespace mlkem
