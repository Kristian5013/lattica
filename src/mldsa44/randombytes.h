#ifndef PQCLEAN_RANDOMBYTES_H
#define PQCLEAN_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifdef _WIN32
/* Load size_t on windows */
#include <crtdefs.h>
#else
#include <unistd.h>
#endif /* _WIN32 */

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
#define randombytes     PQCLEAN_randombytes
int randombytes(uint8_t *output, size_t n);

/* ----- Lattica addition (entropy seam, NOT a cryptographic file) ----------
 * Deterministic-seed control for hierarchical-deterministic key derivation.
 * Between set and clear, randombytes() yields a SHAKE256 stream from the 32-byte
 * seed instead of OS entropy, making one keypair generation reproducible (FIPS
 * 204 KeyGen's only randomness is that single 32-byte draw). Thread-local; the
 * cryptographic files in this directory remain byte-for-byte verbatim. */
void mldsa_set_deterministic_seed(const uint8_t seed[32]);
void mldsa_clear_deterministic_seed(void);

#ifdef __cplusplus
}
#endif

#endif /* PQCLEAN_RANDOMBYTES_H */
