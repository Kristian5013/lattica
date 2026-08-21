# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored libsecp256k1, like Bitcoin Core. Signature verification is consensus
# code, so it must not depend on whichever version a distribution happens to
# ship: two nodes built against different copies could disagree about whether a
# signature is valid. Core moved off system OpenSSL for exactly this reason.
#
# Pinned to upstream release v0.8.0, commit
# 6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d (3 Aug 2026). Refresh by replacing
# src/secp256k1 wholesale rather than patching in place, so the diff against
# upstream stays empty and a new release drops in cleanly.
#
# schnorrsig and extrakeys are on: Taproot needs BIP-340 signing and
# verification and the x-only key type they provide. The rest stay off — musig
# has no caller, ellswift belongs to BIP324 whereas this transport is ML-KEM-768
# (see v2cipher.h), and ecdh, recovery and silentpayments are unused.
set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SILENTPAYMENTS OFF CACHE BOOL "" FORCE)

# Upstream's own test binary is kept and registered with ctest: it is the only
# thing that establishes the vendored copy is intact and correctly configured,
# and it runs in seconds. The exhaustive and constant-time (Valgrind) suites and
# the benchmarks are not part of an ordinary build.
set(SECP256K1_BUILD_TESTS ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/secp256k1)
