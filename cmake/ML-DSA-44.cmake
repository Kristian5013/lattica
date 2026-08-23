# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored post-quantum signature scheme, wired up by its own cmake/ module —
# Lattica's analog of Bitcoin Core's cmake/secp256k1.cmake. Core links
# libsecp256k1 for its ECDSA/Schnorr consensus signatures; Lattica has no
# elliptic curve, so the consensus signature primitive is ML-DSA-44 (FIPS 204),
# verified in CHECKSIG (pubkey.cpp). PQClean sources, built verbatim as C11.
#
# This target also carries the two PQClean common/ primitives — fips202.c
# (SHA3/SHAKE) and randombytes.c — whose symbols are NOT scheme-namespaced and
# must therefore be compiled exactly once. They physically live under
# src/mldsa44/, so they are built here; the sibling ML-KEM-768 target
# (cmake/ML-KEM-768.cmake) links this one to reuse them. randombytes.c carries a
# small Lattica addition: a deterministic-seed mode for HD key derivation (the
# entropy seam, NOT the algorithm).
#
# Built before core_interface so the vendored C keeps its own build policy (no
# strict warnings / -UNDEBUG applied).
add_library(mldsa44 STATIC
    ${PROJECT_SOURCE_DIR}/src/mldsa44/fips202.c       # shared SHA3/SHAKE (PQClean common/)
    ${PROJECT_SOURCE_DIR}/src/mldsa44/randombytes.c   # shared CSPRNG  (PQClean common/)
    ${PROJECT_SOURCE_DIR}/src/mldsa44/ntt.c
    ${PROJECT_SOURCE_DIR}/src/mldsa44/packing.c
    ${PROJECT_SOURCE_DIR}/src/mldsa44/poly.c
    ${PROJECT_SOURCE_DIR}/src/mldsa44/polyvec.c
    ${PROJECT_SOURCE_DIR}/src/mldsa44/reduce.c
    ${PROJECT_SOURCE_DIR}/src/mldsa44/rounding.c
    ${PROJECT_SOURCE_DIR}/src/mldsa44/sign.c
    ${PROJECT_SOURCE_DIR}/src/mldsa44/symmetric-shake.c)
target_include_directories(mldsa44 PUBLIC
    ${PROJECT_SOURCE_DIR}/src/mldsa44)
