# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored post-quantum key-encapsulation mechanism (ML-KEM-768, FIPS 203),
# wired up by its own cmake/ module alongside cmake/ML-DSA-44.cmake. Used by the
# P2P v2 transport key agreement (crypto/mlkem.cpp -> v2cipher.cpp), where Core's
# BIP-324 uses secp256k1 ellswift ECDH — Lattica has no curve, so the shared
# secret comes from ML-KEM-768 instead. PQClean sources, built verbatim as C11.
#
# The scheme-specific files are namespaced PQCLEAN_MLKEM768_*, so they coexist
# with ML-DSA-44's same-named files (ntt/poly/polyvec/reduce) without symbol
# collision. ML-KEM-768 has no fips202.c / randombytes.c of its own: those
# PQClean common/ primitives are non-namespaced and are compiled once by the
# mldsa44 target, so mlkem768 links it to resolve them (PUBLIC, so dependents
# pulling in mlkem768 also get the shared SHA3/CSPRNG).
#
# Built before core_interface so the vendored C keeps its own build policy.
add_library(mlkem768 STATIC
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/cbd.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/indcpa.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/kem.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/ntt.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/poly.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/polyvec.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/reduce.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/symmetric-shake.c
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768/verify.c)
target_include_directories(mlkem768 PUBLIC
    ${PROJECT_SOURCE_DIR}/src/ML-KEM-768)
# fips202 (SHA3/SHAKE) + randombytes live in the mldsa44 target (PQClean common/).
target_link_libraries(mlkem768 PUBLIC mldsa44)
