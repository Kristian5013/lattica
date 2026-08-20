# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored Falcon-512, the second post-quantum signature scheme, wired up by its
# own cmake/ module alongside cmake/ML-DSA-44.cmake. Where ML-DSA-44 is the
# conservative choice, Falcon buys size: 897-byte public key and 666-byte
# signature against 1312 and 2420, so a spend costs roughly a third as much
# chain space.
#
# PQClean sources, taken verbatim from commit
# 0586a824fc0d49df0b6b6e9179d8d15d06d0974f (4 Aug 2026), built as C11.
#
# This is PQClean's falcon-PADDED-512, not its falcon-512. The two share a key
# pair and differ only in signature encoding: plain falcon-512 emits a
# variable-length signature of up to 752 bytes, while the padded form is always
# exactly 666. Lattica needs the fixed one — SchemeSignatureSize() returns a
# single number, and the wallet's size estimate and the witness-item limits are
# built on it. The symbols are therefore PQCLEAN_FALCONPADDED512_CLEAN_*.
#
# No fips202.c or randombytes.c here: those PQClean common/ primitives are not
# scheme-namespaced and are compiled exactly once by the mldsa44 target, so this
# one links it to resolve shake256_inc_* and randombytes — the same arrangement
# ML-KEM-768 uses.
#
# The include directory is PRIVATE on purpose. This tree already carries two
# PQClean "api.h" files on the shared include path, and a third would make the
# quoted include in pubkey.cpp ambiguous by link order. Consumers declare the
# handful of Falcon entry points with extern "C" instead, as crypto/mlkem.cpp
# already does and explains.
#
# Built before core_interface so the vendored C keeps its own build policy.
add_library(falcon512 STATIC
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/codec.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/common.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/fft.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/fpr.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/keygen.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/pqclean.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/rng.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/sign.c
    ${PROJECT_SOURCE_DIR}/src/FALCON-512/vrfy.c)
target_include_directories(falcon512 PRIVATE
    ${PROJECT_SOURCE_DIR}/src/FALCON-512)
# fips202 (SHAKE256) + randombytes live in the mldsa44 target (PQClean common/).
target_link_libraries(falcon512 PUBLIC mldsa44)
