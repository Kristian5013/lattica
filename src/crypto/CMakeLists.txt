# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

add_library(lattica_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  chacha20.cpp
  chacha20poly1305.cpp
  hex_base.cpp
  hmac_sha256.cpp
  mlkem.cpp
  muhash.cpp
  poly1305.cpp
  ripemd160.cpp
  sha256.cpp
  sha3.cpp
  sha3_512.cpp
  siphash.cpp
  ../support/cleanse.cpp
  ../support/lockedpool.cpp
)

target_link_libraries(lattica_crypto
  PRIVATE
    core_interface
  PUBLIC
    # crypto/mlkem.cpp wraps the vendored ML-KEM-768 (FIPS 203) primitives;
    # mlkem768 transitively pulls in mldsa44 for the shared fips202/randombytes.
    mlkem768
)
