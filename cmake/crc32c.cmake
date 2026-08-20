# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored google/crc32c (hardware-accelerated CRC32C for LevelDB's checksums),
# like Bitcoin Core. Its upstream CMakeLists forces -Werror and pulls in glog /
# googletest / benchmark submodules, so we build it via a minimal CMakeLists
# (SSE4.2 / ARMv8 auto-detected, software fallback, runtime dispatch). Must be
# included before leveldb so the `crc32c` target exists, and HAVE_CRC32C is
# pre-seeded so LevelDB's own `if(HAVE_CRC32C) target_link_libraries(...)` uses
# it. (CRC32C is a fixed algorithm — hardware and software agree, so the on-disk
# checksum format is unchanged.)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/crc32c)
set(HAVE_CRC32C 1 CACHE INTERNAL "LevelDB uses the vendored google/crc32c")
