# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored LevelDB (the UTXO/block-index key-value store), like Bitcoin Core.
# Built via its own CMakeLists with tests/benchmarks/install disabled; it links
# the vendored google/crc32c (see crc32c.cmake, included first) for
# hardware-accelerated checksums.
set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LEVELDB_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/leveldb)
