# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored minisketch (BCH set reconciliation for Erlay / BIP-330 transaction
# relay), like Bitcoin Core. Built via its own CMakeLists (tests/benchmark/
# install disabled); it auto-detects CLMUL.
set(MINISKETCH_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MINISKETCH_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(MINISKETCH_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/minisketch)
