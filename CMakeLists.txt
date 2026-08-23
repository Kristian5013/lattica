# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.
#
# Lattica node — top-level build. Mirrors Bitcoin Core's modular CMake: this
# file sets up the project, options, vendored dependencies, the cmake/ helper
# modules and the generated build-config header, then defers the actual
# library/target decomposition to src/CMakeLists.txt (consensus / crypto / util
# / common / node / wallet / cli libraries, sharing flags via core_interface).
#
# Consensus core in C++20: SHA3-256 hashing, SHA3-256d proof-of-work,
# vendored ML-DSA-44 signatures (src/mldsa44, PQClean/FIPS 204), and the UTXO +
# validation stack.

cmake_minimum_required(VERSION 3.22)

project(lattica
    VERSION 0.1.0
    DESCRIPTION "Lattica — UTXO chain with SHA3-256d PoW and PQC signatures (ML-DSA-44)"
    HOMEPAGE_URL "https://github.com/gettessera-project/tessera"
    LANGUAGES C CXX)

# cmake/ module path (Core-style helper modules: AddWindowsResources,
# InstallBinaryComponent, …) and cmake/ root (build-config template +
# GenerateBuildInfo script).
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_SOURCE_DIR}/cmake/module)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Emit build/compile_commands.json so editors/IntelliSense resolve includes.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
# Multiprocess IPC (Cap'n Proto + vendored libmultiprocess; src/ipc). Off by
# default and forced off on Windows: the transport relies on fork(2) and
# AF_UNIX socketpair(2), so it only builds on unix-likes (as in Bitcoin Core).
option(ENABLE_IPC "Build multiprocess IPC support (unix only)" OFF)
if(WIN32)
    set(ENABLE_IPC OFF)
endif()
# Qt Widgets GUI (lattica-qt); needs Qt6. Off by default.
option(ENABLE_GUI "Build the Qt GUI (lattica-qt)" OFF)
# Wallet (always on — Lattica builds the wallet into the node) and the ZMQ
# notification interface (always on — provided natively by msys2).
option(ENABLE_WALLET "Enable wallet functionality" ON)
option(WITH_ZMQ "Build the ZMQ notification interface" ON)

# ---------------------------------------------------------------------------
# Build configuration header — generated from cmake/lattica-build-config.h.in
# (was hand-maintained in build/, which forced copying it into every build dir).
# clientversion.cpp consumes it via <lattica-build-config.h>.
# ---------------------------------------------------------------------------
set(CLIENT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CLIENT_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CLIENT_VERSION_BUILD ${PROJECT_VERSION_PATCH})
set(CLIENT_VERSION_IS_RELEASE "true")
set(CLIENT_VERSION_STRING "${PROJECT_VERSION}")
set(CLIENT_NAME "Lattica")
set(CLIENT_BUGREPORT "")
set(COPYRIGHT_YEAR 2026)
set(COPYRIGHT_HOLDERS "Kristian Pilatovich")
set(COPYRIGHT_HOLDERS_FINAL "Kristian Pilatovich")
# Compile-time feature detection (HAVE_FDATASYNC, HAVE_GETRANDOM, …) consumed by
# the template below, via cmake/introspection.cmake (Core's pattern).
include(introspection)
configure_file(${CMAKE_SOURCE_DIR}/cmake/lattica-build-config.h.in ${CMAKE_BINARY_DIR}/lattica-build-config.h @ONLY)

# lattica-build-info.h — git tag/commit, regenerated each build (Core's pattern).
find_package(Git QUIET)
add_custom_target(generate_build_info
    BYPRODUCTS ${CMAKE_BINARY_DIR}/lattica-build-info.h
    COMMAND ${CMAKE_COMMAND} -DGIT_EXECUTABLE=${GIT_EXECUTABLE} -DBUILD_INFO_HEADER_PATH=${CMAKE_BINARY_DIR}/lattica-build-info.h -DSOURCE_DIR=${CMAKE_SOURCE_DIR} -P ${CMAKE_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
    COMMENT "Generating lattica-build-info.h"
    VERBATIM)

# NSIS Windows installer script — generated from share/setup.nsi.in with the
# project name/version (cmake/module/GenerateSetupNsi.cmake), so the version is
# no longer hand-maintained in the .nsi. The makensis run is driven by
# tools/build-installer.sh (it stages the script + runtime bundle into an
# ASCII workdir, since makensis can't read the Cyrillic-path junction).
if(WIN32)
    include(GenerateSetupNsi)
    generate_setup_nsi()
endif()

# ---------------------------------------------------------------------------
# Vendored dependencies. Declared before core_interface so the vendored C/C++
# keeps its own build policy (no strict warnings / -UNDEBUG applied).
# ---------------------------------------------------------------------------
# Vendored libraries, each wired up by its own cmake/ module (Core's pattern:
# cmake/crc32c.cmake, cmake/leveldb.cmake, cmake/minisketch.cmake). crc32c must
# come before leveldb so the `crc32c` target + HAVE_CRC32C exist when LevelDB
# configures.
include(crc32c)
include(leveldb)
include(minisketch)
include(secp256k1)

# Vendored post-quantum crypto, each scheme wired up by its own cmake/ module:
#   - cmake/ML-DSA-44.cmake -> `mldsa44`  (FIPS 204 signatures; CHECKSIG). This is
#     Lattica's analog of Bitcoin Core's cmake/secp256k1.cmake — Core links
#     libsecp256k1 for its EC consensus signatures; Lattica has no curve.
#   - cmake/ML-KEM-768.cmake -> `mlkem768` (FIPS 203 KEM; P2P v2 transport key
#     agreement). Links mldsa44 to reuse the shared PQClean fips202/randombytes.
# mldsa44 must be included first (mlkem768 depends on it).
include(ML-DSA-44)
include(ML-KEM-768)
include(FALCON-512)

# ---------------------------------------------------------------------------
# System dependencies.
# ---------------------------------------------------------------------------
# Boost (header-only: multi_index for the mempool, etc.), located by
# cmake/module/AddBoostIfNeeded.cmake (Core's pattern).
include(AddBoostIfNeeded)

# ZeroMQ (pub/sub notifications), located by its own Find module
# (cmake/module/FindZeroMQ.cmake) and exposed as the imported target zeromq,
# mirroring Bitcoin Core's cmake/module/Find*.cmake. The RPC/REST HTTP server
# and clients use our own Sock-based implementation, so libevent is not needed.
if(WITH_ZMQ)
    find_package(ZeroMQ MODULE REQUIRED)
endif()

# ---------------------------------------------------------------------------
# core_interface — the INTERFACE library every Lattica target links to pick up
# the shared include roots, strict warnings and platform defines (Bitcoin Core's
# pattern). The vendored libraries above deliberately do NOT link it, keeping
# their own build policy. -UNDEBUG keeps assertions on in every build type
# (util/check.h's Assert() must always evaluate).
# ---------------------------------------------------------------------------
add_library(core_interface INTERFACE)
target_include_directories(core_interface INTERFACE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/univalue/include
    # ML-DSA-44 / ML-KEM-768 headers (api.h, …) are referenced across consensus,
    # common, crypto and the tests; the symbols are linked via the mldsa44 target
    # where used.
    ${CMAKE_SOURCE_DIR}/src/mldsa44
    ${CMAKE_SOURCE_DIR}/src/mlkem768
    ${CMAKE_BINARY_DIR})
# -UNDEBUG keeps assertions on in every build type (util/check.h's Assert()).
target_compile_options(core_interface INTERFACE -UNDEBUG)
if(WIN32)
    # Keep <windows.h> lean and drop its min/max macros (as Bitcoin Core does),
    # and define WIN32 (our util/fs.h PathToString static_asserts require it).
    target_compile_definitions(core_interface INTERFACE WIN32_LEAN_AND_MEAN NOMINMAX WIN32)
endif()

if(MINGW)
    # Link the toolchain runtime in. Without this the executables ask Windows
    # for libgcc_s_seh-1.dll, libstdc++-6.dll, libwinpthread-1.dll and
    # libssp-0.dll, none of which a stock Windows machine has, so a released
    # binary fails to start with a missing-DLL box.
    target_link_options(core_interface INTERFACE -static)
endif()

# ---------------------------------------------------------------------------
# Warning flags — warn_interface (linked into core_interface), each tested for
# support via try_append_cxx_flags so toolchain-specific flags (e.g. the
# clang-only ones) are silently skipped on gcc/mingw. Mirrors Bitcoin Core's
# warn_interface. SKIP_LINK: a warning flag never needs the link probe.
# ---------------------------------------------------------------------------
include(TryAppendCXXFlags)
include(TryAppendLinkerFlag)

add_library(warn_interface INTERFACE)
target_link_libraries(core_interface INTERFACE warn_interface)
try_append_cxx_flags("-Wall" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wextra" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wgnu" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wcovered-switch-default" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wformat -Wformat-security" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wvla" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wshadow-field" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wthread-safety" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wloop-analysis" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wredundant-decls" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wunused-member-function" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wdate-time" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wconditional-uninitialized" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wduplicated-branches" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wduplicated-cond" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wlogical-op" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Woverloaded-virtual" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wsuggest-override" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wimplicit-fallthrough" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wunreachable-code" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wdocumentation" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wself-assign" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wundef" TARGET warn_interface SKIP_LINK)
# Lattica keeps these two beyond Core's set — they caught real bugs during the port.
try_append_cxx_flags("-Wpedantic" TARGET warn_interface SKIP_LINK)
try_append_cxx_flags("-Wshadow" TARGET warn_interface SKIP_LINK)
# Disable the noisy subset -Wextra turns on that fires on intentional patterns in
# the verbatim Core sources (e.g. the no-op lock-assert helpers in sync.h when
# DEBUG_LOCKORDER is off). Must follow -Wextra. Mirrors Bitcoin Core's warn_interface.
try_append_cxx_flags("-Wno-unused-parameter" TARGET warn_interface SKIP_LINK)

# ---------------------------------------------------------------------------
# Hardening — security-oriented compiler/linker flags applied to core_interface,
# each via try_append so toolchain-unsupported ones (e.g. the ELF -z flags on
# mingw) are skipped automatically. Mirrors Bitcoin Core's ENABLE_HARDENING.
# ---------------------------------------------------------------------------
option(ENABLE_HARDENING "Attempt to harden the resulting executables" ON)
if(ENABLE_HARDENING)
    # gcc <=13.2 stack-reuse bug workaround (gcc-only flag).
    try_append_cxx_flags("-fstack-reuse=none" TARGET core_interface)

    # _FORTIFY_SOURCE needs optimization to do anything (else it only warns).
    try_append_cxx_flags("-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
        RESULT_VAR cxx_supports_fortify_source
        SOURCE "int main() {
                #if !defined __OPTIMIZE__ || __OPTIMIZE__ <= 0
                  #error
                #endif
                }")
    if(cxx_supports_fortify_source)
        target_compile_options(core_interface INTERFACE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
    endif()
    unset(cxx_supports_fortify_source)

    try_append_cxx_flags("-Wstack-protector" TARGET core_interface SKIP_LINK)
    try_append_cxx_flags("-fstack-protector-all" TARGET core_interface)
    try_append_cxx_flags("-fcf-protection=full" TARGET core_interface)
    if(NOT MINGW)
        # stack-clash-protection is a no-op on Windows.
        try_append_cxx_flags("-fstack-clash-protection" TARGET core_interface)
    endif()

    # Windows ASLR / DEP / reloc hardening (PE). On ELF these are rejected and
    # skipped; the ELF RELRO/now/separate-code flags below are skipped on mingw.
    try_append_linker_flag("-Wl,--enable-reloc-section" TARGET core_interface)
    try_append_linker_flag("-Wl,--dynamicbase" TARGET core_interface)
    try_append_linker_flag("-Wl,--nxcompat" TARGET core_interface)
    try_append_linker_flag("-Wl,--high-entropy-va" TARGET core_interface)
    try_append_linker_flag("-Wl,-z,relro" TARGET core_interface)
    try_append_linker_flag("-Wl,-z,now" TARGET core_interface)
    try_append_linker_flag("-Wl,-z,separate-code" TARGET core_interface)
endif()

enable_testing()
if(WIN32)
    enable_language(RC)
endif()

# Keep all executables in the build root (latticad.exe, lattica-qt.exe,
# test_*.exe, …) as before the decomposition, so ctest and the packaging
# scripts find them at a stable path even though targets now live under src/.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# The library decomposition + executables + tests live under src/.
add_subdirectory(src)

# Developer documentation (the `docs` target; requires Doxygen).
add_subdirectory(doc)
