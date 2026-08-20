# Vendored google/crc32c (BSD-3-Clause; see LICENSE / AUTHORS).
#
# This is a minimal CMake build for Lattica — like the Bitcoin Core subtree, it
# replaces the upstream CMakeLists (which forces -Werror and pulls in glog /
# googletest / benchmark submodules) with just the library: SSE4.2 and ARMv8
# CRC32C acceleration are auto-detected, with a portable software fallback and
# runtime CPU dispatch. No tests / benchmarks / install. leveldb links this for
# hardware-accelerated checksums (CRC32C is a fixed algorithm — hw and sw give
# identical results, so the on-disk format is unchanged).

project(Crc32c VERSION 1.1.0 LANGUAGES C CXX)

include(CheckCXXSourceCompiles)
include(CMakePushCheckState)

# ---- byte order -------------------------------------------------------------
if(DEFINED CMAKE_CXX_BYTE_ORDER)
  if(CMAKE_CXX_BYTE_ORDER STREQUAL "BIG_ENDIAN")
    set(BYTE_ORDER_BIG_ENDIAN 1)
  else()
    set(BYTE_ORDER_BIG_ENDIAN 0)
  endif()
else()
  include(TestBigEndian)
  test_big_endian(BYTE_ORDER_BIG_ENDIAN)
endif()

# ---- feature detection (mirrors upstream's checks) --------------------------
check_cxx_source_compiles("
int main() {
  char data = 0;
  const char* address = &data;
  __builtin_prefetch(address, 0, 0);
  return 0;
}
" HAVE_BUILTIN_PREFETCH)

check_cxx_source_compiles("
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <xmmintrin.h>
#endif
int main() {
  char data = 0;
  const char* address = &data;
  _mm_prefetch(address, _MM_HINT_NTA);
  return 0;
}
" HAVE_MM_PREFETCH)

cmake_push_check_state(RESET)
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  set(CMAKE_REQUIRED_FLAGS "/arch:AVX")
else()
  set(CMAKE_REQUIRED_FLAGS "-msse4.2")
endif()
check_cxx_source_compiles("
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#include <nmmintrin.h>
#endif
int main() {
  _mm_crc32_u8(0, 0); _mm_crc32_u32(0, 0);
#if defined(_M_X64) || defined(__x86_64__)
  _mm_crc32_u64(0, 0);
#endif
  return 0;
}
" HAVE_SSE42)
cmake_pop_check_state()

cmake_push_check_state(RESET)
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  set(CMAKE_REQUIRED_FLAGS "-march=armv8-a+crc+crypto")
endif()
check_cxx_source_compiles("
#include <arm_acle.h>
#include <arm_neon.h>
int main() {
  __crc32cb(0, 0); __crc32ch(0, 0); __crc32cw(0, 0); __crc32cd(0, 0);
  vmull_p64(0, 0);
  return 0;
}
" HAVE_ARM64_CRC32C)
cmake_pop_check_state()

check_cxx_source_compiles("
#include <arm_acle.h>
#include <arm_neon.h>
#include <sys/auxv.h>
int main() {
  getauxval(AT_HWCAP);
  return 0;
}
" HAVE_STRONG_GETAUXVAL)

check_cxx_source_compiles("
unsigned long getauxval(unsigned long type) __attribute__((weak));
#define AT_HWCAP 16
int main() {
  getauxval(AT_HWCAP);
  return 0;
}
" HAVE_WEAK_GETAUXVAL)

# Tests are not built here.
set(CRC32C_TESTS_BUILT_WITH_GLOG 0)

configure_file(
  "src/crc32c_config.h.in"
  "${PROJECT_BINARY_DIR}/include/crc32c/crc32c_config.h"
)

# crc32c sources include "crc32c/crc32c.h" (public) and the generated
# "crc32c/crc32c_config.h"; sibling internal headers resolve via #include "...".
include_directories(
  "${PROJECT_SOURCE_DIR}/include"
  "${PROJECT_BINARY_DIR}/include")

# ARM64 and SSE4.2 code are built separately so their instructions never reach
# code that runs without the corresponding CPU support (the runtime dispatch in
# crc32c.cc picks the right path).
add_library(crc32c_arm64 OBJECT src/crc32c_arm64.cc)
if(HAVE_ARM64_CRC32C AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  target_compile_options(crc32c_arm64 PRIVATE -march=armv8-a+crc+crypto)
endif()

add_library(crc32c_sse42 OBJECT src/crc32c_sse42.cc)
if(HAVE_SSE42)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(crc32c_sse42 PRIVATE /arch:AVX)
  else()
    target_compile_options(crc32c_sse42 PRIVATE -msse4.2)
  endif()
endif()

add_library(crc32c STATIC
  src/crc32c.cc
  src/crc32c_portable.cc
  $<TARGET_OBJECTS:crc32c_arm64>
  $<TARGET_OBJECTS:crc32c_sse42>)
target_include_directories(crc32c PUBLIC "${PROJECT_SOURCE_DIR}/include")
