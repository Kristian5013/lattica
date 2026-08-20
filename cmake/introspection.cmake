# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Compile-time feature detection, mirroring Bitcoin Core's cmake/introspection.cmake.
# Each check sets a HAVE_* variable consumed by lattica-build-config.h.in. On
# Windows (mingw) the POSIX checks fail and the Windows code paths are used; on
# unix the checks turn on the optimised POSIX paths.
#
# Scope note: Core's introspection also detects x86/ARM SHA/SSE/AVX intrinsics
# and appends the socket/atomic libraries. Lattica omits both — its consensus
# hash is SHA3 (no per-ISA SHA256 object files exist to gate on HAVE_SSE41/SHANI),
# and its target platforms (Windows mingw, Linux x86-64) carry sockets and 64-bit
# atomics in libc (Windows already links ws2_32 explicitly).

include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)

check_cxx_symbol_exists(O_CLOEXEC "fcntl.h" HAVE_O_CLOEXEC)
check_cxx_symbol_exists(fdatasync "unistd.h" HAVE_FDATASYNC)
check_cxx_symbol_exists(fork "unistd.h" HAVE_DECL_FORK)
check_cxx_symbol_exists(pipe2 "unistd.h" HAVE_DECL_PIPE2)
check_cxx_symbol_exists(setsid "unistd.h" HAVE_DECL_SETSID)
check_cxx_symbol_exists(getifaddrs "ifaddrs.h" HAVE_IFADDRS)

# Even though ::system is part of the standard library, we still check
# for it, to support building targets that don't have it.
check_cxx_symbol_exists(std::system "cstdlib" HAVE_STD_SYSTEM)
check_cxx_symbol_exists(::_wsystem "stdlib.h" HAVE__WSYSTEM)
if(HAVE_STD_SYSTEM OR HAVE__WSYSTEM)
  set(HAVE_SYSTEM 1)
endif()

check_cxx_source_compiles("
  #include <string.h>

  int main()
  {
    char buf[100];
    char* p{strerror_r(0, buf, sizeof buf)};
    (void)p;
  }
  " STRERROR_R_CHAR_P
)

# malloc_info (memory statistics in getmemoryinfo).
check_cxx_symbol_exists(malloc_info "malloc.h" HAVE_MALLOC_INFO)

# mallopt(M_ARENA_MAX) (to set glibc arenas).
check_cxx_source_compiles("
  #include <malloc.h>

  int main()
  {
    mallopt(M_ARENA_MAX, 1);
  }
  " HAVE_MALLOPT_ARENA_MAX
)

# posix_fallocate().
check_cxx_source_compiles("
  #include <fcntl.h>

  int main()
  {
    return posix_fallocate(0, 0, 0);
  }
  " HAVE_POSIX_FALLOCATE
)

# Strong getauxval() support in the system headers.
check_cxx_source_compiles("
  #include <sys/auxv.h>

  int main()
  {
    getauxval(AT_HWCAP);
  }
  " HAVE_STRONG_GETAUXVAL
)

# UNIX sockets.
check_cxx_source_compiles("
  #include <sys/socket.h>
  #include <sys/un.h>

  int main()
  {
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
  }
  " HAVE_SOCKADDR_UN
)

# OS randomness sources:
# - Linux getrandom()
check_cxx_source_compiles("
  #include <sys/random.h>

  int main()
  {
    getrandom(nullptr, 32, 0);
  }
  " HAVE_GETRANDOM
)

# - BSD getentropy()
check_cxx_source_compiles("
  #include <sys/random.h>

  int main()
  {
    getentropy(nullptr, 32);
  }
  " HAVE_GETENTROPY_RAND
)

# - BSD sysctl()
check_cxx_source_compiles("
  #include <sys/types.h>
  #include <sys/sysctl.h>

  #ifdef __linux__
  #error Don't use sysctl on Linux, it's deprecated even when it works
  #endif

  int main()
  {
    sysctl(nullptr, 2, nullptr, nullptr, nullptr, 0);
  }
  " HAVE_SYSCTL
)

# - BSD sysctl(KERN_ARND)
check_cxx_source_compiles("
  #include <sys/types.h>
  #include <sys/sysctl.h>

  #ifdef __linux__
  #error Don't use sysctl on Linux, it's deprecated even when it works
  #endif

  int main()
  {
    static int name[2] = {CTL_KERN, KERN_ARND};
    sysctl(name, 2, nullptr, nullptr, nullptr, 0);
  }
  " HAVE_SYSCTL_ARND
)
