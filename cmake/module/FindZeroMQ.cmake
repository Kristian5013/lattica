# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Finds the ZeroMQ library (the optional pub/sub notification interface) and
# exposes it as the imported `zeromq` target, mirroring Bitcoin Core's
# cmake/module/FindZeroMQ.cmake. Found via pkg-config (msys2 / Debian both ship
# a libzmq.pc).
if(TARGET zeromq)
  return()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(libzmq REQUIRED IMPORTED_TARGET libzmq)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZeroMQ
  REQUIRED_VARS libzmq_LINK_LIBRARIES
  VERSION_VAR libzmq_VERSION)

add_library(zeromq INTERFACE IMPORTED)
target_link_libraries(zeromq INTERFACE PkgConfig::libzmq)

if(WIN32)
  # Without this, zmq.h declares its functions __declspec(dllimport) and the
  # link fails on __imp_zmq_* against the static library that depends builds.
  target_compile_definitions(zeromq INTERFACE ZMQ_STATIC)
endif()
