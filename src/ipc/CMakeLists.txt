# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# The multiprocess IPC library: the Cap'n Proto protocol + process framework,
# plus the schemas compiled to capnp + proxy C++ by mpgen (target_capnp_sources,
# from the vendored libmultiprocess). EXCLUDE_FROM_ALL — pulled in by the
# binaries that link it.
add_library(lattica_ipc STATIC EXCLUDE_FROM_ALL
  capnp/mining.cpp
  capnp/protocol.cpp
  interfaces.cpp
  process.cpp
)

target_capnp_sources(lattica_ipc ${CMAKE_SOURCE_DIR}/src
  capnp/common.capnp
  capnp/echo.capnp
  capnp/init.capnp
  capnp/mining.capnp
  capnp/rpc.capnp
  IMPORT_PATHS ${CMAKE_SOURCE_DIR}/src/ipc/libmultiprocess/include
)

target_link_libraries(lattica_ipc
  PRIVATE
    core_interface
    lattica_node
    Libmultiprocess::multiprocess
)

# IPC round-trip test: drives the multiprocess runtime in-process (pipe +
# socketpair + unix socket) and the type-conversion hooks via a FooInterface
# schema. A standalone test main (Lattica style), built and registered only
# here — the whole file is reached only under ENABLE_IPC (unix).
add_executable(test_ipc
  test/ipc_test.cpp
  test/test_ipc.cpp
)
target_capnp_sources(test_ipc ${CMAKE_SOURCE_DIR}/src
  test/ipc_test.capnp
  IMPORT_PATHS ${CMAKE_SOURCE_DIR}/src/ipc/libmultiprocess/include
)
target_link_libraries(test_ipc
  PRIVATE
    core_interface
    lattica_ipc
    lattica_node
    Libmultiprocess::multiprocess
)
add_test(NAME test_ipc COMMAND test_ipc)
