# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

add_library(lattica_zmq STATIC EXCLUDE_FROM_ALL
  zmqabstractnotifier.cpp
  zmqnotificationinterface.cpp
  zmqpublishnotifier.cpp
  zmqrpc.cpp
  zmqutil.cpp
)
target_compile_definitions(lattica_zmq
  INTERFACE
    ENABLE_ZMQ=1
)
target_link_libraries(lattica_zmq
  PRIVATE
    core_interface
    univalue
    zeromq
)
