# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Vendored univalue — the JSON library used by every layer that speaks RPC/JSON.
add_library(univalue STATIC EXCLUDE_FROM_ALL
  lib/univalue.cpp
  lib/univalue_get.cpp
  lib/univalue_read.cpp
  lib/univalue_write.cpp
)
target_include_directories(univalue PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(univalue PRIVATE core_interface)
