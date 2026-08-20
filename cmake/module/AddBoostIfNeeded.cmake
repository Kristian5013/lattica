# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Finds Boost (header-only — multi_index for the mempool, etc.) and makes the
# Boost::headers target available, mirroring Bitcoin Core's
# cmake/module/AddBoostIfNeeded.cmake. Found via its CMake config, which both the
# native msys2 boost and a depends-built boost provide.
if(TARGET Boost::headers)
  return()
endif()

find_package(Boost CONFIG REQUIRED)
