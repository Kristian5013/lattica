# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Finds Qt 6 for the GUI (lattica-qt), wrapping the upstream Qt6 package config
# like Bitcoin Core's cmake/module/FindQt.cmake. Exposes the standard
# Qt6::Core / Qt6::Gui / Qt6::Widgets / Qt6::Network targets; LinguistTools is
# required for qt6_add_lrelease (compiling the .ts translations to .qm).
if(TARGET Qt6::Widgets)
  return()
endif()

find_package(Qt6 6.2
  COMPONENTS Core Gui Widgets Network LinguistTools
  REQUIRED)
