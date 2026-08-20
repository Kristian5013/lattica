# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

include(ts_files.cmake)
qt6_add_lrelease(TS_FILES ${ts_files} LRELEASE_TARGET latticaqt_lrelease OPTIONS -silent)
add_dependencies(latticaqt latticaqt_lrelease)
