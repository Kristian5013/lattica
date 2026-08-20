# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Generates the NSIS installer script from share/setup.nsi.in, filling in the
# Lattica name/version/paths, mirroring Bitcoin Core's
# cmake/module/GenerateSetupNsi.cmake. The version flows from project(), so it
# is no longer hand-maintained in the .nsi. @ONLY substitution touches only
# @VAR@ tokens, leaving NSIS's own ${...} / $(...) syntax untouched.
#
# The makensis run itself is driven by tools/build-installer.sh (it stages the
# generated script + the windeployqt runtime bundle into a plain-ASCII workdir,
# since makensis can't read through the Cyrillic-path junction).
function(generate_setup_nsi)
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(CLIENT_TARNAME "lattica")
  set(CLIENT_URL ${PROJECT_HOMEPAGE_URL})
  set(CLIENT_VERSION ${PROJECT_VERSION})
  set(LATTICA_GUI_NAME "lattica-qt")
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
  configure_file(
    ${PROJECT_SOURCE_DIR}/share/setup.nsi.in
    ${PROJECT_BINARY_DIR}/lattica-win64-setup.nsi
    USE_SOURCE_PERMISSIONS @ONLY)
endfunction()
