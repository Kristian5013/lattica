# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

include_guard(GLOBAL)

function(add_windows_resources target rc_file)
  if(WIN32)
    target_sources(${target} PRIVATE ${rc_file})
    set_property(SOURCE ${rc_file} APPEND PROPERTY
      INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/src
    )
  endif()
endfunction()

# Add a fusion manifest to Windows executables.
# See: https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests
function(add_windows_application_manifest target)
  if(WIN32)
    configure_file(${PROJECT_SOURCE_DIR}/cmake/windows-app.manifest.in ${target}.manifest USE_SOURCE_PERMISSIONS)
    file(CONFIGURE
      OUTPUT ${target}-manifest.rc
      CONTENT "1 /* CREATEPROCESS_MANIFEST_RESOURCE_ID */ 24 /* RT_MANIFEST */ \"${target}.manifest\""
    )
    add_windows_resources(${target} ${CMAKE_CURRENT_BINARY_DIR}/${target}-manifest.rc)
  endif()
endfunction()
