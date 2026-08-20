# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.26)
  set(log_files "CMakeFiles/CMakeConfigureLog.yaml")
else()
  set(log_files "CMakeFiles/CMakeOutput.log CMakeFiles/CMakeError.log")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E echo ${log_files})
