# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# One binary holding every target; FUZZ names which one runs at start-up.
# Linking the node stack once rather than once per target is what keeps a
# growing set of targets buildable.
#
# The sanitizer and coverage flags are not here. They are set for the whole
# configuration in the top-level CMakeLists.txt, because what these targets
# exist to reach is the code they call into rather than their own three files
# -- see the note on BUILD_FUZZ_BINARY there.

add_executable(fuzz
  fuzz.cpp
  pubkey.cpp
  deserialize.cpp
)

target_link_libraries(fuzz PRIVATE core_interface lattica_node)

# fuzzer-no-link everywhere, the driver itself only here.
target_link_options(fuzz PRIVATE -fsanitize=fuzzer)
