# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# test/util — Core-style test fixtures (TestingSetup / TestChain100Setup, mined
# with SHA3-256d), built on demand for the node-context benches and fixture tests.
add_library(lattica_test_util STATIC EXCLUDE_FROM_ALL
  blockfilter.cpp
  coins.cpp
  coverage.cpp
  json.cpp
  mining.cpp
  net.cpp
  random.cpp
  script.cpp
  setup_common.cpp
  transaction_utils.cpp
  txmempool.cpp
  validation.cpp
)
target_link_libraries(lattica_test_util PUBLIC core_interface lattica_node lattica_wallet)
