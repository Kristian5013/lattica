# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.
#
# Library decomposition mirroring Bitcoin Core's src/CMakeLists.txt: the former
# monolithic lattica_core is split into a clean dependency DAG of static libs
#   crypto  <-  util  <-  consensus  <-  common  <-  node
#                                   wallet  <-  common
#                                   cli (standalone)
# All carry the shared flags/includes via the core_interface INTERFACE library
# (defined in the top-level CMakeLists). The build config header is generated
# next to this file.

include(AddWindowsResources)
include(InstallBinaryComponent)

# univalue — the JSON library (vendored under src/univalue), used by every layer
# that speaks RPC/JSON.
add_subdirectory(univalue)

# clientversion — depends on the generated lattica-build-info.h.
add_library(lattica_clientversion STATIC EXCLUDE_FROM_ALL
  clientversion.cpp
)
target_link_libraries(lattica_clientversion PRIVATE core_interface)
add_dependencies(lattica_clientversion generate_build_info)

add_subdirectory(crypto)
add_subdirectory(util)

# Consensus-critical code (block/tx validation primitives, script interpreter).
add_library(lattica_consensus STATIC EXCLUDE_FROM_ALL
  arith_uint256.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  uint256.cpp
)
target_link_libraries(lattica_consensus
  PRIVATE
    core_interface
    lattica_crypto
    # consensus/merkle.cpp calls Assume(), whose assertion_fail() lives in
    # lattica_util. Without this the symbol is only resolved by accident, when
    # some other object pulls util in earlier on the link line — test_merkle,
    # which pulls in nothing else, fails to link in an unoptimised build.
    lattica_util
  PUBLIC
    # pubkey.cpp verifies ML-DSA-44 (FIPS 204) signatures in CHECKSIG.
    mldsa44
    # ...Falcon-512 ones...
    falcon512
    # ...and secp256k1 ones. Verification uses secp256k1_context_static, so this
    # adds no global initialisation to consensus code: a node that only
    # validates never starts an ECC_Context.
    secp256k1
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

# Higher-level functionality shared by the executables and libraries.
add_library(lattica_common STATIC EXCLUDE_FROM_ALL
  addresstype.cpp
  base58.cpp
  bech32.cpp
  chain.cpp
  chainparams.cpp
  chainparamsbase.cpp
  coins.cpp
  common/args.cpp
  common/bloom.cpp
  common/config.cpp
  common/init.cpp
  common/interfaces.cpp
  common/license_info.cpp
  common/messages.cpp
  common/netif.cpp
  common/run_command.cpp
  common/settings.cpp
  common/signmessage.cpp
  common/system.cpp
  common/url.cpp
  compressor.cpp
  core_io.cpp
  deploymentinfo.cpp
  external_signer.cpp
  init/common.cpp
  kernel/chainparams.cpp
  key.cpp
  key_io.cpp
  merkleblock.cpp
  net_permissions.cpp
  net_types.cpp
  netaddress.cpp
  netbase.cpp
  outputtype.cpp
  policy/feerate.cpp
  policy/policy.cpp
  pow.cpp
  protocol.cpp
  rpc/rawtransaction_util.cpp
  rpc/request.cpp
  rpc/util.cpp
  musig.cpp
  scheduler.cpp
  script/descriptor.cpp
  script/miniscript.cpp
  script/parsing.cpp
  psbt.cpp
  script/sign.cpp
  script/signingprovider.cpp
  script/solver.cpp
)
target_link_libraries(lattica_common
  PRIVATE
    core_interface
    lattica_consensus
    lattica_util
    univalue
  PUBLIC
    $<$<PLATFORM_ID:Windows>:ws2_32>
)

if(ENABLE_WALLET)
  add_subdirectory(wallet)

  # lattica-wallet — offline wallet tool (no running node).
  add_executable(lattica-wallet
    lattica-wallet.cpp
    wallet/wallettool.cpp
  )
  target_link_libraries(lattica-wallet
    core_interface
    lattica_wallet
    lattica_common
    lattica_util
  )
endif()

# P2P and RPC server functionality used by latticad and lattica-qt.
add_library(lattica_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  banman.cpp
  blockencodings.cpp
  blockfilter.cpp
  consensus/tx_verify.cpp
  dbwrapper.cpp
  deploymentstatus.cpp
  flatfile.cpp
  headerssync.cpp
  httprpc.cpp
  httpserver.cpp
  i2p.cpp
  index/base.cpp
  index/blockfilterindex.cpp
  index/coinstatsindex.cpp
  index/txindex.cpp
  index/txospenderindex.cpp
  init.cpp
  kernel/chain.cpp
  kernel/checks.cpp
  kernel/coinstats.cpp
  kernel/context.cpp
  kernel/cs_main.cpp
  kernel/disconnected_transactions.cpp
  kernel/mempool_removal_reason.cpp
  mapport.cpp
  net.cpp
  net_processing.cpp
  netgroup.cpp
  node/abort.cpp
  node/blockmanager_args.cpp
  node/blockstorage.cpp
  node/caches.cpp
  node/chainstate.cpp
  node/chainstatemanager_args.cpp
  node/coin.cpp
  node/coins_view_args.cpp
  node/connection_types.cpp
  node/context.cpp
  node/database_args.cpp
  node/eviction.cpp
  node/interface_ui.cpp
  node/interfaces.cpp
  node/kernel_notifications.cpp
  node/mempool_args.cpp
  node/mempool_persist.cpp
  node/mempool_persist_args.cpp
  node/mini_miner.cpp
  node/psbt.cpp
  node/miner.cpp
  node/mining_args.cpp
  node/peerman_args.cpp
  node/timeoffsets.cpp
  node/transaction.cpp
  node/txdownloadman_impl.cpp
  node/txorphanage.cpp
  node/txreconciliation.cpp
  node/utxo_snapshot.cpp
  node/warnings.cpp
  noui.cpp
  policy/ephemeral_policy.cpp
  policy/fees/block_policy_estimator.cpp
  policy/fees/estimator_args.cpp
  policy/fees/estimator_man.cpp
  policy/fees/mempool_estimator.cpp
  policy/packages.cpp
  policy/rbf.cpp
  policy/settings.cpp
  policy/truc_policy.cpp
  private_broadcast.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/fees.cpp
  rpc/mempool.cpp
  rpc/mining.cpp
  rpc/net.cpp
  rpc/node.cpp
  rpc/output_script.cpp
  rpc/rawtransaction.cpp
  rpc/server.cpp
  rpc/server_util.cpp
  rpc/signmessage.cpp
  rpc/txoutproof.cpp
  script/sigcache.cpp
  torcontrol.cpp
  txdb.cpp
  txgraph.cpp
  txmempool.cpp
  txrequest.cpp
  v2cipher.cpp
  validation.cpp
  validationinterface.cpp
  versionbits.cpp
  $<$<TARGET_EXISTS:lattica_wallet>:wallet/init.cpp>
)
target_link_libraries(lattica_node
  PRIVATE
    core_interface
    lattica_common
    lattica_util
    $<TARGET_NAME_IF_EXISTS:lattica_zmq>
    leveldb
    minisketch
    univalue
  # Public: txmempool.h includes <boost/multi_index/...>, so every consumer of
  # this library's headers needs the include path too. As PRIVATE it only ever
  # worked because the host keeps Boost in a default search path.
  PUBLIC
    Boost::headers
)

# latticad — the headless node daemon. Links its own MakeNodeInit
# (init/latticad.cpp, no IPC); the IPC lattica-node below links a different one.
add_executable(latticad latticad.cpp init/latticad.cpp)
add_windows_resources(latticad latticad.rc)
target_link_libraries(latticad
  core_interface
  lattica_node
  $<TARGET_NAME_IF_EXISTS:lattica_wallet>
)

# Multiprocess IPC (unix only). The lattica-node binary is latticad with the
# IPC-enabled MakeNodeInit; the stub MakeIpc is folded into the node lib otherwise.
if(ENABLE_IPC)
  # Build the vendored libmultiprocess (defines the Libmultiprocess::multiprocess
  # and ::mpgen targets and the MP_INCLUDE_DIR property), then load its
  # target_capnp_sources() helper. The helper is shipped for downstream
  # find_package() consumers, so for this vendored (add_subdirectory) build it
  # must be include()'d explicitly before src/ipc uses it.
  add_subdirectory(ipc/libmultiprocess EXCLUDE_FROM_ALL)
  include(${CMAKE_CURRENT_SOURCE_DIR}/ipc/libmultiprocess/cmake/TargetCapnpSources.cmake)
  add_subdirectory(ipc)
  add_executable(lattica-node latticad.cpp init/lattica-node.cpp)
  target_link_libraries(lattica-node core_interface lattica_node lattica_ipc $<TARGET_NAME_IF_EXISTS:lattica_wallet>)
  add_executable(ipc_spawn_test EXCLUDE_FROM_ALL ipc/test/spawn_test.cpp)
  add_dependencies(ipc_spawn_test lattica-node)
  target_link_libraries(ipc_spawn_test PRIVATE core_interface lattica_node lattica_ipc)
else()
  target_sources(lattica_node PRIVATE ipc/stub.cpp)
endif()

# RPC command-line client library + the lattica-cli executable.
add_library(lattica_cli STATIC EXCLUDE_FROM_ALL
  compat/stdin.cpp
  rpc/client.cpp
)
target_link_libraries(lattica_cli PUBLIC core_interface univalue)

add_executable(lattica-cli lattica-cli.cpp)
add_windows_resources(lattica-cli lattica-cli.rc)
target_link_libraries(lattica-cli core_interface lattica_cli lattica_common lattica_node lattica_util)

# lattica-tx — offline raw-transaction tool.
add_executable(lattica-tx lattica-tx.cpp)
add_windows_resources(lattica-tx lattica-tx.rc)
target_link_libraries(lattica-tx core_interface lattica_common lattica_util univalue)

# lattica-util — offline block-header utility: grind the SHA3-256d proof-of-work
# of a hex block header (and netmagic). The Lattica analogue of bitcoin-util.
add_executable(lattica-util lattica-util.cpp)
add_windows_resources(lattica-util lattica-util.rc)
target_link_libraries(lattica-util core_interface lattica_common lattica_consensus lattica_util univalue)

# lattica-miner — standalone CPU miner. Talks to a latticad over JSON-RPC
# (getblocktemplate/submitblock) and grinds the node's SHA3-256d PoW on all
# cores, bit-identical to the node's own miner. The node's generatetoaddress is
# single-threaded and gives up after a million tries, so it cannot serve as one.
add_executable(lattica-miner lattica-miner.cpp)
add_windows_resources(lattica-miner lattica-miner.rc)
target_link_libraries(lattica-miner
  core_interface
  lattica_node
  lattica_common
  lattica_util
  univalue
)

# lattica-miner-gpu — the same miner on an OpenCL device. Built only when an
# OpenCL SDK is present; the node itself never depends on it.
find_package(OpenCL)
if(OpenCL_FOUND)
  add_executable(lattica-miner-gpu lattica-miner-gpu.cpp)
  add_windows_resources(lattica-miner-gpu lattica-miner-gpu.rc)
  target_link_libraries(lattica-miner-gpu
    core_interface
    lattica_node
    lattica_common
    lattica_util
    univalue
    OpenCL::OpenCL
  )
else()
  message(STATUS "OpenCL not found - lattica-miner-gpu will not be built")
endif()

# Windows: embed the UTF-8 active-code-page manifest on lattica-wallet too.
if(WIN32 AND TARGET lattica-wallet)
  add_windows_resources(lattica-wallet lattica-wallet.rc)
endif()

# Qt GUI (lattica-qt). Opt-in (-DENABLE_GUI=ON); links lattica_node directly.
if(ENABLE_GUI)
  find_package(Qt MODULE REQUIRED)
  add_subdirectory(qt)
endif()

# Test fixtures (always available for benches/fixture tests), the unit tests,
# and the benchmarks each live in their own subdirectory CMakeLists, mirroring
# Bitcoin Core's src/{test/util,test,bench} layout.
add_subdirectory(test/util)
add_subdirectory(test)
add_subdirectory(bench)

# tools/mine_genesis — offline genesis miner (built on demand). Lattica-specific
# (no Core analog), so it stays at the src level.
add_executable(mine_genesis EXCLUDE_FROM_ALL ${CMAKE_SOURCE_DIR}/tools/mine_genesis.cpp)
target_link_libraries(mine_genesis PRIVATE core_interface lattica_node)
