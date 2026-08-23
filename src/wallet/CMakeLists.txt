# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Wallet functionality used by latticad and lattica-wallet executables.
add_library(lattica_wallet STATIC EXCLUDE_FROM_ALL
  coincontrol.cpp
  coinselection.cpp
  context.cpp
  crypter.cpp
  db.cpp
  dump.cpp
  external_signer_scriptpubkeyman.cpp
  export.cpp
  feebumper.cpp
  fees.cpp
  interfaces.cpp
  load.cpp
  receive.cpp
  scriptpubkeyman.cpp
  rpc/addresses.cpp
  rpc/backup.cpp
  rpc/coins.cpp
  rpc/encrypt.cpp
  rpc/signmessage.cpp
  rpc/spend.cpp
  rpc/transactions.cpp
  rpc/util.cpp
  rpc/wallet.cpp
  spend.cpp
  sqlite.cpp
  transaction.cpp
  wallet.cpp
  walletdb.cpp
  walletutil.cpp
)
# Locate SQLite rather than naming the library bare. A bare "sqlite3" links
# on a native build only because the header happens to sit in the default
# include path; a cross-build has no such luck and fails on sqlite3.h.
find_path(SQLite3_INCLUDE_DIR NAMES sqlite3.h REQUIRED)
find_library(SQLite3_LIBRARY NAMES sqlite3 REQUIRED)

target_link_libraries(lattica_wallet
  PRIVATE
    core_interface
    lattica_common
    ${SQLite3_LIBRARY}
    univalue
    Boost::headers
)
target_include_directories(lattica_wallet PRIVATE ${SQLite3_INCLUDE_DIR})
