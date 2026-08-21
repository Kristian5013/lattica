# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

# Unit tests — each test_*.cpp is its own standalone executable (int main())
# linked against the full node stack, registered with ctest.
set(LATTICA_TESTS
  test_addresstype test_arith test_bech32 test_block test_chain test_chainparams
  test_chainstate test_check test_clientversion test_coins test_crypter
  test_dbwrapper test_deployment test_falcon512 test_engine_utils test_coinscache test_hash
  test_interpreter test_key test_key_io test_hdkey test_mlkem test_mempool
  test_merkle test_mldsa44 test_moneystr test_policy test_pow test_pubkey
  test_random test_retarget test_ripemd160 test_script test_serialize test_sigcache
  test_signingprovider test_sign test_spend test_sha256 test_signmessage
  test_sha3 test_sha3_512 test_solver test_strencodings test_transaction test_txdb
  test_txgraph test_tx_check test_tx_verify test_uint256 test_v2cipher
  test_v2transport test_validation test_wallet test_wallet_spend test_walletdb)

foreach(t IN LISTS LATTICA_TESTS)
  add_executable(${t} ${t}.cpp)
  target_link_libraries(${t} PRIVATE core_interface lattica_node lattica_wallet)
  add_test(NAME ${t} COMMAND ${t})
endforeach()

