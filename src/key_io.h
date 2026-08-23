// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Text forms of keys and addresses: base58check for the legacy pair and for
// keys, bech32 and bech32m for the witness versions.
//
// Two things differ from Bitcoin's. WIF is an envelope for a 32-byte scalar, so
// only a secp256k1 secret has one. And an extended key is as long as the key it
// carries, so neither the private nor the public form has Bitcoin's fixed size;
// both bounds are written out from the types rather than taken as constants.

#ifndef LATTICA_KEY_IO_H
#define LATTICA_KEY_IO_H

#include <addresstype.h>
#include <kernel/chainparams.h>
#include <key.h>
#include <pubkey.h>

#include <string>
#include <vector>

/** Decode a WIF private key. Invalid, and so returning an invalid CKey, for
 *  anything but secp256k1: WIF is Bitcoin's envelope for a 32-byte scalar, and
 *  neither lattice secret is one. */
CKey DecodeSecret(const std::string& str, const CChainParams& params);
/** Encode a private key as WIF. Empty for a key of either lattice scheme. */
std::string EncodeSecret(const CKey& key, const CChainParams& params);

CExtKey DecodeExtKey(const std::string& str, const CChainParams& params);
std::string EncodeExtKey(const CExtKey& extkey, const CChainParams& params);
/** An extended public key is secp256k1's; see CExtKey::Neuter. */
CExtPubKey DecodeExtPubKey(const std::string& str, const CChainParams& params);
std::string EncodeExtPubKey(const CExtPubKey& extpubkey, const CChainParams& params);

/** Encode a destination as an address: base58check for P2PKH and P2SH, bech32
 *  for witness v0, bech32m for every version above it. Empty for a destination
 *  that has no address. */
std::string EncodeDestination(const CTxDestination& dest, const CChainParams& params);

/** Decode an address. On failure returns CNoDestination and sets error_str (and,
 *  when the string looks like bech32, fills error_locations). */
CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations = nullptr);

/** Decode an address; CNoDestination on failure. */
CTxDestination DecodeDestination(const std::string& str, const CChainParams& params);

/** Whether `str` is a valid address for the given network. */
bool IsValidDestinationString(const std::string& str, const CChainParams& params);

#endif // LATTICA_KEY_IO_H
