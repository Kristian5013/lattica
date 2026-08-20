// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Address <-> destination encoding, modeled on Bitcoin Core's key_io.h. The
// witness-address path (Encode/Decode of P2WPKH/P2WSH/anchor/unknown via bech32/
// bech32m, including the BIP141/BIP350 version+padding checks and bech32 error
// location) mirrors Core's. The rest of Core's key_io is intentionally absent
// because it is EC/base58check-coupled and Lattica has none of it:
//   - base58 P2PKH/P2SH addresses (EncodeBase58Check is double-SHA256; Lattica is
//     SHA3-only and witness-only, so it never produces legacy outputs);
//   - WIF private keys (EncodeSecret/DecodeSecret assume a 32-byte secp256k1 key
//     with a compression flag; an ML-DSA secret is 2560 bytes);
//   - BIP32 xprv/xpub (EncodeExtKey/EncodeExtPubKey; Lattica has no CExtPubKey,
//     since a lattice public key cannot be HD-derived);
//   - Taproot (WitnessV1Taproot).
// Functions take the CChainParams explicitly (there is no global Params()).

#ifndef LATTICA_KEY_IO_H
#define LATTICA_KEY_IO_H

#include <addresstype.h>
#include <kernel/chainparams.h>

#include <string>
#include <vector>

/** Encode a destination as a Lattica (bech32/bech32m) address. Returns an empty
 *  string for destinations without a (witness) address. */
std::string EncodeDestination(const CTxDestination& dest, const CChainParams& params);

/** Decode a Lattica address. On failure returns CNoDestination and sets error_str
 *  (and, when not bech32, fills error_locations via bech32 error location). */
CTxDestination DecodeDestination(const std::string& str, const CChainParams& params, std::string& error_str, std::vector<int>* error_locations = nullptr);

/** Decode a Lattica address; CNoDestination on failure. */
CTxDestination DecodeDestination(const std::string& str, const CChainParams& params);

/** Whether `str` is a valid Lattica address for the given network. */
bool IsValidDestinationString(const std::string& str, const CChainParams& params);

#endif // LATTICA_KEY_IO_H
