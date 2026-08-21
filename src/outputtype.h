// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_OUTPUTTYPE_H
#define LATTICA_OUTPUTTYPE_H

#include <addresstype.h>
#include <key.h>
#include <script/signingprovider.h>

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * The address format a wallet should produce.
 *
 * Core's four values name a format alone, every one of them holding a
 * secp256k1 key. Here the witness version names the signature scheme as well,
 * so the last two values name a scheme: both produce the same bech32m witness
 * v2 address, and what differs is the key that goes under the hash. That is a
 * choice only the wallet can make, at the moment it generates a key, which is
 * why it belongs here rather than in the address encoding.
 */
enum class OutputType {
    LEGACY,       //!< base58 P2PKH or P2SH; secp256k1
    P2SH_SEGWIT,  //!< base58 P2SH wrapping a witness v0 program; secp256k1
    BECH32,       //!< witness v0; secp256k1
    BECH32M,      //!< witness v1, Taproot; secp256k1
    FALCON512,    //!< witness v2, bech32m; Falcon-512
    MLDSA44,      //!< witness v2, bech32m; ML-DSA-44
    UNKNOWN,
};

inline constexpr auto OUTPUT_TYPES = std::array{
    OutputType::LEGACY,
    OutputType::P2SH_SEGWIT,
    OutputType::BECH32,
    OutputType::BECH32M,
    OutputType::FALCON512,
    OutputType::MLDSA44,
};

std::optional<OutputType> ParseOutputType(std::string_view str);
const std::string& FormatOutputType(OutputType type);
std::string FormatAllOutputTypes();

/**
 * The size of the secret a key for this output type has, which is what names its
 * scheme; 0 for UNKNOWN. See CKey's size constants.
 */
unsigned int SecretSizeForOutputType(OutputType type);

/**
 * Get a destination of the requested type (if possible) to the specified script.
 * This function will automatically add the script (and any other
 * necessary scripts) to the keystore.
 */
CTxDestination AddAndGetDestinationForScript(FlatSigningProvider& keystore, const CScript& script, OutputType);

/** Get the OutputType for a CTxDestination.
 *
 *  A witness v2 destination is a hash, and a hash does not say which of the two
 *  schemes made it, so this returns nullopt for one. The wallet knows from the
 *  key it holds; nothing else can. */
std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest);

#endif // LATTICA_OUTPUTTYPE_H
