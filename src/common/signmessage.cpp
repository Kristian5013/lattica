// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <common/signmessage.h>
#include <chainparams.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

/**
 * Text used to signify that a signed message follows and to prevent
 * inadvertently signing a transaction.
 */
const std::string MESSAGE_MAGIC = "Lattica Signed Message:\n";

MessageVerificationResult MessageVerify(
    const std::string& address,
    const std::string& signature,
    const std::string& message)
{
    CTxDestination destination = DecodeDestination(address, Params());
    if (!IsValidDestination(destination)) {
        return MessageVerificationResult::ERR_INVALID_ADDRESS;
    }

    // addresses are witness-only (bech32 P2WPKH); the signer is identified by a
    // WitnessV0KeyHash, not the legacy base58 PKHash Core uses here.
    if (std::get_if<WitnessV0KeyHash>(&destination) == nullptr) {
        return MessageVerificationResult::ERR_ADDRESS_NO_KEY;
    }

    auto signature_bytes = DecodeBase64(signature);
    if (!signature_bytes) {
        return MessageVerificationResult::ERR_MALFORMED_SIGNATURE;
    }

    // ML-DSA signatures are not public-key-recoverable (unlike ECDSA's compact form),
    // so a Lattica signed message carries the public key followed by the signature.
    // Extract and verify them explicitly instead of recovering the key.
    if (signature_bytes->size() <= CPubKey::SIZE) {
        return MessageVerificationResult::ERR_MALFORMED_SIGNATURE;
    }
    CPubKey pubkey(signature_bytes->begin(), signature_bytes->begin() + CPubKey::SIZE);
    if (!pubkey.IsValid()) {
        return MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED;
    }
    if (!pubkey.Verify(MessageHash(message), std::span<const unsigned char>(*signature_bytes).subspan(CPubKey::SIZE))) {
        return MessageVerificationResult::ERR_NOT_SIGNED;
    }

    if (!(WitnessV0KeyHash(pubkey) == *std::get_if<WitnessV0KeyHash>(&destination))) {
        return MessageVerificationResult::ERR_NOT_SIGNED;
    }

    return MessageVerificationResult::OK;
}

bool MessageSign(
    const CKey& privkey,
    const std::string& message,
    std::string& signature)
{
    const CPubKey pubkey = privkey.GetPubKey();
    std::vector<unsigned char> sig;
    if (!privkey.Sign(MessageHash(message), sig)) {
        return false;
    }

    // ML-DSA signatures can't recover the signer's key, so prepend the public key.
    std::vector<unsigned char> blob(pubkey.begin(), pubkey.end());
    blob.insert(blob.end(), sig.begin(), sig.end());
    signature = EncodeBase64(blob);

    return true;
}

uint256 MessageHash(const std::string& message)
{
    HashWriter hasher{};
    hasher << MESSAGE_MAGIC << message;

    return hasher.GetHash();
}

std::string SigningResultString(const SigningResult res)
{
    switch (res) {
        case SigningResult::OK:
            return "No error";
        case SigningResult::PRIVATE_KEY_NOT_AVAILABLE:
            return "Private key not available";
        case SigningResult::SIGNING_FAILED:
            return "Sign failed";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}