// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Round-trip test for the ML-DSA-adapted signed-message helpers. Bitcoin's MessageSign/
// MessageVerify use ECDSA recoverable signatures (the signer's key is recovered from the
// signature); ML-DSA has no recovery, so a Lattica signed message instead carries the public
// key followed by the signature, and MessageVerify checks the embedded key against the address.

#include <common/signmessage.h>

#include <chainparams.h>
#include <key.h>
#include <util/strencodings.h>
#include <key_io.h>
#include <pubkey.h>
#include <util/chaintype.h>

#include <cstdio>
#include <string>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}
} // namespace

int main()
{
    SelectParams(ChainType::REGTEST);

    CKey key;
    key.MakeNewKey();
    const CPubKey pubkey = key.GetPubKey();
    const std::string address = EncodeDestination(WitnessV0KeyHash(pubkey), Params());
    const std::string message = "Lattica signed message round-trip via ML-DSA";

    std::string signature;
    Check("MessageSign succeeds", MessageSign(key, message, signature));
    Check("signature is non-empty", !signature.empty());

    Check("MessageVerify accepts a valid signature",
          MessageVerify(address, signature, message) == MessageVerificationResult::OK);

    Check("MessageVerify rejects a tampered message",
          MessageVerify(address, signature, message + "!") != MessageVerificationResult::OK);

    // A signature made by a different key must not verify against this address.
    {
        CKey other;
        other.MakeNewKey();
        std::string other_sig;
        Check("sign with a second key", MessageSign(other, message, other_sig));
        Check("MessageVerify rejects a foreign key's signature",
              MessageVerify(address, other_sig, message) == MessageVerificationResult::ERR_NOT_SIGNED);
    }

    // Every scheme, not just ML-DSA. The blob is (public key || signature) with
    // no length field between them, and the split used to be a fixed
    // CPubKey::SIZE offset — which only ever landed correctly for the largest
    // scheme, so secp256k1 and Falcon messages were rejected as malformed. The
    // boundary now comes from the total length, and each scheme's key+signature
    // sum is distinct: 97, 1563, 3732.
    {
        ECC_Context ecc_context{};
        for (const unsigned int secret_size : {CKey::SECP256K1_SIZE, CKey::FALCON512_SIZE, CKey::MLDSA44_SIZE}) {
            const CKey k = GenerateRandomKey(secret_size);
            const std::string addr = EncodeDestination(WitnessV0KeyHash(k.GetPubKey()), Params());
            std::string sig;
            Check("sign a message with this scheme", MessageSign(k, message, sig));

            const auto blob = DecodeBase64(sig);
            const CPubKey pub = k.GetPubKey();
            Check("blob is key + signature, no padding",
                  blob && blob->size() > pub.size() &&
                  blob->size() <= pub.size() + pub.SignatureSize());

            Check("verify a message with this scheme",
                  MessageVerify(addr, sig, message) == MessageVerificationResult::OK);
            Check("a tampered message is rejected",
                  MessageVerify(addr, sig, message + "!") != MessageVerificationResult::OK);

            // The address commits to the key, so another scheme's address must
            // not accept this signature.
            for (const unsigned int other_size : {CKey::SECP256K1_SIZE, CKey::FALCON512_SIZE, CKey::MLDSA44_SIZE}) {
                if (other_size == secret_size) continue;
                const CKey o = GenerateRandomKey(other_size);
                const std::string oaddr = EncodeDestination(WitnessV0KeyHash(o.GetPubKey()), Params());
                Check("another scheme's address does not accept it",
                      MessageVerify(oaddr, sig, message) != MessageVerificationResult::OK);
            }
        }
    }

    // Garbage / malformed inputs are rejected, not crashed on.
    Check("MessageVerify rejects an invalid address",
          MessageVerify("not-an-address", signature, message) == MessageVerificationResult::ERR_INVALID_ADDRESS);
    Check("MessageVerify rejects malformed base64",
          MessageVerify(address, "!!!not base64!!!", message) == MessageVerificationResult::ERR_MALFORMED_SIGNATURE);

    std::printf(g_fail ? "\nFAILED (%d)\n" : "\nOK\n", g_fail);
    return g_fail ? 1 : 0;
}
