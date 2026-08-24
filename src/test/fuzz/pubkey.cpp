// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// The vendored C, on bytes a stranger chose.
//
// Verifying a signature here is not the arithmetic it is on Bitcoin: it hands a
// public key and a signature straight to PQClean's Falcon-512 or ML-DSA-44,
// fifteen thousand lines of C with fifty-nine memcpy and fourteen malloc between
// them. Every node runs it on every input of every block it is offered, which
// means a peer chooses the bytes and the whole network executes on them. Nothing
// in C++ makes that safe; only evidence does, and this is where the evidence
// comes from.
//
// The target asserts almost nothing, deliberately. A signature that fails to
// verify is the ordinary case and not a finding. What it is looking for is what
// no return value can express: a read past the end of a buffer, a leak, an
// abort. Those are the sanitizer's to report.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <key.h>
#include <pubkey.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

FUZZ_TARGET(pubkey)
{
    FuzzedDataProvider provider = MakeProvider(buffer);

    // A key of any length at all: the ones no scheme uses must be refused by
    // length rather than reach a parser that expects another size.
    const std::vector<unsigned char> key_bytes = ConsumeRandomLengthBytes(provider, CPubKey::SIZE + 8);
    const CPubKey pubkey{key_bytes.begin(), key_bytes.end()};

    if (!pubkey.IsValid()) {
        // Set() rejected the length. Nothing downstream may treat it as a key.
        Assert(!CPubKey::ValidSize(key_bytes.size()));
        Assert(pubkey.size() == 0);
        return;
    }
    Assert(CPubKey::ValidSize(key_bytes.size()));
    Assert(pubkey.size() == key_bytes.size());

    // Reached before the expensive paths: for the lattice schemes this unpacks
    // the key, which is the first place vendored C touches attacker bytes.
    (void)pubkey.IsFullyValid();

    // The signature. Its length is the scheme's, or is not -- both must be safe,
    // and the second is the interesting one, because a lattice verifier that
    // trusts its length is a lattice verifier that reads past the buffer.
    const std::vector<unsigned char> sig = ConsumeRandomLengthBytes(provider, CPubKey::SIGNATURE_SIZE + 8);
    const uint256 hash = ConsumeUInt256(provider);

    (void)pubkey.Verify(hash, sig);
    (void)CPubKey::CheckLowS(sig);
    (void)pubkey.SignatureSize();
    (void)pubkey.GetID();
    (void)pubkey.IsCompressed();
    (void)pubkey.IsValidNonHybrid();

    // Recovery is secp256k1's alone, and is handed the same arbitrary bytes.
    CPubKey recovered;
    (void)recovered.RecoverCompact(hash, sig);

    // The x-only view, which reinterprets the key rather than re-parsing it.
    if (pubkey.size() == CPubKey::SECP256K1_SIZE) {
        const XOnlyPubKey xonly{pubkey};
        (void)xonly.IsFullyValid();
        // Only at the one length it accepts. VerifySchnorr asserts on any other,
        // and that assert is the API's contract rather than a fault: no peer can
        // reach it, because CheckSchnorrSignature rejects every size but 64 and
        // 65 before calling, and pops the hashtype byte off the 65. Feeding it
        // an arbitrary length would be this target inventing a caller that does
        // not exist, and reporting the crash as a finding.
        if (sig.size() == 64) (void)xonly.VerifySchnorr(hash, sig);
    }

    // Serialization must round-trip whatever it accepted.
    const std::vector<unsigned char> again{pubkey.begin(), pubkey.end()};
    Assert(again == key_bytes);
}

// A key that really is a key, so that verification runs past the early rejects
// and into the body of the vendored implementation rather than stopping at its
// front door. The fuzzer supplies the seed, the signature and the message.
FUZZ_TARGET(pubkey_verify_real)
{
    FuzzedDataProvider provider = MakeProvider(buffer);

    const unsigned int secret_size = provider.PickValueInArray<unsigned int>(
        {CKey::SECP256K1_SIZE, CKey::FALCON512_SIZE, CKey::MLDSA44_SIZE});

    const std::vector<unsigned char> seed = provider.ConsumeBytes<unsigned char>(32);
    if (seed.size() != 32) return;

    CKey key;
    if (!key.MakeKeyFromSeed(secret_size, seed)) return;
    const CPubKey pubkey = key.GetPubKey();
    if (!pubkey.IsValid()) return;

    const uint256 hash = ConsumeUInt256(provider);

    // The signature the fuzzer chose, against a key that will actually be
    // unpacked. This is the path a forged block takes.
    const std::vector<unsigned char> forged = ConsumeRandomLengthBytes(provider, CPubKey::SIGNATURE_SIZE + 8);
    (void)pubkey.Verify(hash, forged);

    // ...and the genuine one, which must verify and must keep verifying when a
    // single byte of it is disturbed only by failing.
    std::vector<unsigned char> real;
    if (key.Sign(hash, real)) {
        Assert(pubkey.Verify(hash, real));
        if (!real.empty()) {
            const size_t at = provider.ConsumeIntegralInRange<size_t>(0, real.size() - 1);
            const uint8_t flip = provider.ConsumeIntegral<uint8_t>();
            if (flip != 0) {
                real[at] ^= flip;
                (void)pubkey.Verify(hash, real);
            }
        }
    }
}
