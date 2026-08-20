// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the wallet encryption layer (crypto/aes + wallet/crypter):
//   - raw AES-256-CBC round-trips a buffer;
//   - CCrypter derives a key from a passphrase (SHA3-512 KDF) and round-trips a
//     secret, while a wrong passphrase does not recover it;
//   - EncryptSecret/DecryptSecret round-trip a master-key-encrypted blob;
//   - DecryptKey recovers a real ML-DSA-44 CKey from its encrypted secret key,
//     the recovered key matches the public key, and a wrong master key fails.

#include <crypto/aes.h>
#include <wallet/crypter.h>
#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <support/allocators/secure.h>

#include <cstdio>
#include <cstring>
#include <vector>

using namespace wallet;

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

bool SameBytes(const CKeyingMaterial& a, const CKeyingMaterial& b)
{
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0;
}
} // namespace

int main()
{
    // 1. Raw AES-256-CBC round-trip with PKCS#7 padding.
    {
        unsigned char key[32], iv[16];
        for (int i = 0; i < 32; ++i) key[i] = static_cast<unsigned char>(i);
        for (int i = 0; i < 16; ++i) iv[i] = static_cast<unsigned char>(i * 7 + 1);

        std::vector<unsigned char> pt(50);
        for (size_t i = 0; i < pt.size(); ++i) pt[i] = static_cast<unsigned char>(0x30 + i);

        std::vector<unsigned char> ct(pt.size() + AES_BLOCKSIZE);
        AES256CBCEncrypt enc(key, iv, true);
        int clen = enc.Encrypt(pt.data(), pt.size(), ct.data());
        ct.resize(clen);
        Check("AES ciphertext is block-aligned and grew", clen > 0 && clen % AES_BLOCKSIZE == 0 && clen > (int)pt.size());

        std::vector<unsigned char> dt(ct.size());
        AES256CBCDecrypt dec(key, iv, true);
        int dlen = dec.Decrypt(ct.data(), ct.size(), dt.data());
        dt.resize(dlen < 0 ? 0 : dlen);
        Check("AES-256-CBC round-trip", dt == pt);
    }

    // 2. CCrypter passphrase KDF (SHA3-512) + Encrypt/Decrypt.
    std::vector<unsigned char> salt(WALLET_CRYPTO_SALT_SIZE);
    for (size_t i = 0; i < salt.size(); ++i) salt[i] = static_cast<unsigned char>(i + 1);
    {
        SecureString pass{"correct horse battery staple"};
        CCrypter cr;
        Check("SetKeyFromPassphrase", cr.SetKeyFromPassphrase(pass, salt, 1000, 0));

        CKeyingMaterial secret(32);
        for (size_t i = 0; i < secret.size(); ++i) secret[i] = static_cast<unsigned char>(0xAB ^ i);

        std::vector<unsigned char> blob;
        Check("CCrypter encrypt", cr.Encrypt(secret, blob));

        CKeyingMaterial recovered;
        Check("CCrypter decrypt", cr.Decrypt(blob, recovered));
        Check("CCrypter round-trip", SameBytes(recovered, secret));

        // Wrong passphrase derives a different key and must not recover the secret.
        CCrypter bad;
        bad.SetKeyFromPassphrase(SecureString{"wrong passphrase"}, salt, 1000, 0);
        CKeyingMaterial junk;
        bool ok = bad.Decrypt(blob, junk);
        Check("wrong passphrase does not recover secret", !ok || !SameBytes(junk, secret));
    }

    // 3. EncryptSecret / DecryptSecret with a master key and a uint256 IV.
    CKeyingMaterial master(WALLET_CRYPTO_KEY_SIZE);
    for (size_t i = 0; i < master.size(); ++i) master[i] = static_cast<unsigned char>(i * 3 + 1);
    {
        unsigned char ivbytes[32];
        for (int i = 0; i < 32; ++i) ivbytes[i] = static_cast<unsigned char>(0xC0 + i);
        const uint256 iv{std::span<const unsigned char>(ivbytes, 32)};

        CKeyingMaterial plain(40);
        for (size_t i = 0; i < plain.size(); ++i) plain[i] = static_cast<unsigned char>(0x5A + i);

        std::vector<unsigned char> ct;
        Check("EncryptSecret", EncryptSecret(master, plain, iv, ct));
        CKeyingMaterial recovered;
        Check("DecryptSecret", DecryptSecret(master, ct, iv, recovered));
        Check("EncryptSecret/DecryptSecret round-trip", SameBytes(recovered, plain));
    }

    // 4. DecryptKey on a real ML-DSA-44 key: encrypt its secret key, recover it.
    {
        CKey k = GenerateRandomKey();
        CPubKey pub = k.GetPubKey();
        Check("generated ML-DSA key is valid", k.IsValid() && pub.IsValid());

        CKeyingMaterial sk(k.begin(), k.end()); // ML-DSA secret, 2560 bytes
        std::vector<unsigned char> ctkey;
        Check("encrypt ML-DSA secret key", EncryptSecret(master, sk, pub.GetHash(), ctkey));

        CKey recovered;
        Check("DecryptKey recovers the ML-DSA key", DecryptKey(master, ctkey, pub, recovered));
        Check("recovered key is valid and matches its pubkey", recovered.IsValid() && recovered.VerifyPubKey(pub));
        Check("recovered secret bytes equal the original",
              recovered.size() == k.size() && std::memcmp(recovered.data(), k.data(), k.size()) == 0);

        // A wrong master key must not yield a valid key.
        CKeyingMaterial wrong_master(master);
        wrong_master[0] ^= 0xFF;
        CKey bad;
        Check("DecryptKey with wrong master fails", !DecryptKey(wrong_master, ctkey, pub, bad));
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
