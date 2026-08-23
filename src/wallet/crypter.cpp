// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <wallet/crypter.h>

#include <common/system.h>
#include <crypto/aes.h>
#include <crypto/sha3_512.h>

#include <type_traits>
#include <vector>

namespace wallet {
int CCrypter::BytesToKeySHA3_512AES(const std::span<const unsigned char> salt, const SecureString& key_data, int count, unsigned char* key, unsigned char* iv) const
{
    // This mimics the behavior of openssl's EVP_BytesToKey with an aes256cbc
    // cipher and a 512-bit message digest. Because the digest's output size (64b)
    // is greater than the aes256 block size (16b) + aes256 key size (32b),
    // there's no need to process more than once (D_0).
    //
    // Lattica is Keccak-only: where Core uses SHA-512 here, we use SHA3-512.

    if(!count || !key || !iv)
        return 0;

    unsigned char buf[SHA3_512::OUTPUT_SIZE];
    SHA3_512 di;

    di.Write(UCharCast(key_data.data()), key_data.size());
    di.Write(salt.data(), salt.size());
    di.Finalize(buf);

    for(int i = 0; i != count - 1; i++)
        di.Reset().Write(buf, sizeof(buf)).Finalize(buf);

    memcpy(key, buf, WALLET_CRYPTO_KEY_SIZE);
    memcpy(iv, buf + WALLET_CRYPTO_KEY_SIZE, WALLET_CRYPTO_IV_SIZE);
    memory_cleanse(buf, sizeof(buf));
    return WALLET_CRYPTO_KEY_SIZE;
}

bool CCrypter::SetKeyFromPassphrase(const SecureString& key_data, const std::span<const unsigned char> salt, const unsigned int rounds, const unsigned int derivation_method)
{
    if (rounds < 1 || salt.size() != WALLET_CRYPTO_SALT_SIZE) {
        return false;
    }

    int i = 0;
    if (derivation_method == 0) {
        i = BytesToKeySHA3_512AES(salt, key_data, rounds, vchKey.data(), vchIV.data());
    }

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(vchKey.data(), vchKey.size());
        memory_cleanse(vchIV.data(), vchIV.size());
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial& new_key, const std::span<const unsigned char> new_iv)
{
    if (new_key.size() != WALLET_CRYPTO_KEY_SIZE || new_iv.size() != WALLET_CRYPTO_IV_SIZE) {
        return false;
    }

    memcpy(vchKey.data(), new_key.data(), new_key.size());
    memcpy(vchIV.data(), new_iv.data(), new_iv.size());

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char> &vchCiphertext) const
{
    if (!fKeySet)
        return false;

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCKSIZE bytes
    vchCiphertext.resize(vchPlaintext.size() + AES_BLOCKSIZE);

    AES256CBCEncrypt enc(vchKey.data(), vchIV.data(), true);
    size_t nLen = enc.Encrypt(vchPlaintext.data(), vchPlaintext.size(), vchCiphertext.data());
    if(nLen < vchPlaintext.size())
        return false;
    vchCiphertext.resize(nLen);

    return true;
}

bool CCrypter::Decrypt(const std::span<const unsigned char> ciphertext, CKeyingMaterial& plaintext) const
{
    if (!fKeySet)
        return false;

    // plaintext will always be equal to or lesser than length of ciphertext
    plaintext.resize(ciphertext.size());

    AES256CBCDecrypt dec(vchKey.data(), vchIV.data(), true);
    int len = dec.Decrypt(ciphertext.data(), ciphertext.size(), plaintext.data());
    if (len == 0) {
        return false;
    }
    plaintext.resize(len);
    return true;
}

bool EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial &vchPlaintext, const uint256& nIV, std::vector<unsigned char> &vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(chIV.data(), &nIV, WALLET_CRYPTO_IV_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt(vchPlaintext, vchCiphertext);
}

bool DecryptSecret(const CKeyingMaterial& master_key, const std::span<const unsigned char> ciphertext, const uint256& iv, CKeyingMaterial& plaintext)
{
    CCrypter key_crypter;
    static_assert(WALLET_CRYPTO_IV_SIZE <= std::remove_reference_t<decltype(iv)>::size());
    const std::span iv_prefix{iv.data(), WALLET_CRYPTO_IV_SIZE};
    if (!key_crypter.SetKey(master_key, iv_prefix)) {
        return false;
    }
    return key_crypter.Decrypt(ciphertext, plaintext);
}

bool DecryptKey(const CKeyingMaterial& master_key, const std::span<const unsigned char> crypted_secret, const CPubKey& pub_key, CKey& key)
{
    CKeyingMaterial secret;
    if (!DecryptSecret(master_key, crypted_secret, pub_key.GetHash(), secret)) {
        return false;
    }

    // The secret's length is the scheme's, and the scheme is named by the public
    // key's leading byte. Core reconstructs from (secret, pubkey, compression);
    // there is no compression flag here, and ML-DSA cannot recompute the public
    // key from the secret, so it is supplied to Set() and verified there.
    if (secret.size() != CKey::SecretSizeForPubKey(pub_key.size())) {
        return false;
    }

    key.Set(secret.begin(), secret.end(), pub_key);
    return key.IsValid();
}
bool EncryptExtKey(const CKeyingMaterial& master_key, const CExtKey& extkey, const CPubKey& pub_key, std::vector<unsigned char>& crypted_secret)
{
    CKeyingMaterial secret(CExtKey::SIZE);
    extkey.Encode(secret.data());
    return EncryptSecret(master_key, secret, pub_key.GetHash(), crypted_secret);
}

bool DecryptExtKey(const CKeyingMaterial& master_key, const std::span<const unsigned char> crypted_secret, const CPubKey& pub_key, CExtKey& extkey)
{
    CKeyingMaterial secret;
    if (!DecryptSecret(master_key, crypted_secret, pub_key.GetHash(), secret)) {
        return false;
    }
    if (secret.size() != CExtKey::SIZE) {
        return false;
    }
    extkey.Decode(secret.data());
    // Decode leaves the key invalid if the scheme byte pair names no scheme, and
    // the node must be the one this record was filed under.
    return extkey.key.IsValid() && extkey.key.GetPubKey() == pub_key;
}
} // namespace wallet
