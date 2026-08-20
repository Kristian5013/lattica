// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// CWallet implementation. See wallet.h for how this relates to Bitcoin Core's
// wallet: it keeps Core's scheme-agnostic orchestration (mapWallet, the TXO cache,
// the notification-driven sync, the address book, encryption) and replaces the
// ScriptPubKeyMan key layer with a direct ML-DSA HD keystore (CWallet is the
// FillableSigningProvider). Coin selection, fee calculation, balance bucketing and
// transaction creation live in wallet/{coinselection,fees,receive,spend}.cpp as free
// functions; this file implements the state and primitives they consume. Persistence
// is incremental, as in Core: mutators write their records through a WalletBatch.

#include <wallet/wallet.h>

#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <common/messages.h>
#include <common/settings.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <interfaces/chain.h>
#include <kernel/chain.h>
#include <kernel/types.h>
#include <key_io.h>
#include <node/types.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <wallet/context.h>
#include <wallet/db.h>

#include <univalue.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <system_error>
#include <tuple>

namespace wallet {

using interfaces::FoundBlock;

// ============================================================ ML-DSA HD key core

void CWallet::GenerateNewSeed()
{
    std::array<unsigned char, SEED_LENGTH> seed;
    GetStrongRandBytes(seed);
    SetSeed(seed);
}

void CWallet::SetSeed(std::span<const unsigned char> seed)
{
    LOCK(cs_wallet);

    // Exactly SEED_LENGTH, and this is stricter than the 16..64 range BIP32 allows
    // on purpose. The seed is persisted as a uint256, so a longer one would derive
    // the master key here from all of its bytes while only the first 32 were
    // written to disk. On the next load the master would be rebuilt from the
    // truncated seed, every key would come out different, and the wallet would
    // show a zero balance against coins it can no longer see. Nothing would report
    // an error at any point -- the same failure the dual-derivation path exists to
    // undo. Currently every caller passes 32 bytes; the check is here so that a
    // future restore-from-seed path (a BIP39 seed is 64 bytes) fails loudly
    // instead of quietly producing an unloadable wallet.
    Assert(seed.size() == SEED_LENGTH);

    m_hd_master.SetSeed(seed);
    // Keep the raw seed so the HD state can be persisted (CHDChain.hd_seed) and the
    // master reconstructed on load.
    m_hd_seed = uint256();
    std::memcpy(m_hd_seed.begin(), seed.data(), SEED_LENGTH);
    m_next_index = 0;
    m_has_seed = true;
    MaybeUpdateBirthTime(GetTime());

    // Persist the (now reset) HD chain.
    if (m_database) {
        WalletBatch batch(*m_database);
        CHDChain chain;
        chain.nExternalChainCounter = m_next_index;
        chain.hd_seed = m_hd_seed;
        if (m_hd_master.key.IsValid()) chain.seed_id = m_hd_master.key.GetPubKey().GetID();
        batch.WriteHDChain(chain);
    }
}

util::Result<CTxDestination> CWallet::GetNewDestination(const std::string& label)
{
    LOCK(cs_wallet);
    if (!m_has_seed) return util::Error{Untranslated("Wallet has no HD seed")};

    CExtKey child;
    if (!m_hd_master.Derive(child, m_next_index)) return util::Error{Untranslated("HD derivation failed")};
    ++m_next_index;
    AddKey(child.key); // stores CKeyID -> CKey and learns the implied P2WPKH script
    const CKeyID new_keyid = child.key.GetPubKey().GetID();
    m_pubkey_ids.insert(new_keyid);

    const CTxDestination dest{WitnessV0KeyHash(child.key.GetPubKey())};

    // Persist incrementally, as Core does (the advanced HD chain; no per-key record,
    // since Lattica's wallet is pure-HD and keys re-derive from the seed on load).
    if (m_database) {
        WalletBatch batch(*m_database);
        CHDChain chain;
        chain.nExternalChainCounter = m_next_index;
        chain.hd_seed = m_hd_seed;
        if (m_hd_master.key.IsValid()) chain.seed_id = m_hd_master.key.GetPubKey().GetID();
        batch.WriteHDChain(chain);
        batch.WritePubKeyId(new_keyid); // public data: lets a locked encrypted wallet see this output
        if (!label.empty()) SetAddressBookWithDB(batch, dest, label, AddressPurpose::RECEIVE);
    } else if (!label.empty()) {
        m_address_book[dest].SetLabel(label);
        m_address_book[dest].purpose = AddressPurpose::RECEIVE;
    }
    return dest;
}

util::Result<CTxDestination> CWallet::GetNewChangeDestination()
{
    // Same key pool as receive addresses (legacy-keystore style); change has no label.
    return GetNewDestination("");
}

std::string CWallet::GetNewAddress(const std::string& label)
{
    const auto dest = GetNewDestination(label);
    if (!dest) return {};
    assert(m_params);
    return EncodeDestination(*dest, *m_params);
}

std::optional<CKey> CWallet::GetKey(const CKeyID& keyid) const
{
    LOCK(cs_wallet);
    CKey key;
    if (FillableSigningProvider::GetKey(keyid, key)) return key;
    return std::nullopt;
}

void CWallet::LoadHDChain(const CHDChain& chain)
{
    LOCK(cs_wallet);
    m_next_index = chain.nExternalChainCounter;
    if (!chain.crypted_seed.empty()) {
        // Encrypted wallet: the seed is sealed. Stay locked (no key core, no keys)
        // until Unlock decrypts it and re-derives the keystore.
        m_crypted_seed = chain.crypted_seed;
        m_has_seed = false;
        return;
    }
    if (!chain.hd_seed.IsNull()) {
        m_hd_seed = chain.hd_seed;
        m_hd_master.SetSeed(std::span<const unsigned char>(chain.hd_seed.begin(), chain.hd_seed.size()));
        m_has_seed = true;
        // Re-derive every key the wallet has handed out. Lattica persists only the
        // seed + counter, so the keystore is rebuilt here (no per-key records).
        for (uint32_t i = 0; i < m_next_index; ++i) {
            CExtKey child;
            if (m_hd_master.Derive(child, i)) { AddKey(child.key); m_pubkey_ids.insert(child.key.GetPubKey().GetID()); }
        }
    }
}

// ================================================================== encryption

bool CWallet::HasEncryptionKeys() const { return !mapMasterKeys.empty(); }

bool CWallet::IsLocked() const
{
    if (!IsCrypted()) return false;
    LOCK(cs_wallet);
    return vMasterKey.empty();
}

bool CWallet::Lock()
{
    if (!IsCrypted()) return false;
    {
        LOCK(cs_wallet);
        if (!vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data(), vMasterKey.size());
            vMasterKey.clear();
        }
        // Wipe the in-memory secrets: the seed, the master key, and every derived key.
        // The wallet can only sign again after Unlock re-decrypts the seed.
        memory_cleanse(m_hd_seed.begin(), m_hd_seed.size());
        m_hd_seed.SetNull();
        m_hd_master = CExtKey{};
        m_has_seed = false;
        WITH_LOCK(cs_KeyStore, mapKeys.clear());
    }
    NotifyStatusChanged(this);
    return true;
}

bool CWallet::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    LOCK(cs_wallet);
    // Decrypt the sealed seed with the candidate master key and rebuild the key core.
    // A wrong master key fails the AES padding check (or the size check), so this
    // doubles as master-key verification.
    if (!m_crypted_seed.empty()) {
        CKeyingMaterial seed_material;
        if (!DecryptSecret(vMasterKeyIn, m_crypted_seed, uint256(), seed_material)) return false;
        if (seed_material.size() != m_hd_seed.size()) return false;
        std::memcpy(m_hd_seed.begin(), seed_material.data(), m_hd_seed.size());
        m_hd_master.SetSeed(std::span<const unsigned char>(m_hd_seed.begin(), m_hd_seed.size()));
        m_has_seed = true;
        for (uint32_t i = 0; i < m_next_index; ++i) {
            CExtKey child;
            if (m_hd_master.Derive(child, i)) { AddKey(child.key); m_pubkey_ids.insert(child.key.GetPubKey().GetID()); }
        }
    }
    vMasterKey = vMasterKeyIn;
    return true;
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    LOCK(cs_wallet);
    CKeyingMaterial vMasterKeyDecrypted;
    CCrypter crypter;
    for (const auto& [id, master] : mapMasterKeys) {
        if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, master.vchSalt, master.nDeriveIterations, master.nDerivationMethod)) {
            return false;
        }
        if (!crypter.Decrypt(master.vchCryptedKey, vMasterKeyDecrypted)) {
            continue; // try the next master key
        }
        if (Unlock(vMasterKeyDecrypted)) {
            NotifyStatusChanged(this);
            return true;
        }
    }
    return false;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    LOCK(cs_wallet);
    if (IsCrypted()) return false;
    if (!m_has_seed) return false; // nothing to protect

    CKeyingMaterial new_master_key;
    new_master_key.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(new_master_key);

    CMasterKey kMasterKey;
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(kMasterKey.vchSalt);

    CCrypter crypter;
    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod)) {
        return false;
    }
    if (!crypter.Encrypt(new_master_key, kMasterKey.vchCryptedKey)) {
        return false;
    }

    // Seal the HD seed with the new master key. The whole key tree re-derives from
    // the seed, so this single ciphertext protects all of the wallet's private keys.
    CKeyingMaterial seed_material(m_hd_seed.begin(), m_hd_seed.end());
    std::vector<unsigned char> crypted_seed;
    if (!EncryptSecret(new_master_key, seed_material, uint256(), crypted_seed)) return false;

    {
        WalletBatch batch(GetDatabase());
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (!batch.WriteMasterKey(nMasterKeyMaxID, kMasterKey)) return false;
        m_crypted_seed = crypted_seed;
        // Rewrite the HD chain with the seed encrypted (plaintext hd_seed cleared on disk).
        CHDChain chain;
        chain.nExternalChainCounter = m_next_index;
        chain.crypted_seed = crypted_seed;
        if (m_hd_master.key.IsValid()) chain.seed_id = m_hd_master.key.GetPubKey().GetID();
        if (!batch.WriteHDChain(chain)) return false;
        // Persist the public key ids now, while the seed is still available: once the wallet
        // locks, the sealed seed can no longer re-derive them, so without this a reloaded
        // encrypted wallet would recognise none of its outputs and show a zero balance.
        for (uint32_t i = 0; i < m_next_index; ++i) {
            CExtKey child;
            if (m_hd_master.Derive(child, i)) {
                const CKeyID id = child.key.GetPubKey().GetID();
                m_pubkey_ids.insert(id);
                batch.WritePubKeyId(id);
            }
        }
        vMasterKey = new_master_key; // the wallet stays unlocked after encrypting
    }
    NotifyStatusChanged(this);
    return true;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    LOCK(cs_wallet);
    if (!Unlock(strOldWalletPassphrase)) return false;

    WalletBatch batch(GetDatabase());
    for (auto& [id, master] : mapMasterKeys) {
        CCrypter crypter;
        if (!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, master.vchSalt, master.nDeriveIterations, master.nDerivationMethod)) return false;
        CKeyingMaterial decrypted;
        if (!crypter.Decrypt(master.vchCryptedKey, decrypted)) return false;
        if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, master.vchSalt, master.nDeriveIterations, master.nDerivationMethod)) return false;
        if (!crypter.Encrypt(decrypted, master.vchCryptedKey)) return false;
        batch.WriteMasterKey(id, master);
    }
    return true;
}

bool CWallet::WithEncryptionKey(std::function<bool (const CKeyingMaterial&)> cb) const
{
    LOCK(cs_wallet);
    if (vMasterKey.empty()) return false;
    return cb(vMasterKey);
}

// ============================================================== spent tracking

void CWallet::AddToSpends(const COutPoint& outpoint, const Txid& wtxid)
{
    auto range = mapTxSpends.equal_range(outpoint);
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second == wtxid) return;
    }
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));
    SyncMetaData(range);
}

void CWallet::AddToSpends(const CWalletTx& wtx)
{
    if (wtx.IsCoinBase()) return;
    for (const CTxIn& txin : wtx.tx->vin) AddToSpends(txin.prevout, wtx.GetHash());
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // Propagate the oldest (smallest nOrderPos) conflicting transaction's metadata to
    // all of them, so listing/abandon logic sees a consistent ordering (Core behavior).
    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (auto it = range.first; it != range.second; ++it) {
        const auto mit = mapWallet.find(it->second);
        if (mit == mapWallet.end()) continue;
        const CWalletTx* wtx = &mit->second;
        if (wtx->nOrderPos < nMinOrderPos) {
            nMinOrderPos = static_cast<int>(wtx->nOrderPos);
            copyFrom = wtx;
        }
    }
    if (!copyFrom) return;
    for (auto it = range.first; it != range.second; ++it) {
        const auto mit = mapWallet.find(it->second);
        if (mit == mapWallet.end()) continue;
        CWalletTx* copyTo = &mit->second;
        if (copyFrom == copyTo) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        copyTo->nTimeReceived = copyFrom->nTimeReceived;
    }
}

bool CWallet::IsSpent(const COutPoint& outpoint) const
{
    const auto range = mapTxSpends.equal_range(outpoint);
    for (auto it = range.first; it != range.second; ++it) {
        const auto mi = mapWallet.find(it->second);
        if (mi != mapWallet.end()) {
            const CWalletTx& wtx = mi->second;
            if (!wtx.isAbandoned() && !wtx.isBlockConflicted() && !wtx.isMempoolConflicted()) {
                return true; // spent by a live wallet transaction
            }
        }
    }
    return false;
}

std::set<Txid> CWallet::GetConflicts(const Txid& txid) const
{
    std::set<Txid> result;
    const auto it = mapWallet.find(txid);
    if (it == mapWallet.end()) return result;
    const CWalletTx& wtx = it->second;
    for (const CTxIn& txin : wtx.tx->vin) {
        const auto range = mapTxSpends.equal_range(txin.prevout);
        for (auto i = range.first; i != range.second; ++i) result.insert(i->second);
    }
    result.erase(txid);
    return result;
}

std::set<Txid> CWallet::GetTxConflicts(const CWalletTx& wtx) const { return GetConflicts(wtx.GetHash()); }

bool CWallet::HasWalletSpend(const CTransactionRef& tx) const
{
    const Txid& txid = tx->GetHash();
    for (uint32_t i = 0; i < tx->vout.size(); ++i) {
        if (mapTxSpends.count(COutPoint(txid, i)) > 0) return true;
    }
    return false;
}

bool CWallet::IsSpentKey(const CScript& scriptPubKey) const
{
    CTxDestination dest;
    if (!ExtractDestination(scriptPubKey, dest)) return false;
    const auto it = m_address_book.find(dest);
    return it != m_address_book.end() && it->second.previously_spent;
}

void CWallet::SetSpentKeyState(WalletBatch& batch, const Txid& hash, unsigned int n, bool used, std::set<CTxDestination>& tx_destinations)
{
    const auto mi = mapWallet.find(hash);
    if (mi == mapWallet.end() || n >= mi->second.tx->vout.size()) return;
    CTxDestination dst;
    const CScript& scriptPubKey = mi->second.tx->vout[n].scriptPubKey;
    if (ExtractDestination(scriptPubKey, dst) && IsMine(scriptPubKey)) {
        if (used && !m_address_book[dst].previously_spent) tx_destinations.insert(dst);
        SetAddressPreviouslySpent(batch, dst, used);
    }
}

void CWallet::MarkDestinationsDirty(const std::set<CTxDestination>& /*destinations*/)
{
    // CWalletTx caches credit/debit lazily; the balance layer recomputes from the TXO
    // cache, so there is no per-destination cache to invalidate here.
}

// ====================================================================== TXO model
//
// Balance bucketing (wallet/receive.cpp) and coin selection (wallet/coinselection.cpp,
// wallet/spend.cpp) read the wallet's outputs through this cache + HowSpent().

CWallet::SpendType CWallet::HowSpent(const COutPoint& outpoint) const
{
    SpendType st{SpendType::UNSPENT};
    const auto range = mapTxSpends.equal_range(outpoint);
    for (auto it = range.first; it != range.second; ++it) {
        const auto mit = mapWallet.find(it->second);
        if (mit != mapWallet.end()) {
            const CWalletTx& wtx = mit->second;
            if (wtx.isConfirmed()) return SpendType::CONFIRMED;
            if (wtx.InMempool()) {
                st = SpendType::MEMPOOL;
            } else if (!wtx.isAbandoned() && !wtx.isBlockConflicted() && !wtx.isMempoolConflicted()) {
                if (st == SpendType::UNSPENT) st = SpendType::NONMEMPOOL;
            }
        }
    }
    return st;
}

std::optional<WalletTXO> CWallet::GetTXO(const COutPoint& outpoint) const
{
    AssertLockHeld(cs_wallet);
    const auto it = m_txos.find(outpoint);
    if (it == m_txos.end()) return std::nullopt;
    return it->second;
}

void CWallet::RefreshTXOsFromTx(const CWalletTx& wtx)
{
    AssertLockHeld(cs_wallet);
    for (uint32_t i = 0; i < wtx.tx->vout.size(); ++i) {
        const CTxOut& txout = wtx.tx->vout.at(i);
        if (!IsMine(txout)) continue;
        const COutPoint outpoint(wtx.GetHash(), i);
        if (!m_txos.contains(outpoint)) {
            m_txos.emplace(outpoint, WalletTXO{wtx, txout});
        }
    }
}

void CWallet::RefreshAllTXOs()
{
    AssertLockHeld(cs_wallet);
    for (const auto& [_, wtx] : mapWallet) {
        RefreshTXOsFromTx(wtx);
    }
}

// ============================================================== tx ingestion

const CWalletTx* CWallet::GetWalletTx(const Txid& hash) const
{
    const auto it = mapWallet.find(hash);
    return it == mapWallet.end() ? nullptr : &it->second;
}

unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx, bool rescanning_old_block) const
{
    std::optional<uint256> block_hash;
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        block_hash = conf->confirmed_block_hash;
    } else if (auto* conf = wtx.state<TxStateBlockConflicted>()) {
        block_hash = conf->conflicting_block_hash;
    }

    unsigned int nTimeSmart = wtx.nTimeReceived;
    // A chain-less wallet (wallet-tool / unit tests) cannot resolve block times,
    // so the smart time stays at the receive time.
    if (block_hash && HaveChain()) {
        int64_t blocktime;
        int64_t block_max_time;
        if (chain().findBlock(*block_hash, FoundBlock().time(blocktime).maxTime(block_max_time))) {
            if (rescanning_old_block) {
                nTimeSmart = block_max_time;
            } else {
                int64_t latestNow = wtx.nTimeReceived;
                int64_t latestEntry = 0;

                // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                int64_t latestTolerated = latestNow + 300;
                // Lattica keeps no persistent wtxOrdered multimap, so build the
                // reverse-nOrderPos view on demand and scan for the latest tolerable
                // neighbouring smart-time (mirrors Core's wtxOrdered loop).
                std::vector<const CWalletTx*> ordered;
                ordered.reserve(mapWallet.size());
                for (const auto& [hash, entry] : mapWallet) ordered.push_back(&entry);
                std::sort(ordered.begin(), ordered.end(), [](const CWalletTx* a, const CWalletTx* b) { return a->nOrderPos > b->nOrderPos; });
                for (const CWalletTx* pwtx : ordered) {
                    if (pwtx == &wtx) {
                        continue;
                    }
                    int64_t nSmartTime = pwtx->nTimeSmart;
                    if (!nSmartTime) {
                        nSmartTime = pwtx->nTimeReceived;
                    }
                    if (nSmartTime <= latestTolerated) {
                        latestEntry = nSmartTime;
                        if (nSmartTime > latestNow) {
                            latestNow = nSmartTime;
                        }
                        break;
                    }
                }

                nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
            }
        } else {
            WalletLogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), block_hash->ToString());
        }
    }
    return nTimeSmart;
}

CWalletTx* CWallet::AddToWallet(CTransactionRef tx, const TxState& state, const UpdateWalletTxFn& update_wtx, bool rescanning_old_block)
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());
    const Txid hash = tx->GetHash();

    if (IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
        std::set<CTxDestination> tx_destinations;
        for (const CTxIn& txin : tx->vin) SetSpentKeyState(batch, txin.prevout.hash, txin.prevout.n, true, tx_destinations);
        MarkDestinationsDirty(tx_destinations);
    }

    auto ret = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(tx, state));
    CWalletTx& wtx = ret.first->second;
    bool fInsertedNew = ret.second;
    bool fUpdated = update_wtx && update_wtx(wtx, fInsertedNew);
    if (fInsertedNew) {
        wtx.nTimeReceived = GetTime();
        wtx.nOrderPos = IncOrderPosNext(&batch);
        AddToSpends(wtx);
        wtx.nTimeSmart = ComputeTimeSmart(wtx, rescanning_old_block);
        MaybeUpdateBirthTime(wtx.nTimeReceived);
    } else if (state.index() != wtx.m_state.index()) {
        wtx.m_state = state;
        fUpdated = true;
    }

    // Mark inactive coinbase transactions as abandoned.
    if (wtx.IsCoinBase() && wtx.isInactive()) {
        wtx.m_state = TxStateInactive{/*abandoned=*/true};
        fUpdated = true;
    }

    if (fInsertedNew || fUpdated) {
        if (!batch.WriteTx(wtx)) return nullptr;
    }

    // Break debit/credit balance caches and cache the outputs that belong to us.
    wtx.MarkDirty();
    RefreshTXOsFromTx(wtx);

    NotifyTransactionChanged(hash, fInsertedNew ? CT_NEW : CT_UPDATED);
    return &wtx;
}

bool CWallet::LoadToWallet(const Txid& hash, const UpdateWalletTxFn& fill_wtx)
{
    auto ins = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(nullptr, TxStateInactive{}));
    CWalletTx& wtx = ins.first->second;
    if (!fill_wtx(wtx, ins.second)) return false;
    AddToSpends(wtx);
    for (const CTxIn& txin : wtx.tx->vin) {
        const auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            if (auto* prev = it->second.state<TxStateBlockConflicted>()) {
                MarkConflicted(prev->conflicting_block_hash, prev->conflicting_block_height, wtx.GetHash());
            }
        }
    }
    MaybeUpdateBirthTime(wtx.nTimeReceived);
    RefreshTXOsFromTx(wtx);
    return true;
}

bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const SyncTxState& state, bool rescanning_old_block)
{
    AssertLockHeld(cs_wallet);
    const CTransaction& tx = *ptx;

    bool involved = false;
    for (const CTxOut& txout : tx.vout) {
        if (IsMine(txout)) { involved = true; break; }
    }
    if (!involved) {
        for (const CTxIn& txin : tx.vin) {
            const auto mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end() && txin.prevout.n < mi->second.tx->vout.size() &&
                IsMine(mi->second.tx->vout[txin.prevout.n])) { involved = true; break; }
        }
    }
    if (!involved && mapWallet.find(tx.GetHash()) == mapWallet.end()) return false;

    // Build the full TxState from the SyncTxState and ingest.
    TxState tx_state = std::visit([](auto&& s) -> TxState { return s; }, state);
    return AddToWallet(ptx, tx_state, /*update_wtx=*/nullptr, rescanning_old_block) != nullptr;
}

bool CWallet::SyncTransaction(const CTransactionRef& ptx, const SyncTxState& state, bool rescanning_old_block)
{
    if (!AddToWalletIfInvolvingMe(ptx, state, rescanning_old_block)) return false;
    MarkInputsDirty(ptx);
    return true;
}

void CWallet::MarkInputsDirty(const CTransactionRef& tx)
{
    // A change in this tx's state changes the spendable balance of the coins it spends,
    // so force those parents' caches to recompute.
    for (const CTxIn& txin : tx->vin) {
        const auto mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end()) mi->second.MarkDirty();
    }
}

void CWallet::RecursiveUpdateTxState(WalletBatch* batch, const Txid& tx_hash, const TryUpdatingStateFn& try_updating_state)
{
    std::set<Txid> todo{tx_hash};
    while (!todo.empty()) {
        const Txid now = *todo.begin();
        todo.erase(now);
        const auto it = mapWallet.find(now);
        if (it == mapWallet.end()) continue;
        CWalletTx& wtx = it->second;
        const TxUpdate update_state = try_updating_state(wtx);
        if (update_state != TxUpdate::UNCHANGED) {
            wtx.MarkDirty();
            if (batch) batch->WriteTx(wtx);
            for (uint32_t i = 0; i < wtx.tx->vout.size(); ++i) {
                const auto range = mapTxSpends.equal_range(COutPoint(now, i));
                for (auto r = range.first; r != range.second; ++r) {
                    if (todo.count(r->second) == 0) todo.insert(r->second);
                }
            }
            if (update_state == TxUpdate::NOTIFY_CHANGED) NotifyTransactionChanged(now, CT_UPDATED);
            MarkInputsDirty(wtx.tx);
        }
    }
}

void CWallet::MarkConflicted(const uint256& hashBlock, int conflicting_height, const Txid& hashTx)
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());
    RecursiveUpdateTxState(&batch, hashTx, [&](CWalletTx& wtx) {
        if (wtx.isBlockConflicted()) return TxUpdate::UNCHANGED;
        wtx.m_state = TxStateBlockConflicted{hashBlock, conflicting_height};
        return TxUpdate::CHANGED;
    });
}

// ============================================================== notifications

void CWallet::transactionAddedToMempool(const CTransactionRef& tx)
{
    LOCK(cs_wallet);
    SyncTransaction(tx, TxStateInMempool{});
}

void CWallet::transactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason)
{
    LOCK(cs_wallet);
    if (reason == MemPoolRemovalReason::BLOCK) return;    // handled by blockConnected
    if (reason == MemPoolRemovalReason::CONFLICT) return; // handled by blockConnected's MarkConflicted
    const auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end() && it->second.state<TxStateInMempool>()) {
        it->second.m_state = TxStateInactive{};
        WalletBatch(GetDatabase()).WriteTx(it->second);
    }
}

void CWallet::blockConnected(const kernel::ChainstateRole& role, const interfaces::BlockInfo& block)
{
    if (role.historical) return; // ignore background/assumeutxo validation chainstate
    LOCK(cs_wallet);
    SetLastBlockProcessed(block.height, block.hash);
    if (!block.data) return;
    for (size_t i = 0; i < block.data->vtx.size(); ++i) {
        SyncTransaction(block.data->vtx[i], TxStateConfirmed{block.hash, block.height, int(i)});
    }
}

void CWallet::blockDisconnected(const interfaces::BlockInfo& block)
{
    LOCK(cs_wallet);
    SetLastBlockProcessed(block.height - 1, block.prev_hash ? *block.prev_hash : uint256());
    if (!block.data) return;
    for (const CTransactionRef& tx : block.data->vtx) {
        SyncTransaction(tx, TxStateInactive{});
    }
}

void CWallet::updatedBlockTip() { m_best_block_time = GetTime(); }

CWallet::ScanResult CWallet::ScanForWalletTransactions(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, const bool save_progress)
{
    constexpr auto INTERVAL_TIME{std::chrono::minutes{1}};
    auto current_time{reserver.now()};
    auto start_time{reserver.now()};

    assert(reserver.isReserved());

    uint256 block_hash = start_block;
    ScanResult result;

    WalletLogPrintf("Rescan started from block %s...\n", start_block.ToString());

    ShowProgress(strprintf("[%s] %s", GetName(), "Rescanning…"), 0);
    uint256 tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
    uint256 end_hash = tip_hash;
    if (max_height) chain().findAncestorByHeight(tip_hash, *max_height, FoundBlock().hash(end_hash));
    double progress_begin = chain().guessVerificationProgress(block_hash);
    double progress_end = chain().guessVerificationProgress(end_hash);
    double progress_current = progress_begin;
    int block_height = start_height;
    while (!fAbortRescan && !chain().shutdownRequested()) {
        if (progress_end - progress_begin > 0.0) {
            m_scanning_progress = (progress_current - progress_begin) / (progress_end - progress_begin);
        } else { // avoid divide-by-zero for single block scan range
            m_scanning_progress = 0;
        }
        if (block_height % 100 == 0 && progress_end - progress_begin > 0.0) {
            ShowProgress(strprintf("[%s] %s", GetName(), "Rescanning…"), std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
        }

        bool next_interval = reserver.now() >= current_time + INTERVAL_TIME;
        if (next_interval) {
            current_time = reserver.now();
            WalletLogPrintf("Still rescanning. At block %d. Progress=%f\n", block_height, progress_current);
        }

        // Find next block separately from reading data below, because reading is
        // slow and there might be a reorg while it is read.
        bool block_still_active = false;
        bool next_block = false;
        uint256 next_block_hash;
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).nextBlock(FoundBlock().inActiveChain(next_block).hash(next_block_hash)));

        {
            // Read block data and locator if needed (the locator is usually null unless we need to save progress)
            CBlock block;
            CBlockLocator loc;
            FoundBlock found_block{FoundBlock().data(block)};
            if (save_progress && next_interval) found_block.locator(loc);
            chain().findBlock(block_hash, found_block);

            if (!block.IsNull()) {
                LOCK(cs_wallet);
                if (!block_still_active) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    SyncTransaction(block.vtx[posInBlock], TxStateConfirmed{block_hash, block_height, static_cast<int>(posInBlock)}, /*rescanning_old_block=*/true);
                }
                // scan succeeded, record block as most recent successfully scanned
                result.last_scanned_block = block_hash;
                result.last_scanned_height = block_height;

                if (!loc.IsNull()) {
                    WalletLogPrintf("Saving scan progress %d.\n", block_height);
                    WalletBatch batch(GetDatabase());
                    batch.WriteBestBlock(loc);
                }
            } else {
                // could not scan block, keep scanning but record this block as the most recent failure
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
            }
        }
        if (max_height && block_height >= *max_height) {
            break;
        }
        if (block_height >= WITH_LOCK(cs_wallet, return GetLastBlockHeight())) {
            break;
        }

        {
            if (!next_block) {
                // break successfully when rescan has reached the tip, or
                // previous block is no longer on the chain due to a reorg
                break;
            }

            // increment block and verification progress
            block_hash = next_block_hash;
            ++block_height;
            progress_current = chain().guessVerificationProgress(block_hash);

            // handle updated tip hash
            const uint256 prev_tip_hash = tip_hash;
            tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
            if (!max_height && prev_tip_hash != tip_hash) {
                progress_end = chain().guessVerificationProgress(tip_hash);
            }
        }
    }
    if (!max_height) {
        WalletLogPrintf("Scanning current mempool transactions.\n");
        WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
    }
    ShowProgress(strprintf("[%s] %s", GetName(), "Rescanning…"), 100);
    if (fAbortRescan) {
        WalletLogPrintf("Rescan aborted at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else if (chain().shutdownRequested()) {
        WalletLogPrintf("Rescan interrupted by shutdown request at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else {
        WalletLogPrintf("Rescan completed in %15dms\n", Ticks<std::chrono::milliseconds>(reserver.now() - start_time));
    }
    return result;
}

void CWallet::BlockUntilSyncedToCurrentChain() const
{
    AssertLockNotHeld(cs_wallet);
    if (!m_chain) return;
    uint256 last_block_hash{WITH_LOCK(cs_wallet, return m_last_block_processed)};
    m_chain->waitForNotificationsIfTipChanged(last_block_hash);
}

// ============================================================== chain view

void CWallet::SetLastBlockProcessedInMem(int block_height, uint256 block_hash)
{
    m_last_block_processed_height = block_height;
    m_last_block_processed = block_hash;
}

void CWallet::SetLastBlockProcessed(int block_height, uint256 block_hash)
{
    SetLastBlockProcessedInMem(block_height, block_hash);
    WriteBestBlock();
}

void CWallet::WriteBestBlock() const
{
    if (!m_database || m_last_block_processed_height < 0 || !m_chain) return;
    // Persist the processed position as a CBlockLocator so a reload can detect and scan the
    // gap of blocks that were connected while the wallet was closed (see AttachChain). A
    // locator — not a bare (height,hash) — lets findLocatorFork walk back correctly across a
    // reorg. Written on every processed block, so both a graceful close and a crash leave a
    // usable checkpoint on disk.
    CBlockLocator loc;
    if (chain().findBlock(m_last_block_processed, FoundBlock().locator(loc)) && !loc.IsNull()) {
        WalletBatch batch(GetDatabase());
        batch.WriteBestBlock(loc);
    }
}

void CWallet::MaybeUpdateBirthTime(int64_t time)
{
    int64_t cur = m_birth_time.load();
    while (time < cur && !m_birth_time.compare_exchange_weak(cur, time)) {}
}

// ============================================================== ownership

bool CWallet::IsMine(const CScript& script) const
{
    CTxDestination dest;
    if (!ExtractDestination(script, dest)) return false;
    LOCK(cs_wallet);
    const CKeyID keyid = GetKeyForDestination(*this, dest);
    if (keyid.IsNull()) return false;
    // HaveKey covers an unlocked wallet; m_pubkey_ids additionally covers a locked encrypted
    // wallet whose private keys are not re-derived yet but whose outputs are still ours.
    return HaveKey(keyid) || m_pubkey_ids.count(keyid) > 0;
}

bool CWallet::IsMine(const CTxOut& txout) const { return IsMine(txout.scriptPubKey); }
bool CWallet::IsMine(const CTxDestination& dest) const { return IsMine(GetScriptForDestination(dest)); }

bool CWallet::IsMine(const CTransaction& tx) const
{
    for (const CTxOut& txout : tx.vout) {
        if (IsMine(txout)) return true;
    }
    return false;
}

bool CWallet::IsMine(const COutPoint& outpoint) const
{
    const auto mi = mapWallet.find(outpoint.hash);
    if (mi == mapWallet.end() || outpoint.n >= mi->second.tx->vout.size()) return false;
    return IsMine(mi->second.tx->vout[outpoint.n]);
}

CAmount CWallet::GetDebit(const CTxIn& txin) const
{
    LOCK(cs_wallet);
    const auto txo = GetTXO(txin.prevout);
    if (txo) return txo->GetTxOut().nValue;
    return 0;
}

CAmount CWallet::GetDebit(const CTransaction& tx) const
{
    CAmount debit = 0;
    for (const CTxIn& txin : tx.vin) debit += GetDebit(txin);
    return debit;
}

CAmount CWallet::GetCredit(const CTxOut& txout) const { return IsMine(txout) ? txout.nValue : 0; }

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    LOCK(cs_wallet);
    for (const CTxIn& txin : tx.vin) {
        if (GetTXO(txin.prevout)) return true;
    }
    return false;
}

// ============================================================== depth/maturity

int CWallet::GetTxDepthInMainChain(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);
    if (const auto* conf = wtx.state<TxStateConfirmed>()) {
        return m_last_block_processed_height - conf->confirmed_block_height + 1;
    }
    if (const auto* conflicted = wtx.state<TxStateBlockConflicted>()) {
        return -(m_last_block_processed_height - conflicted->conflicting_block_height + 1);
    }
    return 0; // in mempool / inactive
}

int CWallet::GetTxBlocksToMaturity(const CWalletTx& wtx) const
{
    if (!wtx.IsCoinBase()) return 0;
    const int depth = GetTxDepthInMainChain(wtx);
    if (depth < 0) return 0;
    return std::max(0, (COINBASE_MATURITY + 1) - depth);
}

bool CWallet::IsTxImmatureCoinBase(const CWalletTx& wtx) const { return GetTxBlocksToMaturity(wtx) > 0; }

// ============================================================== abandon/conflict

bool CWallet::TransactionCanBeAbandoned(const Txid& hashTx) const
{
    LOCK(cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && GetTxDepthInMainChain(*wtx) == 0 && !wtx->state<TxStateInMempool>();
}

bool CWallet::AbandonTransaction(const Txid& hashTx)
{
    LOCK(cs_wallet);
    const auto it = mapWallet.find(hashTx);
    if (it == mapWallet.end()) return false;
    return AbandonTransaction(it->second);
}

bool CWallet::AbandonTransaction(CWalletTx& tx)
{
    AssertLockHeld(cs_wallet);
    if (GetTxDepthInMainChain(tx) != 0 || tx.state<TxStateInMempool>()) return false;
    WalletBatch batch(GetDatabase());
    RecursiveUpdateTxState(&batch, tx.GetHash(), [](CWalletTx& wtx) {
        if (wtx.isAbandoned()) return TxUpdate::UNCHANGED;
        wtx.m_state = TxStateInactive{/*abandoned=*/true};
        return TxUpdate::NOTIFY_CHANGED;
    });
    return true;
}

bool CWallet::MarkReplaced(const Txid& originalHash, const Txid& newHash)
{
    LOCK(cs_wallet);
    const auto mi = mapWallet.find(originalHash);
    if (mi == mapWallet.end()) return false;
    CWalletTx& wtx = mi->second;
    wtx.mapValue["replaced_by_txid"] = newHash.ToString();
    return WalletBatch(GetDatabase()).WriteTx(wtx);
}

util::Result<void> CWallet::RemoveTxs(std::vector<Txid>& txs_to_remove)
{
    AssertLockHeld(cs_wallet);
    bilingual_str str_err;  // future: make RunWithinTxn return a util::Result
    bool was_txn_committed = RunWithinTxn(GetDatabase(), /*process_desc=*/"remove transactions", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        util::Result<void> result{RemoveTxs(batch, txs_to_remove)};
        if (!result) str_err = util::ErrorString(result);
        return result.has_value();
    });
    if (!str_err.empty()) return util::Error{str_err};
    if (!was_txn_committed) return util::Error{_("Error starting/committing db txn for wallet transactions removal process")};
    return {}; // all good
}

util::Result<void> CWallet::RemoveTxs(WalletBatch& batch, std::vector<Txid>& txs_to_remove)
{
    AssertLockHeld(cs_wallet);
    if (!batch.HasActiveTxn()) return util::Error{strprintf(_("The transactions removal process can only be executed within a db txn"))};

    // Check for transaction existence and remove entries from disk
    std::vector<decltype(mapWallet)::const_iterator> erased_txs;
    for (const Txid& hash : txs_to_remove) {
        auto it_wtx = mapWallet.find(hash);
        if (it_wtx == mapWallet.end()) {
            return util::Error{strprintf(_("Transaction %s does not belong to this wallet"), hash.GetHex())};
        }
        if (!batch.EraseTx(hash)) {
            return util::Error{strprintf(_("Failure removing transaction: %s"), hash.GetHex())};
        }
        erased_txs.emplace_back(it_wtx);
    }

    // Register callback to update the memory state only when the db txn is actually dumped to disk
    batch.RegisterTxnListener({.on_commit=[&, erased_txs]() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        // Update the in-memory state and notify upper layers about the removals.
        // Lattica keeps no ordered tx index (Core's wtxOrdered), so there is no
        // ordered-list entry to erase here.
        for (const auto& it : erased_txs) {
            const Txid hash{it->first};
            for (const auto& txin : it->second.tx->vin) {
                auto range = mapTxSpends.equal_range(txin.prevout);
                for (auto iter = range.first; iter != range.second; ++iter) {
                    if (iter->second == hash) {
                        mapTxSpends.erase(iter);
                        break;
                    }
                }
            }
            for (unsigned int i = 0; i < it->second.tx->vout.size(); ++i) {
                m_txos.erase(COutPoint(hash, i));
            }
            mapWallet.erase(it);
            NotifyTransactionChanged(hash, CT_DELETED);
        }

        MarkDirty();
    }, .on_abort={}});

    return {};
}

void CWallet::MarkDirty()
{
    LOCK(cs_wallet);
    for (auto& [_, wtx] : mapWallet) wtx.MarkDirty();
}

int64_t CWallet::IncOrderPosNext(WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    const int64_t pos = nOrderPosNext++;
    if (batch) batch->WriteOrderPosNext(nOrderPosNext);
    else WalletBatch(GetDatabase()).WriteOrderPosNext(nOrderPosNext);
    return pos;
}

DBErrors CWallet::ReorderTransactions() { return DBErrors::LOAD_OK; }

// ============================================================== coin locking

bool CWallet::LockCoin(const COutPoint& output, bool persist)
{
    const bool inserted = m_locked_coins.insert(output).second;
    if (inserted && persist && m_database) WalletBatch(GetDatabase()).WriteLockedUTXO(output);
    return inserted;
}

bool CWallet::UnlockCoin(const COutPoint& output)
{
    const bool erased = m_locked_coins.erase(output) > 0;
    if (erased && m_database) WalletBatch(GetDatabase()).EraseLockedUTXO(output);
    return erased;
}

bool CWallet::UnlockAllCoins()
{
    if (m_database) {
        WalletBatch batch(GetDatabase());
        for (const COutPoint& o : m_locked_coins) batch.EraseLockedUTXO(o);
    }
    m_locked_coins.clear();
    return true;
}

bool CWallet::IsLockedCoin(const COutPoint& output) const { return m_locked_coins.count(output) > 0; }
void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const { vOutpts.assign(m_locked_coins.begin(), m_locked_coins.end()); }

// ============================================================== signing

bool CWallet::SignTransaction(CMutableTransaction& tx) const
{
    AssertLockHeld(cs_wallet);
    // Gather the spent coins from mapWallet, then sign with SIGHASH_ALL.
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : tx.vin) {
        const auto mi = mapWallet.find(txin.prevout.hash);
        if (mi == mapWallet.end() || txin.prevout.n >= mi->second.tx->vout.size()) return false;
        coins[txin.prevout] = Coin(mi->second.tx->vout[txin.prevout.n], /*nHeightIn=*/0, /*fCoinBaseIn=*/false);
    }
    std::map<int, bilingual_str> input_errors;
    return SignTransaction(tx, coins, SIGHASH_ALL, input_errors);
}

bool CWallet::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    bool ok = true;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const auto it = coins.find(tx.vin[i].prevout);
        if (it == coins.end()) { input_errors[int(i)] = Untranslated("Input not found"); ok = false; continue; }
        const CTxOut& out = it->second.out;
        SignatureData sigdata;
        if (!SignSignature(*this, out.scriptPubKey, tx, static_cast<unsigned int>(i), out.nValue, sighash, sigdata)) {
            input_errors[int(i)] = Untranslated("Signing failed");
            ok = false;
        }
    }
    return ok;
}

// =============================================================== broadcast

void CWallet::CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm)
{
    LOCK(cs_wallet);
    CWalletTx* wtx = AddToWallet(tx, TxStateInactive{}, [&](CWalletTx& w, bool /*new_tx*/) {
        w.mapValue = std::move(mapValue);
        w.vOrderForm = std::move(orderForm);
        return true;
    });
    if (!wtx) return;
    // Mark the inputs dirty so their owning txs' caches recompute and notify the UI.
    for (const CTxIn& txin : tx->vin) {
        const auto mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end()) {
            mi->second.MarkDirty();
            NotifyTransactionChanged(mi->second.GetHash(), CT_UPDATED);
        }
    }
    if (!fBroadcastTransactions) return;
    std::string err;
    SubmitTxMemoryPoolAndRelay(*wtx, err, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL);
}

bool CWallet::SubmitTxMemoryPoolAndRelay(CWalletTx& wtx, std::string& err_string, node::TxBroadcast broadcast_method) const
{
    AssertLockHeld(cs_wallet);
    // Can't relay if not broadcasting; don't relay abandoned/coinbase/confirmed txs.
    if (!GetBroadcastTransactions()) return false;
    if (wtx.isAbandoned()) return false;
    if (wtx.IsCoinBase()) return false;
    if (GetTxDepthInMainChain(wtx) != 0) return false;
    if (!m_chain) return false;
    // Set TxStateInMempool eagerly so the change becomes spendable immediately on
    // success (mirrors Core; the entered-mempool callback would set it later anyway).
    const bool ret = m_chain->broadcastTransaction(wtx.tx, m_default_max_tx_fee, broadcast_method, err_string);
    if (ret) wtx.m_state = TxStateInMempool{};
    return ret;
}

NodeClock::time_point CWallet::GetDefaultNextResend()
{
    FastRandomContext rng;
    // 12-36 hours from now (~1 day on average), to obfuscate which txs are ours.
    return NodeClock::now() + std::chrono::hours{12} + std::chrono::seconds{rng.randrange(24 * 60 * 60)};
}

bool CWallet::ShouldResend() const
{
    if (!fBroadcastTransactions) return false;
    if (!chain().isReadyToBroadcast()) return false;
    if (NodeClock::now() < m_next_resend) return false;
    return true;
}

void CWallet::ResubmitWalletTransactions(node::TxBroadcast broadcast_method, bool force)
{
    if (!fBroadcastTransactions) return;
    int submitted_tx_count = 0;
    {
        LOCK(cs_wallet);
        // Collect unconfirmed txs and resubmit in insertion (nOrderPos) order.
        std::vector<CWalletTx*> to_submit;
        for (auto& [txid, wtx] : mapWallet) {
            if (!wtx.isUnconfirmed()) continue;
            if (!force && wtx.nTimeReceived > m_best_block_time - 5 * 60) continue;
            to_submit.push_back(&wtx);
        }
        std::sort(to_submit.begin(), to_submit.end(),
                  [](const CWalletTx* a, const CWalletTx* b) { return a->nOrderPos < b->nOrderPos; });
        for (CWalletTx* wtx : to_submit) {
            std::string unused_err_string;
            if (SubmitTxMemoryPoolAndRelay(*wtx, unused_err_string, broadcast_method)) ++submitted_tx_count;
        }
    }
    if (submitted_tx_count > 0) {
        WalletLogPrintf("%s: resubmit %u unconfirmed transactions\n", __func__, submitted_tx_count);
    }
}

void MaybeResendWalletTxs(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        if (!pwallet->ShouldResend()) continue;
        pwallet->ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL, /*force=*/false);
        pwallet->SetNextResend();
    }
}

// =================================================== solving provider / change type

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script) const
{
    SignatureData sigdata;
    return GetSolvingProvider(script, sigdata);
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script, SignatureData& /*sigdata*/) const
{
    // Lattica's keystore is the wallet itself, and signing goes through
    // SignTransaction; signed sizes are fixed for ML-DSA, so spend.cpp never consults
    // the returned provider. We still hand back a best-effort FlatSigningProvider
    // carrying our key material for `script` so the contract is honest.
    LOCK(cs_wallet);
    if (!IsMine(script)) return nullptr;
    auto provider = std::make_unique<FlatSigningProvider>();
    CTxDestination dest;
    if (ExtractDestination(script, dest)) {
        const CKeyID keyid = GetKeyForDestination(*this, dest);
        if (!keyid.IsNull()) {
            CPubKey pub;
            if (GetPubKey(keyid, pub)) provider->pubkeys.emplace(keyid, pub);
            CKey key;
            if (FillableSigningProvider::GetKey(keyid, key)) provider->keys.emplace(keyid, key);
        }
    }
    provider->scripts.emplace(CScriptID(script), script);
    return provider;
}

OutputType CWallet::TransactionChangeType(const std::optional<OutputType>& change_type, const std::vector<CRecipient>& /*vecSend*/) const
{
    // -changetype wins; otherwise the wallet's configured change/address type. Lattica
    // only derives and spends witness-v0 (P2WPKH), so there is no per-recipient type
    // matching as in Core.
    if (change_type) return *change_type;
    if (m_default_change_type) return *m_default_change_type;
    return m_default_address_type;
}

void CWallet::DisconnectChainNotifications()
{
    if (m_chain_notifications_handler) {
        m_chain_notifications_handler->disconnect();
        chain().waitForNotifications();
        m_chain_notifications_handler.reset();
    }
}

// ============================================================== address book

const CAddressBookData* CWallet::FindAddressBookEntry(const CTxDestination& dest, bool allow_change) const
{
    const auto it = m_address_book.find(dest);
    if (it == m_address_book.end()) return nullptr;
    if (!allow_change && it->second.IsChange()) return nullptr;
    return &it->second;
}

bool CWallet::SetAddressBookWithDB(WalletBatch& batch, const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& new_purpose)
{
    bool is_mine;
    {
        LOCK(cs_wallet);
        CAddressBookData& entry = m_address_book[address];
        entry.SetLabel(strName);
        if (new_purpose) entry.purpose = new_purpose;
        is_mine = IsMine(address);
        assert(m_params);
        const std::string addr = EncodeDestination(address, *m_params);
        if (!batch.WriteName(addr, strName)) return false;
        if (new_purpose && !batch.WritePurpose(addr, PurposeToString(*new_purpose))) return false;
    }
    NotifyAddressBookChanged(address, strName, is_mine, new_purpose.value_or(AddressPurpose::RECEIVE), CT_NEW);
    return true;
}

bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& purpose)
{
    WalletBatch batch(GetDatabase());
    return SetAddressBookWithDB(batch, address, strName, purpose);
}

bool CWallet::DelAddressBookWithDB(WalletBatch& batch, const CTxDestination& address)
{
    {
        LOCK(cs_wallet);
        assert(m_params);
        const std::string addr = EncodeDestination(address, *m_params);
        for (const auto& [id, req] : m_address_book[address].receive_requests) batch.EraseAddressReceiveRequest(addr, id);
        m_address_book.erase(address);
        if (!batch.EraseName(addr)) return false;
        if (!batch.ErasePurpose(addr)) return false;
    }
    NotifyAddressBookChanged(address, "", false, AddressPurpose::SEND, CT_DELETED);
    return true;
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    WalletBatch batch(GetDatabase());
    return DelAddressBookWithDB(batch, address);
}

std::vector<CTxDestination> CWallet::ListAddrBookAddresses(const std::optional<AddrBookFilter>& filter) const
{
    AssertLockHeld(cs_wallet);
    std::vector<CTxDestination> result;
    for (const auto& [dest, data] : m_address_book) {
        if (filter && filter->ignore_change && data.IsChange()) continue;
        if (filter && filter->m_op_label && data.GetLabel() != *filter->m_op_label) continue;
        result.push_back(dest);
    }
    return result;
}

std::set<std::string> CWallet::ListAddrBookLabels(std::optional<AddressPurpose> purpose) const
{
    AssertLockHeld(cs_wallet);
    std::set<std::string> labels;
    for (const auto& [dest, data] : m_address_book) {
        if (data.IsChange()) continue;
        if (purpose && data.purpose != purpose) continue;
        labels.insert(data.GetLabel());
    }
    return labels;
}

void CWallet::ForEachAddrBookEntry(const ListAddrBookFunc& func) const
{
    AssertLockHeld(cs_wallet);
    for (const auto& [dest, data] : m_address_book) {
        func(dest, data.GetLabel(), data.IsChange(), data.purpose);
    }
}

bool CWallet::IsAddressPreviouslySpent(const CTxDestination& dest) const
{
    const auto it = m_address_book.find(dest);
    return it != m_address_book.end() && it->second.previously_spent;
}

bool CWallet::SetAddressPreviouslySpent(WalletBatch& batch, const CTxDestination& dest, bool used)
{
    m_address_book[dest].previously_spent = used;
    assert(m_params);
    return batch.WriteAddressPreviouslySpent(EncodeDestination(dest, *m_params), used);
}

std::vector<std::string> CWallet::GetAddressReceiveRequests() const
{
    AssertLockHeld(cs_wallet);
    std::vector<std::string> result;
    for (const auto& [dest, data] : m_address_book) {
        for (const auto& [id, req] : data.receive_requests) result.push_back(req);
    }
    return result;
}

bool CWallet::SetAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id, const std::string& value)
{
    assert(m_params);
    const std::string addr = EncodeDestination(dest, *m_params);
    if (value.empty()) {
        m_address_book[dest].receive_requests.erase(id);
        return batch.EraseAddressReceiveRequest(addr, id);
    }
    m_address_book[dest].receive_requests[id] = value;
    return batch.WriteAddressReceiveRequest(addr, id, value);
}

bool CWallet::EraseAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id)
{
    m_address_book[dest].receive_requests.erase(id);
    assert(m_params);
    return batch.EraseAddressReceiveRequest(EncodeDestination(dest, *m_params), id);
}

// ============================================================== wallet flags

void CWallet::SetWalletFlag(uint64_t flags)
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());
    SetWalletFlagWithDB(batch, m_wallet_flags | flags);
}

void CWallet::SetWalletFlagWithDB(WalletBatch& batch, uint64_t flags)
{
    m_wallet_flags = flags;
    if (!batch.WriteWalletFlags(flags)) throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetWalletFlag(uint64_t flag)
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());
    UnsetWalletFlagWithDB(batch, flag);
}

void CWallet::UnsetWalletFlagWithDB(WalletBatch& batch, uint64_t flag)
{
    m_wallet_flags &= ~flag;
    if (!batch.WriteWalletFlags(m_wallet_flags)) throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetBlankWalletFlag(WalletBatch& batch) { UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET); }

bool CWallet::IsWalletFlagSet(uint64_t flag) const { return (m_wallet_flags.load() & flag) != 0; }

void CWallet::InitWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());
    assert(m_wallet_flags == 0);
    SetWalletFlagWithDB(batch, flags);
    if (!LoadWalletFlags(flags)) assert(false);
}

bool CWallet::LoadWalletFlags(uint64_t flags)
{
    if ((flags & ~KNOWN_WALLET_FLAGS) != 0) return false; // unknown non-tolerable flag
    m_wallet_flags = flags;
    return true;
}

uint64_t CWallet::GetWalletFlags() const { return m_wallet_flags.load(); }

// ============================================================== persistence

DBErrors CWallet::PopulateWalletFromDB()
{
    if (!m_database) return DBErrors::LOAD_FAIL;
    WalletBatch batch(*m_database);
    return batch.LoadWallet(this);
}

void CWallet::postInitProcess()
{
    LOCK(cs_wallet);
    // Make sure wallet transactions not yet in a block are in our own mempool, and
    // catch up our state with the node's current mempool.
    ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_NO_BROADCAST, /*force=*/true);
    if (m_chain) m_chain->requestMempoolTransactions(*this);
}

bool CWallet::BackupWallet(const std::string& strDest) const
{
    return m_database && m_database->Backup(strDest);
}

void CWallet::Close()
{
    if (m_database) m_database->Close();
}

// ============================================================== wallet lifecycle

bool AttachChain(const std::shared_ptr<CWallet>& wallet, interfaces::Chain& chain, bilingual_str& error)
{
    wallet->SetChain(&chain);
    // Register on the validation-signal bus before reading the tip, so no block
    // connected after this point is missed. The handler holds a reference to the
    // wallet (CWallet is an interfaces::Chain::Notifications); the cycle is broken by
    // CWallet::DisconnectChainNotifications().
    wallet->m_chain_notifications_handler = chain.handleNotifications(wallet);
    LOCK(wallet->cs_wallet);

    // Where did we leave off? Read the saved best-block locator and find where it forks
    // from the current active chain. Blocks after that fork were connected while the wallet
    // was closed; the validation bus does NOT redeliver them as notifications, so unless we
    // scan them here a reloaded wallet silently misses transactions (miner coinbase payouts,
    // or an exchange's deposits across a daemon restart) until a manual rescanblockchain.
    int rescan_height = 0;
    bool have_locator = false;
    if (wallet->HasDatabase()) {                       // a database-less wallet (some unit tests) has no saved locator
        WalletBatch batch(wallet->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator) && !locator.IsNull()) {
            if (const std::optional<int> fork_height = chain.findLocatorFork(locator)) {
                rescan_height = *fork_height;
                have_locator = true;
            }
        }
    }

    const std::optional<int> tip_height = chain.getHeight();
    if (tip_height) {
        wallet->SetLastBlockProcessed(*tip_height, chain.getBlockHash(*tip_height));
    } else {
        wallet->SetLastBlockProcessed(-1, uint256());
    }

    // CWalletTx serialization stores only the confirming block hash, so a reloaded
    // confirmed transaction comes back with confirmed_block_height = -1 (see
    // TxStateInterpretSerialized). updateState re-derives each height from the chain
    // (and marks reorged-out txs inactive); otherwise GetTxDepthInMainChain
    // over-reports depth, immature coinbase looks mature, and the wallet builds
    // spends the mempool rejects (premature-spend-of-coinbase).
    for (auto& [_, wtx] : wallet->mapWallet) {
        wtx.updateState(chain);
    }

    // Catch up the offline gap (rescan_height .. tip]. Gated on a real saved locator so a
    // freshly created wallet (no locator yet) does not trigger a full-chain rescan; a
    // pre-existing wallet with no locator recovers with one manual rescanblockchain, after
    // which WriteBestBlock keeps the checkpoint current and reloads self-heal.
    if (have_locator && tip_height && *tip_height != rescan_height) {
        // The gap blocks must still be on disk to be scanned. On a pruned node (or while an
        // assumeutxo background sync is in progress) they may not be; fail the load loudly
        // with an actionable message instead of letting ScanForWalletTransactions die with a
        // confusing error — silently skipping would drop confirmed deposits. Mirrors the
        // guard the rescanblockchain RPC already applies.
        const uint256 tip_hash = chain.getBlockHash(*tip_height);
        if (!chain.hasBlocks(tip_hash, rescan_height)) {
            error = Untranslated("Wallet is behind the chain tip, but the blocks connected while it was closed are no longer available (node is pruned, or an assumeutxo background sync is in progress). Reindex (-reindex) or wait for the sync to finish, then reload the wallet.");
            return false;
        }
        WalletRescanReserver reserver(*wallet);
        if (!reserver.reserve()) {
            error = Untranslated("Failed to acquire the rescan lock while catching up the wallet at load");
            return false;
        }
        wallet->WalletLogPrintf("Wallet is behind the tip: scanning blocks %d..%d connected while it was closed.\n",
                                rescan_height, *tip_height);
        const CWallet::ScanResult res = wallet->ScanForWalletTransactions(
            chain.getBlockHash(rescan_height), rescan_height, /*max_height=*/std::nullopt, reserver, /*save_progress=*/true);
        if (res.status != CWallet::ScanResult::SUCCESS) {
            error = Untranslated("Failed to scan the block gap while loading the wallet; run rescanblockchain manually");
            return false;
        }
    }
    return true;
}

bool AddWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    assert(wallet);
    if (std::find(context.wallets.begin(), context.wallets.end(), wallet) != context.wallets.end()) return false;
    context.wallets.push_back(wallet);
    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    const auto it = std::find(context.wallets.begin(), context.wallets.end(), wallet);
    if (it == context.wallets.end()) return false;
    context.wallets.erase(it);
    // Notify listeners (the GUI) that the wallet is unloading, so they tear down their
    // views and drop their shared_ptr references. Upstream emitted this from UnloadWallet(),
    // which Lattica removed along with WaitForDeleteWallet; without the emit, "Close Wallet"
    // removes the wallet from the backend but the GUI never learns and the window stays open.
    // The GUI handler schedules teardown on its own thread (queued), so this returns promptly;
    // the handler disconnects when its WalletModel is destroyed, keeping ~CWallet's
    // assert(NotifyUnload.empty()) valid.
    wallet->NotifyUnload();
    // Break the chain-notifications -> wallet reference cycle and release the
    // database handle (SQLite's exclusive lock), so the wallet can be reloaded in
    // the same session. Lattica has no WaitForDeleteWallet; closing the database
    // explicitly is what frees the lock even if a stray shared_ptr lingers.
    wallet->DisconnectChainNotifications();
    wallet->Close();
    return true;
}

std::vector<std::shared_ptr<CWallet>> GetWallets(WalletContext& context)
{
    LOCK(context.wallets_mutex);
    return context.wallets;
}

std::shared_ptr<CWallet> GetWallet(WalletContext& context, const std::string& name)
{
    LOCK(context.wallets_mutex);
    for (const auto& wallet : context.wallets) {
        if (wallet->GetName() == name) return wallet;
    }
    return nullptr;
}

std::shared_ptr<CWallet> GetDefaultWallet(WalletContext& context, size_t& count)
{
    LOCK(context.wallets_mutex);
    count = context.wallets.size();
    return count == 1 ? context.wallets[0] : nullptr;
}

// ====================================================== wallet lifecycle helpers

bool AddWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    const auto update_function = [&wallet_name](common::SettingsValue& setting_value) {
        if (!setting_value.isArray()) setting_value.setArray();
        for (const auto& value : setting_value.getValues()) {
            if (value.isStr() && value.get_str() == wallet_name) return interfaces::SettingsAction::SKIP_WRITE;
        }
        setting_value.push_back(wallet_name);
        return interfaces::SettingsAction::WRITE;
    };
    return chain.updateRwSetting("wallet", update_function);
}

bool RemoveWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    const auto update_function = [&wallet_name](common::SettingsValue& setting_value) {
        if (!setting_value.isArray()) return interfaces::SettingsAction::SKIP_WRITE;
        common::SettingsValue new_value(common::SettingsValue::VARR);
        for (const auto& value : setting_value.getValues()) {
            if (!value.isStr() || value.get_str() != wallet_name) new_value.push_back(value);
        }
        if (new_value.size() == setting_value.size()) return interfaces::SettingsAction::SKIP_WRITE;
        setting_value = std::move(new_value);
        return interfaces::SettingsAction::WRITE;
    };
    return chain.updateRwSetting("wallet", update_function);
}

static void UpdateWalletSetting(interfaces::Chain& chain,
                                const std::string& wallet_name,
                                std::optional<bool> load_on_startup,
                                std::vector<bilingual_str>& warnings)
{
    if (!load_on_startup) return;
    if (load_on_startup.value() && !AddWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."));
    } else if (!load_on_startup.value() && !RemoveWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may still be loaded next node startup."));
    }
}

//! Read the wallet's fee / behavior settings from the command line into the wallet
//! members the spend and fee layers consume. Without this the wallet keeps its
//! compiled defaults (notably -fallbackfee), so on networks with no fee estimation
//! data it would build zero-fee transactions the mempool rejects.
static bool ApplyWalletArgs(CWallet& wallet, const ArgsManager& args, interfaces::Chain* chain, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    using common::AmountErrMsg;
    using common::AmountHighWarn;

    if (!args.GetArg("-addresstype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-addresstype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown address type '%s'"), args.GetArg("-addresstype", ""));
            return false;
        }
        wallet.m_default_address_type = parsed.value();
    }

    if (!args.GetArg("-changetype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-changetype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown change type '%s'"), args.GetArg("-changetype", ""));
            return false;
        }
        wallet.m_default_change_type = parsed.value();
    }

    if (const auto arg{args.GetArg("-mintxfee")}) {
        std::optional<CAmount> min_tx_fee = ParseMoney(*arg);
        if (!min_tx_fee) {
            error = AmountErrMsg("mintxfee", *arg);
            return false;
        } else if (min_tx_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-mintxfee") + Untranslated(" ") +
                               _("This is the minimum transaction fee you pay on every transaction."));
        }
        wallet.m_min_fee = CFeeRate{min_tx_fee.value()};
    }

    if (const auto arg{args.GetArg("-maxapsfee")}) {
        const std::string& max_aps_fee{*arg};
        if (max_aps_fee == "-1") {
            wallet.m_max_aps_fee = -1;
        } else if (std::optional<CAmount> max_fee = ParseMoney(max_aps_fee)) {
            if (max_fee.value() > HIGH_APS_FEE) {
                warnings.push_back(AmountHighWarn("-maxapsfee") + Untranslated(" ") +
                                  _("This is the maximum transaction fee you pay (in addition to the normal fee) to prioritize partial spend avoidance over regular coin selection."));
            }
            wallet.m_max_aps_fee = max_fee.value();
        } else {
            error = AmountErrMsg("maxapsfee", max_aps_fee);
            return false;
        }
    }

    if (const auto arg{args.GetArg("-fallbackfee")}) {
        std::optional<CAmount> fallback_fee = ParseMoney(*arg);
        if (!fallback_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-fallbackfee", *arg);
            return false;
        } else if (fallback_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-fallbackfee") + Untranslated(" ") +
                               _("This is the transaction fee you may pay when fee estimates are not available."));
        }
        wallet.m_fallback_fee = CFeeRate{fallback_fee.value()};
    }

    // Disable fallback fee in case value was set to 0, enable if non-null value
    wallet.m_allow_fallback_fee = wallet.m_fallback_fee.GetFeePerK() != 0;

    if (const auto arg{args.GetArg("-discardfee")}) {
        std::optional<CAmount> discard_fee = ParseMoney(*arg);
        if (!discard_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-discardfee", *arg);
            return false;
        } else if (discard_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-discardfee") + Untranslated(" ") +
                               _("This is the transaction fee you may discard if change is smaller than dust at this level"));
        }
        wallet.m_discard_rate = CFeeRate{discard_fee.value()};
    }

    if (const auto arg{args.GetArg("-maxtxfee")}) {
        std::optional<CAmount> max_fee = ParseMoney(*arg);
        if (!max_fee) {
            error = AmountErrMsg("maxtxfee", *arg);
            return false;
        }
        if (chain && CFeeRate{max_fee.value(), 1000} < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                "-maxtxfee", *arg, chain->relayMinFee().ToString());
            return false;
        }
        wallet.m_default_max_tx_fee = max_fee.value();
    }

    if (const auto arg{args.GetArg("-consolidatefeerate")}) {
        if (std::optional<CAmount> consolidate_feerate = ParseMoney(*arg)) {
            wallet.m_consolidate_feerate = CFeeRate(*consolidate_feerate);
        } else {
            error = AmountErrMsg("consolidatefeerate", *arg);
            return false;
        }
    }

    wallet.m_confirm_target = args.GetIntArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    wallet.m_spend_zero_conf_change = args.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    wallet.m_signal_rbf = args.GetBoolArg("-walletrbf", DEFAULT_WALLET_RBF);

    // Without this the broadcast flag stays false and CommitTransaction never
    // submits to the mempool: the transaction lands in the wallet but nowhere else.
    wallet.SetBroadcastTransactions(args.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    return true;
}

std::shared_ptr<CWallet> CreateWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    options.require_create = true;
    const fs::path path{GetWalletDir(*context.args) / fs::PathFromString(name)};

    std::unique_ptr<WalletDatabase> database{MakeDatabase(path, options, status, error)};
    if (!database) {
        if (status == DatabaseStatus::SUCCESS) status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    auto wallet{std::make_shared<CWallet>(context.chain, name, std::move(database))};
    wallet->SetChainParams(Params());
    wallet->InitWalletFlags(options.create_flags);

    // Only generate an HD seed for wallets that can hold private keys and are not
    // intentionally blank.
    const bool can_have_keys = !wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) &&
                               !wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET);
    if (can_have_keys) {
        wallet->GenerateNewSeed();
        if (!options.create_passphrase.empty() && !wallet->EncryptWallet(options.create_passphrase)) {
            error = Untranslated("Error: Wallet created but failed to encrypt.");
            status = DatabaseStatus::FAILED_CREATE;
            return nullptr;
        }
    }

    if (!ApplyWalletArgs(*wallet, *context.args, context.chain, error, warnings)) {
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    if (context.chain && !AttachChain(wallet, *context.chain, error)) {
        return nullptr;
    }
    AddWallet(context, wallet);
    if (context.chain) UpdateWalletSetting(*context.chain, name, load_on_start, warnings);
    status = DatabaseStatus::SUCCESS;
    return wallet;
}

std::shared_ptr<CWallet> LoadWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    options.require_existing = true;
    const fs::path path{GetWalletDir(*context.args) / fs::PathFromString(name)};

    std::unique_ptr<WalletDatabase> database{MakeDatabase(path, options, status, error)};
    if (!database) {
        return nullptr;
    }

    auto wallet{std::make_shared<CWallet>(context.chain, name, std::move(database))};
    wallet->SetChainParams(Params());
    if (wallet->PopulateWalletFromDB() != DBErrors::LOAD_OK) {
        error = Untranslated("Error loading wallet; see the log for details");
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }

    if (!ApplyWalletArgs(*wallet, *context.args, context.chain, error, warnings)) {
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }

    if (context.chain && !AttachChain(wallet, *context.chain, error)) {
        return nullptr;
    }
    AddWallet(context, wallet);
    if (context.chain) UpdateWalletSetting(*context.chain, name, load_on_start, warnings);
    status = DatabaseStatus::SUCCESS;
    return wallet;
}

std::shared_ptr<CWallet> RestoreWallet(WalletContext& context, const fs::path& backup_file, const std::string& wallet_name, std::optional<bool> load_on_start, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings, bool load_after_restore)
{
    if (wallet_name.empty()) {
        error = Untranslated("Wallet name cannot be empty");
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }

    DatabaseOptions options;
    options.require_existing = true;

    // Lattica stores each wallet as <walletdir>/<name>/wallet.dat (the SQLite
    // backend appends the wallet.dat filename), so the destination is the wallet
    // directory and the backup is copied to wallet.dat inside it.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(*context.args), fs::PathFromString(wallet_name));
    const fs::path wallet_file = wallet_path / "wallet.dat";
    std::shared_ptr<CWallet> wallet;
    bool wallet_file_copied = false;
    bool created_wallet_dir = false;

    try {
        if (!fs::exists(backup_file)) {
            error = Untranslated("Backup file does not exist");
            status = DatabaseStatus::FAILED_BAD_PATH;
            return nullptr;
        }

        // Wallet directories may exist, but must not already contain a wallet.dat;
        // an existing database is a hard failure to avoid overwriting it.
        if (fs::exists(wallet_path)) {
            if (!fs::is_directory(wallet_path)) {
                error = Untranslated(strprintf("Failed to restore wallet. Database file exists '%s'.", fs::PathToString(wallet_path)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }
            if (fs::exists(wallet_file)) {
                error = Untranslated(strprintf("Failed to restore wallet. Database file exists in '%s'.", fs::PathToString(wallet_file)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }
        } else {
            if (!TryCreateDirectories(wallet_path)) {
                error = Untranslated(strprintf("Failed to restore database path '%s'.", fs::PathToString(wallet_path)));
                status = DatabaseStatus::FAILED_ALREADY_EXISTS;
                return nullptr;
            }
            created_wallet_dir = true;
        }

        fs::copy_file(backup_file, wallet_file, fs::copy_options::none);
        wallet_file_copied = true;

        if (load_after_restore) {
            wallet = LoadWallet(context, wallet_name, load_on_start, options, status, error, warnings);
        }
    } catch (const std::exception& e) {
        error = Untranslated(strprintf("Unexpected exception: %s", e.what()));
    }

    // Remove created files if loading the wallet failed.
    if (load_after_restore && !wallet) {
        if (wallet_file_copied) {
            std::error_code ec;
            fs::remove(wallet_file, ec);
        }
        if (created_wallet_dir) {
            std::error_code ec;
            fs::remove_all(wallet_path, ec);
        }
    }

    return wallet;
}

} // namespace wallet
