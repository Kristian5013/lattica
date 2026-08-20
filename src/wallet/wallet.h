// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// CWallet for Lattica.
//
// This is a hand-written wallet (not a verbatim port of Bitcoin Core's wallet.cpp)
// because ML-DSA removes the entire elliptic-curve complexity layer that shapes
// Core's wallet: there is no EC point compression, no BIP32 *public* derivation
// (so no xpub / descriptor range expansion / DescriptorScriptPubKeyMan), no DER
// signature encoding or low-R grinding, no key recovery, no Schnorr/Taproot, no
// ECDH, and no global signing context. So Lattica's wallet keeps Core's
// scheme-agnostic orchestration (mapWallet, the TXO cache, IsMine, balance, the
// notification-driven sync, the address book, encryption, the SQLite WalletDatabase)
// but replaces the ScriptPubKeyMan key layer with a direct ML-DSA HD keystore:
// CWallet *is* the FillableSigningProvider, deriving hardened children from a
// 32-byte seed and producing witness-v0 (P2WPKH) destinations. One key layer in
// place of Core's three (CWallet -> SPKM -> Descriptor).
//
// Coin selection, fee calculation, balance bucketing and transaction creation live
// in the sibling translation units wallet/coinselection.cpp, wallet/fees.cpp,
// wallet/receive.cpp and wallet/spend.cpp (free functions taking a CWallet&), exactly
// as in Core; this header only exposes the state and primitives they consume.
//
// Omitted relative to Core (each is EC / descriptor / PSBT / migration / external
// signer / keypool, none of which applies): ScriptPubKeyMan & DescriptorScriptPubKeyMan,
// output descriptors, PSBT (FillPSBT), message signing via SigningResult, external
// signers, legacy->descriptor migration, fee bumping, and the keypool
// ReserveDestination (the ML-DSA keystore derives on demand).

#ifndef LATTICA_WALLET_WALLET_H
#define LATTICA_WALLET_WALLET_H

#include <addresstype.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <kernel/cs_main.h>
#include <kernel/mempool_removal_reason.h>
#include <key.h>
#include <kernel/chainparams.h>
#include <logging.h>
#include <node/types.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/signingprovider.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/btcsignals.h>
#include <util/hasher.h>
#include <util/result.h>
#include <util/string.h>
#include <util/time.h>
#include <util/ui_change_type.h>
#include <wallet/crypter.h>
#include <wallet/transaction.h>
#include <wallet/types.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

class ArgsManager;
class SignatureData;

namespace wallet {

//! -mintxfee default (sat per kvB).
static constexpr CAmount DEFAULT_TRANSACTION_MINFEE = 1000;
//! -discardfee default (sat per kvB): change worth less than the cost to spend is dropped to fees.
static constexpr CAmount DEFAULT_DISCARD_FEE = 10000;
//! -fallbackfee default (0 = disabled; the wallet falls back to this when the fee
//! estimator has no data).
static constexpr CAmount DEFAULT_FALLBACK_FEE = 0;
//! -consolidatefeerate default (10 sat/vbyte).
static constexpr CAmount DEFAULT_CONSOLIDATE_FEERATE = 10000;
//! -maxtxfee default.
static constexpr CAmount DEFAULT_TRANSACTION_MAXFEE = COIN / 10;
//! minimum recommended increment for replacement transactions (BIP125 fee bumping).
static const CAmount WALLET_INCREMENTAL_RELAY_FEE = 5000;
//! Discourage users to set fees higher than this amount (per kvB).
static constexpr CAmount HIGH_TX_FEE_PER_KB = COIN / 100;
//! -maxapsfee default (absolute fee). A value of -1 disables partial spend avoidance.
static constexpr CAmount DEFAULT_MAX_AVOIDPARTIALSPEND_FEE = 0;
//! discourage APS fee higher than this amount.
constexpr CAmount HIGH_APS_FEE{COIN / 10000};
//! Default for -spendzeroconfchange.
static constexpr bool DEFAULT_SPEND_ZEROCONF_CHANGE = true;
//! Default for -walletrejectlongchains.
static constexpr bool DEFAULT_WALLET_REJECT_LONG_CHAINS = true;
//! -txconfirmtarget default.
static constexpr unsigned int DEFAULT_TX_CONFIRM_TARGET = 6;
//! -walletrbf default (signal opt-in RBF on created transactions).
static constexpr bool DEFAULT_WALLET_RBF = true;
//! -walletbroadcast default.
static constexpr bool DEFAULT_WALLETBROADCAST = true;

//! Default address type the wallet hands out (witness v0, the only spendable type
//! for ML-DSA keys, whose pubkeys/sigs exceed MAX_SCRIPT_ELEMENT_SIZE).
static constexpr OutputType DEFAULT_ADDRESS_TYPE{OutputType::BECH32};

//! Lower-bound estimate (vbytes) used by coin selection when the wallet can't infer
//! the signed size of a change output (spend.cpp). Kept from Core.
static constexpr size_t DUMMY_NESTED_P2WPKH_INPUT_SIZE = 91;

//! Wallet flags Lattica understands (a subset of Core's; descriptor/external-signer
//! flags are accepted for forward-compat but the wallet is always a keystore wallet).
static constexpr uint64_t KNOWN_WALLET_FLAGS =
        WALLET_FLAG_AVOID_REUSE
    |   WALLET_FLAG_BLANK_WALLET
    |   WALLET_FLAG_KEY_ORIGIN_METADATA
    |   WALLET_FLAG_DISABLE_PRIVATE_KEYS;

static constexpr uint64_t MUTABLE_WALLET_FLAGS = WALLET_FLAG_AVOID_REUSE;

/**
 * Address book data. The label/purpose/previously-spent/receive-request fields are
 * scheme-agnostic, ported as-is from Bitcoin Core's wallet.h.
 */
struct CAddressBookData {
    //! Always nullopt for change addresses; the presence/absence of a label
    //! distinguishes change from non-change addresses.
    std::optional<std::string> label;
    //! Cached IsMine hint, historically a BIP70 payment-protocol field.
    std::optional<AddressPurpose> purpose;
    //! Whether coins with this address have previously been spent (avoid_reuse).
    bool previously_spent{false};
    //! BIP21 receive-request metadata, keyed by request id.
    std::map<std::string, std::string> receive_requests{};

    bool IsChange() const { return !label.has_value(); }
    std::string GetLabel() const { return label ? *label : std::string{}; }
    void SetLabel(std::string name) { label = std::move(name); }
};

inline std::string PurposeToString(AddressPurpose p)
{
    switch (p) {
    case AddressPurpose::RECEIVE: return "receive";
    case AddressPurpose::SEND: return "send";
    case AddressPurpose::REFUND: return "refund";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

inline std::optional<AddressPurpose> PurposeFromString(std::string_view s)
{
    if (s == "receive") return AddressPurpose::RECEIVE;
    else if (s == "send") return AddressPurpose::SEND;
    else if (s == "refund") return AddressPurpose::REFUND;
    return {};
}

/** A recipient of a transaction the wallet creates: a destination, an amount, and
 *  whether the fee is subtracted from this output. (Core keeps CRecipient in wallet.h.) */
struct CRecipient {
    CTxDestination dest;
    CAmount nAmount;
    bool fSubtractFeeFromAmount;
};

/**
 * A CWallet maintains a set of transactions and balances and creates new
 * transactions. It receives chain state through interfaces::Chain::Notifications
 * and persists to a WalletDatabase (SQLite). See the file header for how it relates
 * to Core's CWallet.
 */
class WalletRescanReserver; // holds the wallet's rescan flag for ScanForWalletTransactions

class CWallet final : public FillableSigningProvider, public interfaces::Chain::Notifications
{
private:
    // ------------------------------------------------------------ encryption
    //! Decrypted master key, only set while the wallet is unlocked.
    CKeyingMaterial vMasterKey GUARDED_BY(cs_wallet);

    // ------------------------------------------------------- ML-DSA HD key core
    CExtKey m_hd_master GUARDED_BY(cs_wallet);
    uint256 m_hd_seed GUARDED_BY(cs_wallet);   //!< the 32-byte seed the master expands from (cleared while locked)
    //! The encrypted seed, present iff the wallet is encrypted. Persisted in CHDChain;
    //! decrypted into m_hd_seed (and the key core re-derived) on Unlock.
    std::vector<unsigned char> m_crypted_seed GUARDED_BY(cs_wallet);
    uint32_t m_next_index GUARDED_BY(cs_wallet){0};
    bool m_has_seed GUARDED_BY(cs_wallet){false};
    //! Key ids of every derived key (public data). Populated on load/derive and kept even
    //! while the wallet is locked, so an encrypted wallet still recognises its own outputs
    //! (IsMine) and shows a balance before Unlock re-derives the private keys.
    std::set<CKeyID> m_pubkey_ids GUARDED_BY(cs_wallet);

    // ------------------------------------------------------------ wallet state
    //! WalletFlags set on this wallet.
    std::atomic<uint64_t> m_wallet_flags{0};
    //! First created key time, used to skip blocks before it during rescan.
    std::atomic<int64_t> m_birth_time{std::numeric_limits<int64_t>::max()};

    //! Used to keep track of spent outpoints, and detect conflicts/double-spends.
    using TxSpends = std::unordered_multimap<COutPoint, Txid, SaltedOutpointHasher>;
    TxSpends mapTxSpends GUARDED_BY(cs_wallet);
    void AddToSpends(const COutPoint& outpoint, const Txid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void AddToSpends(const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    //! Cache of this wallet's outputs (IsMine outpoints). WalletTXO holds references
    //! into mapWallet, so an entry stays valid while its owning CWalletTx lives there.
    std::unordered_map<COutPoint, WalletTXO, SaltedOutpointHasher> m_txos GUARDED_BY(cs_wallet);

    //! Add (or update) a transaction only if it pays to us or spends one of our coins.
    bool AddToWalletIfInvolvingMe(const CTransactionRef& tx, const SyncTxState& state, bool rescanning_old_block) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SyncTransaction(const CTransactionRef& tx, const SyncTxState& state, bool rescanning_old_block = false) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    //! Mark a transaction (and its in-wallet descendants) as conflicting with a block.
    void MarkConflicted(const uint256& hashBlock, int conflicting_height, const Txid& hashTx);
    void MarkInputsDirty(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    enum class TxUpdate { UNCHANGED, CHANGED, NOTIFY_CHANGED };
    using TryUpdatingStateFn = std::function<TxUpdate(CWalletTx& wtx)>;
    void RecursiveUpdateTxState(WalletBatch* batch, const Txid& tx_hash, const TryUpdatingStateFn& try_updating_state) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool SetAddressBookWithDB(WalletBatch& batch, const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& purpose);
    void SetWalletFlagWithDB(WalletBatch& batch, uint64_t flags);
    void UnsetWalletFlagWithDB(WalletBatch& batch, uint64_t flag);
    void UnsetBlankWalletFlag(WalletBatch& batch);

    bool Unlock(const CKeyingMaterial& vMasterKeyIn);

    //! Interface to the chain (block/mempool notifications, broadcast). May be null
    //! (e.g. wallet-tool / migration), checked via HaveChain().
    interfaces::Chain* m_chain{nullptr};
    //! Wallet name (relative directory name, or "" for the default wallet).
    std::string m_name;
    //! On-disk database (SQLite).
    std::unique_ptr<WalletDatabase> m_database;
    //! Chain params, for encoding/decoding addresses (Lattica has no global Params()).
    const CChainParams* m_params{nullptr};

    //! Tip the wallet has processed (height + hash), advanced by blockConnected.
    uint256 m_last_block_processed GUARDED_BY(cs_wallet);
    int m_last_block_processed_height GUARDED_BY(cs_wallet){-1};

    void SetLastBlockProcessedInMem(int block_height, uint256 block_hash) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

public:
    //! HD seed length (bytes): 256 bits of entropy, hashed (SHA3-512) into the
    //! master node seed + chain code by CExtKey::SetSeed.
    static constexpr size_t SEED_LENGTH = 32;

    /** Main wallet lock. Protects all the fields above and below. */
    mutable RecursiveMutex cs_wallet;

    CWallet() = default;
    /** Construct with a chain interface, name and database (Core-shaped). */
    CWallet(interfaces::Chain* chain, std::string name, std::unique_ptr<WalletDatabase> database)
        : m_chain(chain), m_name(std::move(name)), m_database(std::move(database)) {}

    ~CWallet() { assert(NotifyUnload.empty()); }

    // ---------------------------------------------------------------- identity
    const std::string& GetName() const { return m_name; }
    void SetName(std::string name) { m_name = std::move(name); }
    std::string LogName() const { return m_name.empty() ? std::string("default wallet") : m_name; }
    WalletDatabase& GetDatabase() const { assert(m_database); return *m_database; }
    void SetDatabase(std::unique_ptr<WalletDatabase> database) { m_database = std::move(database); }
    bool HasDatabase() const { return static_cast<bool>(m_database); }
    void SetChainParams(const CChainParams& params) { m_params = &params; }
    const CChainParams* GetChainParams() const { return m_params; }

    /** Prepend the wallet name in logging output to ease debugging. Uses a plain
     *  const char* format (wrapped in tfm::RuntimeFormat) rather than Core's
     *  ConstevalFormatString: the consteval form builds fine under g++ but trips up
     *  the C/C++ IntelliSense parser in a non-deduced context. tinyformat still
     *  validates the format at runtime. */
    template <typename... Params>
    void WalletLogPrintf(const char* wallet_fmt, const Params&... params) const
    {
        LogInfo("[%s] %s", LogName(), tfm::format(tfm::RuntimeFormat{std::string(wallet_fmt)}, params...));
    }

    // ------------------------------------------------------------ chain access
    bool HaveChain() const { return m_chain != nullptr; }
    interfaces::Chain& chain() const { assert(m_chain); return *m_chain; }
    void SetChain(interfaces::Chain* chain) { m_chain = chain; }
    /** Registered interfaces::Chain::Notifications handler. */
    std::unique_ptr<interfaces::Handler> m_chain_notifications_handler;
    //! Disconnect chain notifications and wait for all pending ones to be processed.
    void DisconnectChainNotifications();

    // --------------------------------------------------------------- core maps
    //! Map from txid to CWalletTx for every transaction the wallet is interested in.
    std::unordered_map<Txid, CWalletTx, SaltedTxidHasher> mapWallet GUARDED_BY(cs_wallet);

    //! Outputs the wallet won't spend from (e.g. used to fund an unconfirmed tx).
    std::set<COutPoint> m_locked_coins GUARDED_BY(cs_wallet);

    //! Address book: destination -> label / purpose / receive-request metadata.
    std::map<CTxDestination, CAddressBookData> m_address_book GUARDED_BY(cs_wallet);
    const CAddressBookData* FindAddressBookEntry(const CTxDestination&, bool allow_change = false) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    //! Encryption master keys (id -> encrypted master key) loaded from disk.
    std::map<unsigned int, CMasterKey> mapMasterKeys;
    unsigned int nMasterKeyMaxID{0};
    //! Next free transaction ordering position.
    int64_t nOrderPosNext GUARDED_BY(cs_wallet){0};

    // ----------------------------------------------------------------- fee config
    unsigned int m_confirm_target{DEFAULT_TX_CONFIRM_TARGET};
    //! Allow coin selection to pick unconfirmed change we sent ourselves.
    bool m_spend_zero_conf_change{DEFAULT_SPEND_ZEROCONF_CHANGE};
    //! Signal opt-in RBF on transactions the wallet creates.
    bool m_signal_rbf{DEFAULT_WALLET_RBF};
    //! False if -fallbackfee=0 (fallback fee disabled).
    bool m_allow_fallback_fee{true};
    //! User-set minimum feerate floor (-mintxfee).
    CFeeRate m_min_fee{DEFAULT_TRANSACTION_MINFEE};
    //! Feerate to use when the estimator has no data (-fallbackfee).
    CFeeRate m_fallback_fee{DEFAULT_FALLBACK_FEE};
    //! Change worth less than the cost to spend it at this feerate is dropped to fees.
    CFeeRate m_discard_rate{DEFAULT_DISCARD_FEE};
    //! Bias toward consolidating inputs when the actual feerate is below this.
    CFeeRate m_consolidate_feerate{DEFAULT_CONSOLIDATE_FEERATE};
    //! Max extra absolute fee to pay to prioritize partial-spend avoidance.
    CAmount m_max_aps_fee{DEFAULT_MAX_AVOIDPARTIALSPEND_FEE};
    //! Absolute maximum fee the wallet will pay by default.
    CAmount m_default_max_tx_fee{DEFAULT_TRANSACTION_MAXFEE};
    OutputType m_default_address_type{DEFAULT_ADDRESS_TYPE};
    //! Change output type; unset means derive it from the recipients / address type.
    std::optional<OutputType> m_default_change_type{};

    //! Choose the change OutputType for a transaction (Lattica: witness v0 only).
    OutputType TransactionChangeType(const std::optional<OutputType>& change_type, const std::vector<CRecipient>& vecSend) const;

    // ------------------------------------------------------------------ key core
    void GenerateNewSeed();
    void SetSeed(std::span<const unsigned char> seed);
    bool HasSeed() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return m_has_seed; }
    //! HD is enabled whenever the wallet has a seed — including an encrypted wallet whose
    //! seed is sealed while locked (m_has_seed false but a crypted seed exists). Otherwise a
    //! locked encrypted wallet would wrongly report "HD disabled".
    bool IsHDEnabled() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return m_has_seed || !m_crypted_seed.empty(); }
    bool CanGetAddresses() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return m_has_seed; }
    uint32_t GetKeyCount() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return m_next_index; }
    const CExtKey& GetHDMaster() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return m_hd_master; }
    //! Derive the next hardened child, store it (and persist), return its P2WPKH destination.
    util::Result<CTxDestination> GetNewDestination(const std::string& label);
    util::Result<CTxDestination> GetNewChangeDestination();
    std::string GetNewAddress(const std::string& label = "");
    //! Find the private key for a key id, if available (and the wallet is unlocked).
    std::optional<CKey> GetKey(const CKeyID& keyid) const;

    //! The keystore is CWallet itself, so the solving provider for any of our scripts
    //! is the wallet (Core returns a per-script ScriptPubKeyMan provider). The
    //! signed-size code in spend.cpp does not consult it (sizes are fixed for ML-DSA).
    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script) const;
    std::unique_ptr<SigningProvider> GetSolvingProvider(const CScript& script, SignatureData& sigdata) const;
    //! Whether the signer can grind the R of a signature. ML-DSA signatures are
    //! deterministic and fixed length, so there is nothing to grind: always false.
    bool CanGrindR() const { return false; }

    // --------------------------------------------- record loaders (WalletBatch::LoadWallet)
    //! The keystore is CWallet itself (FillableSigningProvider). The wallet is pure-HD,
    //! so the only key record is the HD chain (seed + counter); LoadHDChain rebuilds
    //! the whole keystore by re-deriving (or, when encrypted, defers until Unlock).
    void LoadHDChain(const CHDChain& chain);
    //! Load a persisted derived-key id (public data) so IsMine works while locked.
    void LoadPubKeyId(const CKeyID& id) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { m_pubkey_ids.insert(id); }
    void LoadLockedCoin(const COutPoint& output, bool /*persistent*/) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { m_locked_coins.insert(output); }
    void LoadAddressPreviouslySpent(const CTxDestination& dest) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { m_address_book[dest].previously_spent = true; }
    void LoadAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& request) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { m_address_book[dest].receive_requests[id] = request; }

    // -------------------------------------------------------------- encryption
    bool IsCrypted() const { return HasEncryptionKeys(); }
    bool IsLocked() const;
    bool Lock();
    bool Unlock(const SecureString& strWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool WithEncryptionKey(std::function<bool (const CKeyingMaterial&)> cb) const;
    bool HasEncryptionKeys() const;

    //! Scheduled auto-relock time (seconds since epoch) set by the walletpassphrase
    //! RPC; 0 when no relock is pending.
    int64_t nRelockTime GUARDED_BY(cs_wallet){0};
    //! Serializes concurrent walletpassphrase calls.
    Mutex m_unlock_mutex;
    //! Guards the scheduled relock callback against a racing walletlock.
    Mutex m_relock_mutex;

    // -------------------------------------------------------------- tx ingestion
    using UpdateWalletTxFn = std::function<bool(CWalletTx& wtx, bool new_tx)>;
    //! Add (or update) a transaction in the wallet, wrapping it in a CWalletTx and
    //! persisting it. update_wtx, if set, fills metadata; rescanning_old_block tunes time.
    CWalletTx* AddToWallet(CTransactionRef tx, const TxState& state, const UpdateWalletTxFn& update_wtx = nullptr, bool rescanning_old_block = false);
    //! Insert (or find) a CWalletTx during load and let fill_wtx populate it.
    bool LoadToWallet(const Txid& hash, const UpdateWalletTxFn& fill_wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    const CWalletTx* GetWalletTx(const Txid& hash) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    //! Compute the "smart" timestamp for a wallet transaction (block time bounded by neighbouring entries).
    unsigned int ComputeTimeSmart(const CWalletTx& wtx, bool rescanning_old_block) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // ------------------------------------------------------------------- TXO model
    //! How an outpoint is spent (by a confirmed/mempool/non-mempool wallet tx, or unspent).
    enum class SpendType { UNSPENT, CONFIRMED, MEMPOOL, NONMEMPOOL };
    SpendType HowSpent(const COutPoint& outpoint) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    const std::unordered_map<COutPoint, WalletTXO, SaltedOutpointHasher>& GetTXOs() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { AssertLockHeld(cs_wallet); return m_txos; }
    std::optional<WalletTXO> GetTXO(const COutPoint& outpoint) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    //! Cache the IsMine outputs of `wtx` into m_txos.
    void RefreshTXOsFromTx(const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void RefreshAllTXOs() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // ------------------------------------- interfaces::Chain::Notifications
    void transactionAddedToMempool(const CTransactionRef& tx) override;
    void transactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason) override;
    void blockConnected(const kernel::ChainstateRole& role, const interfaces::BlockInfo& block) override;
    void blockDisconnected(const interfaces::BlockInfo& block) override;
    void updatedBlockTip() override;
    /** Block until the wallet has processed notifications up to the current chain tip. */
    void BlockUntilSyncedToCurrentChain() const LOCKS_EXCLUDED(::cs_main) EXCLUSIVE_LOCKS_REQUIRED(!cs_wallet);

    // -------------------------------------------------------------------- rescan
    struct ScanResult {
        enum { SUCCESS, FAILURE, USER_ABORT } status = SUCCESS;
        //! Hash and height of the most recent block that was successfully scanned.
        uint256 last_scanned_block;
        std::optional<int> last_scanned_height;
        //! Height of the most recent block that could not be scanned (read error).
        uint256 last_failed_block;
    };
    //! Scan the active chain from start_block forward, adding any involving-me
    //! transactions. The reserver must be held for the duration of the scan.
    ScanResult ScanForWalletTransactions(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, bool save_progress);

    void AbortRescan() { fAbortRescan = true; }
    bool IsAbortingRescan() const { return fAbortRescan; }
    bool IsScanning() const { return fScanningWallet; }
    bool IsScanningWithPassphrase() const { return m_scanning_with_passphrase; }
    SteadyClock::duration ScanningDuration() const { return fScanningWallet ? SteadyClock::now() - m_scanning_start.load() : SteadyClock::duration{}; }
    double ScanningProgress() const { return fScanningWallet ? (double)m_scanning_progress : 0; }

    // ----------------------------------------------------------------- chain view
    void SetLastBlockProcessed(int block_height, uint256 block_hash) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int GetLastBlockHeight() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { AssertLockHeld(cs_wallet); assert(m_last_block_processed_height >= 0); return m_last_block_processed_height; }
    uint256 GetLastBlockHash() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { AssertLockHeld(cs_wallet); assert(m_last_block_processed_height >= 0); return m_last_block_processed; }
    void WriteBestBlock() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void MaybeUpdateBirthTime(int64_t time);
    int64_t GetBirthTime() const { return m_birth_time; }

    // ---------------------------------------------------------------- ownership
    bool IsMine(const CScript& script) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsMine(const CTxOut& txout) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsMine(const CTxDestination& dest) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsMine(const CTransaction& tx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsMine(const COutPoint& outpoint) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsFromMe(const CTransaction& tx) const;
    CAmount GetDebit(const CTxIn& txin) const;
    CAmount GetDebit(const CTransaction& tx) const;
    CAmount GetCredit(const CTxOut& txout) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // ------------------------------------------------------------ spent tracking
    bool IsSpent(const COutPoint& outpoint) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    //! Whether this or any known scriptPubKey with the same single key has been spent.
    bool IsSpentKey(const CScript& scriptPubKey) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void SetSpentKeyState(WalletBatch& batch, const Txid& hash, unsigned int n, bool used, std::set<CTxDestination>& tx_destinations) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void MarkDestinationsDirty(const std::set<CTxDestination>& destinations) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::set<Txid> GetConflicts(const Txid& txid) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::set<Txid> GetTxConflicts(const CWalletTx& wtx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool HasWalletSpend(const CTransactionRef& tx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // ------------------------------------------------------------ depth/maturity
    int GetTxDepthInMainChain(const CWalletTx& wtx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int GetTxBlocksToMaturity(const CWalletTx& wtx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsTxImmatureCoinBase(const CWalletTx& wtx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // ----------------------------------------------------------- abandon/conflict
    bool TransactionCanBeAbandoned(const Txid& hashTx) const;
    bool AbandonTransaction(const Txid& hashTx);
    bool AbandonTransaction(CWalletTx& tx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool MarkReplaced(const Txid& originalHash, const Txid& newHash);
    //! Remove transactions from the wallet (used by removeprunedfunds). Erases the
    //! records from disk and, on db-txn commit, drops them from mapWallet / the spend
    //! map / the TXO cache and notifies listeners with CT_DELETED.
    util::Result<void> RemoveTxs(std::vector<Txid>& txs_to_remove) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    util::Result<void> RemoveTxs(WalletBatch& batch, std::vector<Txid>& txs_to_remove) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void MarkDirty();
    DBErrors ReorderTransactions();
    int64_t IncOrderPosNext(WalletBatch* batch = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // -------------------------------------------------------------- coin locking
    bool LockCoin(const COutPoint& output, bool persist = true) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool UnlockCoin(const COutPoint& output) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool UnlockAllCoins() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsLockedCoin(const COutPoint& output) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void ListLockedCoins(std::vector<COutPoint>& vOutpts) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // ------------------------------------------------------- broadcast / rebroadcast
    void CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm);
    bool SubmitTxMemoryPoolAndRelay(CWalletTx& wtx, std::string& err_string, node::TxBroadcast broadcast_method) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool GetBroadcastTransactions() const { return fBroadcastTransactions; }
    void SetBroadcastTransactions(bool broadcast) { fBroadcastTransactions = broadcast; }
    bool ShouldResend() const;
    void SetNextResend() { m_next_resend = GetDefaultNextResend(); }
    void ResubmitWalletTransactions(node::TxBroadcast broadcast_method, bool force);

    // ------------------------------------------------------------------ signing
    bool SignTransaction(CMutableTransaction& tx) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const;

    // -------------------------------------------------------------- address book
    struct AddrBookFilter {
        std::optional<std::string> m_op_label{std::nullopt};
        bool ignore_change{true};
    };
    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& purpose);
    bool DelAddressBook(const CTxDestination& address);
    bool DelAddressBookWithDB(WalletBatch& batch, const CTxDestination& address);
    std::vector<CTxDestination> ListAddrBookAddresses(const std::optional<AddrBookFilter>& filter) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::set<std::string> ListAddrBookLabels(std::optional<AddressPurpose> purpose) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    using ListAddrBookFunc = std::function<void(const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose> purpose)>;
    void ForEachAddrBookEntry(const ListAddrBookFunc& func) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool IsAddressPreviouslySpent(const CTxDestination& dest) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SetAddressPreviouslySpent(WalletBatch& batch, const CTxDestination& dest, bool used) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::vector<std::string> GetAddressReceiveRequests() const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SetAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id, const std::string& value) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool EraseAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    // -------------------------------------------------------------- wallet flags
    void SetWalletFlag(uint64_t flags);
    void UnsetWalletFlag(uint64_t flag);
    bool IsWalletFlagSet(uint64_t flag) const;
    void InitWalletFlags(uint64_t flags);
    bool LoadWalletFlags(uint64_t flags);
    uint64_t GetWalletFlags() const;

    // -------------------------------------------------------------- persistence
    DBErrors PopulateWalletFromDB();
    void postInitProcess();
    bool BackupWallet(const std::string& strDest) const;
    void Close();

    // ----------------------------------------------------------------- signals
    btcsignals::signal<void ()> NotifyUnload;
    btcsignals::signal<void (const CTxDestination& address, const std::string& label, bool isMine, AddressPurpose purpose, ChangeType status)> NotifyAddressBookChanged;
    btcsignals::signal<void (const Txid& hashTx, ChangeType status)> NotifyTransactionChanged;
    btcsignals::signal<void (const std::string& title, int nProgress)> ShowProgress;
    btcsignals::signal<void ()> NotifyCanGetAddressesChanged;
    btcsignals::signal<void (CWallet* wallet)> NotifyStatusChanged;

private:
    //! Whether this wallet submits newly created transactions to the node's mempool
    //! and rebroadcasts them.
    bool fBroadcastTransactions{false};
    //! The next scheduled rebroadcast of wallet transactions.
    NodeClock::time_point m_next_resend{GetDefaultNextResend()};
    //! Local time the tip block was received, used to schedule rebroadcasts.
    std::atomic<int64_t> m_best_block_time{0};
    static NodeClock::time_point GetDefaultNextResend();

    //! Rescan state, owned by WalletRescanReserver (reserve/release the scanner).
    std::atomic<bool> fAbortRescan{false};
    std::atomic<bool> fScanningWallet{false};
    std::atomic<bool> m_scanning_with_passphrase{false};
    std::atomic<SteadyClock::time_point> m_scanning_start{SteadyClock::time_point{}};
    std::atomic<double> m_scanning_progress{0};
    friend class WalletRescanReserver;
};

/** RAII object to serialize and own a wallet rescan; release on destruction. */
class WalletRescanReserver
{
private:
    using Clock = std::chrono::steady_clock;
    using NowFn = std::function<Clock::time_point()>;
    CWallet& m_wallet;
    bool m_could_reserve{false};
    NowFn m_now;
public:
    explicit WalletRescanReserver(CWallet& w) : m_wallet(w) {}

    bool reserve(bool with_passphrase = false)
    {
        assert(!m_could_reserve);
        if (m_wallet.fScanningWallet.exchange(true)) {
            return false;
        }
        m_wallet.fAbortRescan = false;
        m_wallet.m_scanning_with_passphrase.exchange(with_passphrase);
        m_wallet.m_scanning_start = SteadyClock::now();
        m_wallet.m_scanning_progress = 0;
        m_could_reserve = true;
        return true;
    }

    bool isReserved() const
    {
        return (m_could_reserve && m_wallet.fScanningWallet);
    }

    Clock::time_point now() const { return m_now ? m_now() : Clock::now(); }

    void setNow(NowFn now) { m_now = std::move(now); }

    ~WalletRescanReserver()
    {
        if (m_could_reserve) {
            m_wallet.fScanningWallet = false;
            m_wallet.m_scanning_with_passphrase = false;
        }
    }
};

// ------------------------------------------------------------------ wallet lifecycle
struct WalletContext;

//! Wire a wallet to a chain: register it on the block/mempool notification bus (so it
//! auto-follows the chain) and catch its processed tip up to the chain tip. The wallet
//! must be held in a shared_ptr (the notification handler keeps a reference to it). Call
//! CWallet::DisconnectChainNotifications() before releasing the wallet to break the cycle.
bool AttachChain(const std::shared_ptr<CWallet>& wallet, interfaces::Chain& chain, bilingual_str& error);

//! Wallet registry, held in the WalletContext (mirrors Core's AddWallet/RemoveWallet/…).
bool AddWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet);
bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet);
std::vector<std::shared_ptr<CWallet>> GetWallets(WalletContext& context);
std::shared_ptr<CWallet> GetWallet(WalletContext& context, const std::string& name);
std::shared_ptr<CWallet> GetDefaultWallet(WalletContext& context, size_t& count);

//! Rebroadcast every wallet's unconfirmed transactions (called periodically by StartWallets).
void MaybeResendWalletTxs(WalletContext& context);

//! Wallet lifecycle: create a new wallet `name` (under the -walletdir / wallets dir)
//! and load an existing one. Both register the wallet in the context on success.
//! Lattica opens wallets by explicit name -> path; there is no descriptor / legacy
//! migration machinery. NULL on failure (status / error set). load_on_start, when
//! set, adds/removes the wallet name from the persistent settings.json load list.
std::shared_ptr<CWallet> CreateWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings);
std::shared_ptr<CWallet> LoadWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings);
//! Restore a wallet from a backup file (copies it into the wallets dir, then loads it).
std::shared_ptr<CWallet> RestoreWallet(WalletContext& context, const fs::path& backup_file, const std::string& wallet_name, std::optional<bool> load_on_start, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings, bool load_after_restore = true);

//! Add or remove a wallet name from the persistent "wallet" settings.json list, so
//! it is (or is not) loaded automatically on the next node startup.
bool AddWalletSetting(interfaces::Chain& chain, const std::string& wallet_name);
bool RemoveWalletSetting(interfaces::Chain& chain, const std::string& wallet_name);

} // namespace wallet

#endif // LATTICA_WALLET_WALLET_H
