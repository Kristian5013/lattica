// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// The wallet's persistence layer, written in the style of Bitcoin Core's
// wallet/walletdb.h but adapted for Lattica (NOT a verbatim port, because Core's
// walletdb is full of elliptic-curve / descriptor operations -- per-descriptor and
// per-key records, CExtPubKey xpub caches, active-ScriptPubKeyMan records, watch-only
// records -- none of which a post-quantum keystore wallet has). It keeps Core's
// shape: DBErrors, the DBKeys record-type strings, CHDChain, WalletBatch with its
// typed Write/Erase helpers, the LoadRecords prefix-cursor load machinery (in the
// .cpp), and RunWithinTxn.
//
// Lattica's wallet is pure-HD and keystore-only, so the only records are: the HD
// chain (the seed + counter, encrypted when the wallet is), the encryption master
// keys, transactions, the address book, locked UTXOs, the order counter, the wallet
// flags, and the version. Private keys are NOT stored per-key -- the whole key tree
// re-derives from the seed on load.

#ifndef LATTICA_WALLET_WALLETDB_H
#define LATTICA_WALLET_WALLETDB_H

#include <clientversion.h>
#include <key.h>
#include <primitives/transaction_identifier.h>
#include <serialize.h>
#include <uint256.h>
#include <wallet/crypter.h>
#include <wallet/db.h>

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>
#include <vector>

class CScript;
struct CBlockLocator;
struct COutPoint;

namespace wallet {
class CWallet;
class CWalletTx;

//! Logs information about the wallet database during startup.
void LogDBInfo();

/** Error statuses for the wallet database, in order of severity (highest wins). */
enum class DBErrors : int
{
    LOAD_OK = 0,
    NEED_RESCAN = 1,
    NONCRITICAL_ERROR = 4,
    TOO_NEW = 5,
    LOAD_FAIL = 7,
    CORRUPT = 10,
};

namespace DBKeys {
extern const std::string BESTBLOCK;
extern const std::string DESTDATA;
extern const std::string FLAGS;
extern const std::string HDCHAIN;
extern const std::string LOCKED_UTXO;
extern const std::string MASTER_KEY;
extern const std::string MINVERSION;
extern const std::string NAME;
extern const std::string ORDERPOSNEXT;
extern const std::string PUBKEYID;
extern const std::string PURPOSE;
extern const std::string TX;
extern const std::string VERSION;
} // namespace DBKeys

/**
 * The HD chain model: the ML-DSA HD seed and the count of keys handed out. The
 * whole key tree re-derives from the seed, so this single record (plus the
 * encryption master key) is the wallet's entire key material.
 */
class CHDChain
{
public:
    uint32_t nExternalChainCounter{0}; //!< number of keys derived so far
    CKeyID seed_id;                    //!< id (hash) of the HD master public key
    //! The 32-byte HD seed in the clear. Null when the wallet is encrypted -- then
    //! the seed lives only in crypted_seed below.
    uint256 hd_seed;
    //! The AES-256-CBC encryption of the seed, present iff the wallet is encrypted.
    std::vector<unsigned char> crypted_seed;

    static const int VERSION_HD_BASE = 1;
    static const int CURRENT_VERSION  = VERSION_HD_BASE;
    int nVersion;

    CHDChain() { SetNull(); }

    SERIALIZE_METHODS(CHDChain, obj)
    {
        READWRITE(obj.nVersion, obj.nExternalChainCounter, obj.seed_id, obj.hd_seed, obj.crypted_seed);
    }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        nExternalChainCounter = 0;
        seed_id.SetNull();
        hd_seed.SetNull();
        crypted_seed.clear();
    }
};

struct DbTxnListener {
    std::function<void()> on_commit, on_abort;
};

/**
 * Access to the wallet database. Opens it and provides read/write access; each
 * read/write is its own transaction unless wrapped in TxnBegin()/TxnCommit().
 */
class WalletBatch
{
private:
    template <typename K, typename T>
    bool WriteIC(const K& key, const T& value, bool fOverwrite = true)
    {
        return m_batch->Write(key, value, fOverwrite);
    }

    template <typename K>
    bool EraseIC(const K& key)
    {
        return m_batch->Erase(key);
    }

public:
    explicit WalletBatch(WalletDatabase& database) : m_batch(database.MakeBatch()) {}
    WalletBatch(const WalletBatch&) = delete;
    WalletBatch& operator=(const WalletBatch&) = delete;

    bool WriteName(const std::string& strAddress, const std::string& strName);
    bool EraseName(const std::string& strAddress);

    bool WritePurpose(const std::string& strAddress, const std::string& purpose);
    bool ErasePurpose(const std::string& strAddress);

    bool WriteTx(const CWalletTx& wtx);
    bool EraseTx(const Txid& hash);

    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey);
    bool EraseMasterKey(unsigned int id);
    //! Returns true if the wallet stores any encryption master key.
    bool IsEncrypted();

    //! Write/read the HD chain (the seed + counter, sealed when encrypted).
    bool WriteHDChain(const CHDChain& chain);

    //! Record a derived key's id (public data), so an encrypted+locked wallet can still
    //! recognise its own outputs (IsMine) and show a balance without the sealed seed.
    bool WritePubKeyId(const CKeyID& keyid);

    bool WriteBestBlock(const CBlockLocator& locator);
    bool ReadBestBlock(CBlockLocator& locator);

    bool WriteOrderPosNext(int64_t nOrderPosNext);
    bool WriteWalletFlags(uint64_t flags);

    bool WriteLockedUTXO(const COutPoint& output);
    bool EraseLockedUTXO(const COutPoint& output);

    //! DESTDATA address-metadata. The caller passes a pre-encoded address string
    //! (Lattica has no global Params() to encode a CTxDestination here).
    bool WriteAddressPreviouslySpent(const std::string& address, bool previously_spent);
    bool WriteAddressReceiveRequest(const std::string& address, const std::string& id, const std::string& receive_request);
    bool EraseAddressReceiveRequest(const std::string& address, const std::string& id);

    bool WriteVersion(int version);
    bool WriteMinVersion(int version);

    //! Delete records of the given types.
    bool EraseRecords(const std::unordered_set<std::string>& types);

    //! Reconstruct the wallet from its stored records.
    DBErrors LoadWallet(CWallet* pwallet);

    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort();
    bool HasActiveTxn() { return m_batch->HasActiveTxn(); }

    //! Register callbacks fired on the current db txn's commit/abort.
    void RegisterTxnListener(const DbTxnListener& l);

private:
    std::unique_ptr<DatabaseBatch> m_batch;
    std::vector<DbTxnListener> m_txn_listeners;
};

/**
 * Run the provided function within a database transaction: writes commit
 * atomically on success, roll back if it returns false or throws.
 */
bool RunWithinTxn(WalletDatabase& database, std::string_view process_desc, const std::function<bool(WalletBatch&)>& func);

} // namespace wallet

#endif // LATTICA_WALLET_WALLETDB_H
