// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// The wallet's persistence implementation, in the style of Bitcoin Core's
// wallet/walletdb.cpp but adapted for Lattica's pure-HD keystore wallet (see
// wallet/walletdb.h). It keeps Core's LoadRecords prefix-cursor load machinery and
// RunWithinTxn, but only the scheme-agnostic records a keystore wallet has -- there
// are no descriptor, per-key, watch-only or active-ScriptPubKeyMan records.

#include <wallet/walletdb.h>

#include <addresstype.h>
#include <key_io.h>
#include <logging.h>
#include <primitives/block.h>
#include <wallet/sqlite.h>
#include <wallet/wallet.h>

#include <algorithm>

namespace wallet {

namespace DBKeys {
const std::string BESTBLOCK{"bestblock"};
const std::string DESTDATA{"destdata"};
const std::string FLAGS{"flags"};
const std::string HDCHAIN{"hdchain"};
const std::string LOCKED_UTXO{"lockedutxo"};
const std::string MASTER_KEY{"mkey"};
const std::string MINVERSION{"minversion"};
const std::string NAME{"name"};
const std::string ORDERPOSNEXT{"orderposnext"};
const std::string PUBKEYID{"pubkeyid"};
const std::string PURPOSE{"purpose"};
const std::string TX{"tx"};
const std::string VERSION{"version"};
} // namespace DBKeys

void LogDBInfo()
{
    LogInfo("Using SQLite Version %s", SQLiteDatabaseVersion());
}

//
// WalletBatch writers
//

bool WalletBatch::WriteName(const std::string& strAddress, const std::string& strName)
{
    return WriteIC(std::make_pair(DBKeys::NAME, strAddress), strName);
}

bool WalletBatch::EraseName(const std::string& strAddress)
{
    return EraseIC(std::make_pair(DBKeys::NAME, strAddress));
}

bool WalletBatch::WritePurpose(const std::string& strAddress, const std::string& strPurpose)
{
    return WriteIC(std::make_pair(DBKeys::PURPOSE, strAddress), strPurpose);
}

bool WalletBatch::ErasePurpose(const std::string& strAddress)
{
    return EraseIC(std::make_pair(DBKeys::PURPOSE, strAddress));
}

bool WalletBatch::WriteTx(const CWalletTx& wtx)
{
    return WriteIC(std::make_pair(DBKeys::TX, wtx.GetHash().ToUint256()), wtx);
}

bool WalletBatch::EraseTx(const Txid& hash)
{
    return EraseIC(std::make_pair(DBKeys::TX, hash.ToUint256()));
}

bool WalletBatch::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    return WriteIC(std::make_pair(DBKeys::MASTER_KEY, nID), kMasterKey, true);
}

bool WalletBatch::EraseMasterKey(unsigned int id)
{
    return EraseIC(std::make_pair(DBKeys::MASTER_KEY, id));
}

bool WalletBatch::IsEncrypted()
{
    DataStream prefix;
    prefix << DBKeys::MASTER_KEY;
    if (auto cursor = m_batch->GetNewPrefixCursor(prefix)) {
        DataStream k, v;
        if (cursor->Next(k, v) == DatabaseCursor::Status::MORE) return true;
    }
    return false;
}

bool WalletBatch::WriteHDChain(const CHDChain& chain)
{
    return WriteIC(DBKeys::HDCHAIN, chain);
}

bool WalletBatch::WritePubKeyId(const CKeyID& keyid)
{
    return WriteIC(std::make_pair(DBKeys::PUBKEYID, keyid), uint8_t{1});
}

bool WalletBatch::WriteBestBlock(const CBlockLocator& locator)
{
    return WriteIC(DBKeys::BESTBLOCK, locator);
}

bool WalletBatch::ReadBestBlock(CBlockLocator& locator)
{
    return m_batch->Read(DBKeys::BESTBLOCK, locator);
}

bool WalletBatch::WriteOrderPosNext(int64_t nOrderPosNext)
{
    return WriteIC(DBKeys::ORDERPOSNEXT, nOrderPosNext);
}

bool WalletBatch::WriteWalletFlags(uint64_t flags)
{
    return WriteIC(DBKeys::FLAGS, flags);
}

bool WalletBatch::WriteLockedUTXO(const COutPoint& output)
{
    return WriteIC(std::make_pair(DBKeys::LOCKED_UTXO, std::make_pair(output.hash, output.n)), uint8_t{'1'});
}

bool WalletBatch::EraseLockedUTXO(const COutPoint& output)
{
    return EraseIC(std::make_pair(DBKeys::LOCKED_UTXO, std::make_pair(output.hash, output.n)));
}

bool WalletBatch::WriteAddressPreviouslySpent(const std::string& address, bool previously_spent)
{
    auto key{std::make_pair(DBKeys::DESTDATA, std::make_pair(address, std::string("used")))};
    return previously_spent ? WriteIC(key, std::string("1")) : EraseIC(key);
}

bool WalletBatch::WriteAddressReceiveRequest(const std::string& address, const std::string& id, const std::string& receive_request)
{
    return WriteIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(address, "rr" + id)), receive_request);
}

bool WalletBatch::EraseAddressReceiveRequest(const std::string& address, const std::string& id)
{
    return EraseIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(address, "rr" + id)));
}

bool WalletBatch::WriteVersion(int version)
{
    return WriteIC(DBKeys::VERSION, version);
}

bool WalletBatch::WriteMinVersion(int version)
{
    return WriteIC(DBKeys::MINVERSION, version);
}

bool WalletBatch::EraseRecords(const std::unordered_set<std::string>& types)
{
    return std::all_of(types.begin(), types.end(), [&](const std::string& type) {
        return m_batch->ErasePrefix(DataStream() << type);
    });
}

//
// Load machinery (Core-style: one prefix cursor per record type, dispatched to a
// LoadFunc). The loaders target CWallet directly -- it is the keystore.
//

struct LoadResult {
    DBErrors m_result{DBErrors::LOAD_OK};
    int m_records{0};
};

using LoadFunc = std::function<DBErrors(CWallet* pwallet, DataStream& key, DataStream& value, std::string& err)>;

static LoadResult LoadRecords(CWallet* pwallet, DatabaseBatch& batch, const std::string& key, LoadFunc load_func)
{
    LoadResult result;
    DataStream prefix;
    prefix << key;
    std::unique_ptr<DatabaseCursor> cursor = batch.GetNewPrefixCursor(prefix);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for '%s' records\n", key);
        result.m_result = DBErrors::CORRUPT;
        return result;
    }
    DataStream ssKey, ssValue;
    while (true) {
        DatabaseCursor::Status status = cursor->Next(ssKey, ssValue);
        if (status == DatabaseCursor::Status::DONE) break;
        if (status == DatabaseCursor::Status::FAIL) {
            pwallet->WalletLogPrintf("Error reading next '%s' record\n", key);
            result.m_result = DBErrors::CORRUPT;
            return result;
        }
        std::string type;
        ssKey >> type;
        assert(type == key);
        std::string error;
        DBErrors record_res = load_func(pwallet, ssKey, ssValue, error);
        if (record_res != DBErrors::LOAD_OK) pwallet->WalletLogPrintf("%s\n", error);
        result.m_result = std::max(result.m_result, record_res);
        ++result.m_records;
    }
    return result;
}

static DBErrors LoadKeyCore(CWallet* pwallet, DatabaseBatch& batch)
{
    // HD chain: the seed (or its ciphertext) + the derived-key counter. CWallet
    // re-derives (or, when encrypted, defers) the whole keystore from it.
    LoadResult res = LoadRecords(pwallet, batch, DBKeys::HDCHAIN,
        [](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            try {
                CHDChain chain;
                value >> chain;
                pwallet->LoadHDChain(chain);
            } catch (const std::exception& e) { err = e.what(); return DBErrors::CORRUPT; }
            return DBErrors::LOAD_OK;
        });
    return res.m_result;
}

static DBErrors LoadPubKeyIds(CWallet* pwallet, DatabaseBatch& batch)
{
    // Public key ids of the wallet's derived keys. Public data, stored unencrypted, so a
    // locked encrypted wallet still recognises its own outputs (IsMine) and shows a balance
    // before the sealed seed is decrypted.
    LoadResult res = LoadRecords(pwallet, batch, DBKeys::PUBKEYID,
        [](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            try {
                CKeyID id;
                key >> id;
                pwallet->LoadPubKeyId(id);
            } catch (const std::exception& e) { err = e.what(); return DBErrors::CORRUPT; }
            return DBErrors::LOAD_OK;
        });
    return res.m_result;
}

static DBErrors LoadEncryptionKeys(CWallet* pwallet, DatabaseBatch& batch)
{
    LoadResult res = LoadRecords(pwallet, batch, DBKeys::MASTER_KEY,
        [](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            try {
                unsigned int nID;
                key >> nID;
                CMasterKey kMasterKey;
                value >> kMasterKey;
                if (pwallet->mapMasterKeys.count(nID) != 0) { err = "duplicate CMasterKey id"; return DBErrors::CORRUPT; }
                pwallet->mapMasterKeys[nID] = kMasterKey;
                if (pwallet->nMasterKeyMaxID < nID) pwallet->nMasterKeyMaxID = nID;
            } catch (const std::exception& e) { err = e.what(); return DBErrors::CORRUPT; }
            return DBErrors::LOAD_OK;
        });
    return res.m_result;
}

static DBErrors LoadAddressBook(CWallet* pwallet, DatabaseBatch& batch)
{
    DBErrors result = DBErrors::LOAD_OK;
    const CChainParams* params = pwallet->GetChainParams();

    result = std::max(result, LoadRecords(pwallet, batch, DBKeys::NAME,
        [params](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            std::string addr, label;
            key >> addr; value >> label;
            if (params) pwallet->m_address_book[DecodeDestination(addr, *params)].SetLabel(label);
            return DBErrors::LOAD_OK;
        }).m_result);

    result = std::max(result, LoadRecords(pwallet, batch, DBKeys::PURPOSE,
        [params](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            std::string addr, purpose_str;
            key >> addr; value >> purpose_str;
            if (params) pwallet->m_address_book[DecodeDestination(addr, *params)].purpose = PurposeFromString(purpose_str);
            return DBErrors::LOAD_OK;
        }).m_result);

    result = std::max(result, LoadRecords(pwallet, batch, DBKeys::DESTDATA,
        [params](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            std::string addr, item, val;
            key >> addr; key >> item; value >> val;
            if (!params) return DBErrors::LOAD_OK;
            const CTxDestination dest{DecodeDestination(addr, *params)};
            if (item == "used") pwallet->LoadAddressPreviouslySpent(dest);
            else if (item.starts_with("rr")) pwallet->LoadAddressReceiveRequest(dest, item.substr(2), val);
            return DBErrors::LOAD_OK;
        }).m_result);
    return result;
}

static DBErrors LoadTxRecords(CWallet* pwallet, DatabaseBatch& batch)
{
    DBErrors result = DBErrors::LOAD_OK;

    result = std::max(result, LoadRecords(pwallet, batch, DBKeys::TX,
        [](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            uint256 hash;
            key >> hash;
            DBErrors res = DBErrors::LOAD_OK;
            auto fill_wtx = [&](CWalletTx& wtx, bool new_tx) {
                if (!new_tx) { err = "Corrupt: duplicate tx"; res = DBErrors::CORRUPT; return false; }
                value >> wtx;
                if (wtx.GetHash() != Txid::FromUint256(hash)) return false;
                return true;
            };
            if (!pwallet->LoadToWallet(Txid::FromUint256(hash), fill_wtx)) res = std::max(res, DBErrors::NEED_RESCAN);
            return res;
        }).m_result);

    result = std::max(result, LoadRecords(pwallet, batch, DBKeys::LOCKED_UTXO,
        [](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            Txid hash; uint32_t n;
            key >> hash; key >> n;
            pwallet->LoadLockedCoin(COutPoint(hash, n), /*persistent=*/true);
            return DBErrors::LOAD_OK;
        }).m_result);

    result = std::max(result, LoadRecords(pwallet, batch, DBKeys::ORDERPOSNEXT,
        [](CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            try { value >> pwallet->nOrderPosNext; }
            catch (const std::exception& e) { err = e.what(); return DBErrors::NONCRITICAL_ERROR; }
            return DBErrors::LOAD_OK;
        }).m_result);
    return result;
}

DBErrors WalletBatch::LoadWallet(CWallet* pwallet)
{
    DBErrors result = DBErrors::LOAD_OK;
    LOCK(pwallet->cs_wallet);

    int last_client = CLIENT_VERSION;
    const bool has_last_client = m_batch->Read(DBKeys::VERSION, last_client);

    try {
        // Wallet flags first, so they are known while processing the other records.
        uint64_t flags;
        if (m_batch->Read(DBKeys::FLAGS, flags) && !pwallet->LoadWalletFlags(flags)) {
            pwallet->WalletLogPrintf("Error: unknown non-tolerable wallet flags\n");
            return DBErrors::TOO_NEW;
        }

        result = std::max(result, LoadKeyCore(pwallet, *m_batch));
        result = std::max(result, LoadPubKeyIds(pwallet, *m_batch));
        result = std::max(result, LoadEncryptionKeys(pwallet, *m_batch));
        result = std::max(result, LoadAddressBook(pwallet, *m_batch));
        result = std::max(result, LoadTxRecords(pwallet, *m_batch));
    } catch (const std::runtime_error& e) {
        pwallet->WalletLogPrintf("%s\n", e.what());
        result = DBErrors::CORRUPT;
    } catch (...) {
        result = DBErrors::CORRUPT;
    }

    if (result != DBErrors::LOAD_OK) return result;
    if (!has_last_client || last_client != CLIENT_VERSION) WriteVersion(CLIENT_VERSION);
    return result;
}

//
// Transactions
//

static bool RunWithinTxnImpl(WalletBatch& batch, std::string_view process_desc, const std::function<bool(WalletBatch&)>& func)
{
    if (!batch.TxnBegin()) { LogInfo("Error: cannot create db txn for %s", process_desc); return false; }
    if (!func(batch)) { LogInfo("Error: %s failed", process_desc); batch.TxnAbort(); return false; }
    if (!batch.TxnCommit()) { LogInfo("Error: cannot commit db txn for %s", process_desc); return false; }
    return true;
}

bool RunWithinTxn(WalletDatabase& database, std::string_view process_desc, const std::function<bool(WalletBatch&)>& func)
{
    WalletBatch batch(database);
    return RunWithinTxnImpl(batch, process_desc, func);
}

bool WalletBatch::TxnBegin() { return m_batch->TxnBegin(); }

bool WalletBatch::TxnCommit()
{
    bool res = m_batch->TxnCommit();
    if (res) {
        for (const auto& listener : m_txn_listeners) listener.on_commit();
        m_txn_listeners.clear();
    }
    return res;
}

bool WalletBatch::TxnAbort()
{
    bool res = m_batch->TxnAbort();
    if (res) {
        for (const auto& listener : m_txn_listeners) listener.on_abort();
        m_txn_listeners.clear();
    }
    return res;
}

void WalletBatch::RegisterTxnListener(const DbTxnListener& l)
{
    assert(m_batch->HasActiveTxn());
    m_txn_listeners.emplace_back(l);
}

} // namespace wallet
