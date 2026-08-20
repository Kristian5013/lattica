// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// The wallet database abstraction, ported from Bitcoin Core's wallet/db.h. The
// interface (DatabaseCursor / DatabaseBatch with its typed Read/Write/Erase/Exists
// helpers, WalletDatabase, DatabaseOptions/Status) is scheme-agnostic and ported
// faithfully. Lattica keeps Core's SQLite wallet backend (see wallet/sqlite.cpp)
// but only that one -- Core's legacy BDB backend and its BDB/SQLite format-sniffing
// don't apply, so MakeDatabase dispatches straight to the SQLite backend (db.cpp).

#ifndef LATTICA_WALLET_DB_H
#define LATTICA_WALLET_DB_H

#include <streams.h>
#include <support/allocators/secure.h>
#include <util/fs.h>

#include <atomic>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

struct bilingual_str;

namespace wallet {

//! BytePrefix compares equality with other byte spans that begin with the same prefix.
struct BytePrefix {
    std::span<const std::byte> prefix;
};
bool operator<(BytePrefix a, std::span<const std::byte> b);
bool operator<(std::span<const std::byte> a, BytePrefix b);

class DatabaseCursor
{
public:
    explicit DatabaseCursor() = default;
    virtual ~DatabaseCursor() = default;

    DatabaseCursor(const DatabaseCursor&) = delete;
    DatabaseCursor& operator=(const DatabaseCursor&) = delete;

    enum class Status {
        FAIL,
        MORE,
        DONE,
    };

    virtual Status Next(DataStream& key, DataStream& value) { return Status::FAIL; }
};

/** RAII class that provides access to a WalletDatabase */
class DatabaseBatch
{
private:
    virtual bool ReadKey(DataStream&& key, DataStream& value) = 0;
    virtual bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite = true) = 0;
    virtual bool EraseKey(DataStream&& key) = 0;
    virtual bool HasKey(DataStream&& key) = 0;

public:
    explicit DatabaseBatch() = default;
    virtual ~DatabaseBatch() = default;

    DatabaseBatch(const DatabaseBatch&) = delete;
    DatabaseBatch& operator=(const DatabaseBatch&) = delete;

    virtual void Close() = 0;

    template <typename K, typename T>
    bool Read(const K& key, T& value)
    {
        DataStream ssKey{};
        ssKey.reserve(1000);
        ssKey << key;

        DataStream ssValue{};
        if (!ReadKey(std::move(ssKey), ssValue)) return false;
        try {
            ssValue >> value;
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    template <typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite = true)
    {
        DataStream ssKey{};
        ssKey.reserve(1000);
        ssKey << key;

        DataStream ssValue{};
        ssValue.reserve(10000);
        ssValue << value;

        return WriteKey(std::move(ssKey), std::move(ssValue), fOverwrite);
    }

    template <typename K>
    bool Erase(const K& key)
    {
        DataStream ssKey{};
        ssKey.reserve(1000);
        ssKey << key;
        return EraseKey(std::move(ssKey));
    }

    template <typename K>
    bool Exists(const K& key)
    {
        DataStream ssKey{};
        ssKey.reserve(1000);
        ssKey << key;
        return HasKey(std::move(ssKey));
    }

    virtual bool ErasePrefix(std::span<const std::byte> prefix) = 0;

    virtual std::unique_ptr<DatabaseCursor> GetNewCursor() = 0;
    virtual std::unique_ptr<DatabaseCursor> GetNewPrefixCursor(std::span<const std::byte> prefix) = 0;
    virtual bool TxnBegin() = 0;
    virtual bool TxnCommit() = 0;
    virtual bool TxnAbort() = 0;
    virtual bool HasActiveTxn() = 0;
};

/** An instance of this class represents one database. */
class WalletDatabase
{
public:
    WalletDatabase() = default;
    virtual ~WalletDatabase() = default;

    /** Open the database if it is not already opened. */
    virtual void Open() = 0;

    //! Counts the number of active database users, so the database is not closed while in use.
    std::atomic<int> m_refcount{0};

    /** Rewrite the entire database on disk. */
    virtual bool Rewrite() = 0;

    /** Back up the entire database to a file. */
    virtual bool Backup(const std::string& strDest) const = 0;

    /** Flush to the database file and close the database. */
    virtual void Close() = 0;

    /** Return path to main database file for logs and error messages. */
    virtual std::string Filename() = 0;

    /** Return paths to all database created files. */
    virtual std::vector<fs::path> Files() = 0;

    virtual std::string Format() = 0;

    /** Make a DatabaseBatch connected to this database. */
    virtual std::unique_ptr<DatabaseBatch> MakeBatch() = 0;
};

struct DatabaseOptions {
    bool require_existing = false;
    bool require_create = false;
    bool verify = true;           //!< Check data integrity on load.
    bool use_unsafe_sync = false; //!< Disable file sync for faster performance.
    uint64_t create_flags = 0;    //!< Wallet flags to set on a freshly created wallet.
    SecureString create_passphrase; //!< If non-empty, encrypt a freshly created wallet with this.
};

enum class DatabaseStatus {
    SUCCESS,
    FAILED_BAD_PATH,
    FAILED_ALREADY_EXISTS,
    FAILED_NOT_FOUND,
    FAILED_CREATE,
    FAILED_LOAD,
    FAILED_VERIFY,
};

//! Open (or create) the wallet database at `path` (backed by SQLite).
std::unique_ptr<WalletDatabase> MakeDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error);

//! Path to the SQLite data file inside a wallet directory.
fs::path SQLiteDataFile(const fs::path& path);

} // namespace wallet

#endif // LATTICA_WALLET_DB_H
