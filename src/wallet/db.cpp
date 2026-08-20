// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// The "common" wallet-database file, mirroring Bitcoin Core's wallet/db.cpp.
// In Core this file is almost entirely backend-dispatch and format-sniffing
// (ListDatabases scans a directory for wallet.dat files, IsBDBFile/IsSQLiteFile
// sniff their magic bytes, MakeDatabase picks BDB vs SQLite) -- but Lattica keeps
// only the SQLite backend, so MakeDatabase dispatches straight to it and the
// BDB-format helpers are dropped. The scheme-agnostic pieces Core keeps here -- the
// BytePrefix comparator and SQLiteDataFile -- are reproduced faithfully.

#include <wallet/db.h>

#include <util/fs.h>
#include <wallet/sqlite.h>

#include <algorithm>

namespace wallet {

bool operator<(BytePrefix a, std::span<const std::byte> b) { return std::ranges::lexicographical_compare(a.prefix, b.subspan(0, std::min(a.prefix.size(), b.size()))); }
bool operator<(std::span<const std::byte> a, BytePrefix b) { return std::ranges::lexicographical_compare(a.subspan(0, std::min(a.size(), b.prefix.size())), b.prefix); }

fs::path SQLiteDataFile(const fs::path& path)
{
    return path / "wallet.dat";
}

// Lattica has a single (SQLite) backend, so the format-dispatch MakeDatabase
// that Core keeps in walletdb.cpp collapses to a direct call here.
std::unique_ptr<WalletDatabase> MakeDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error)
{
    return MakeSQLiteDatabase(path, options, status, error);
}

} // namespace wallet
