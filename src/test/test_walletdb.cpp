// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the wallet database (wallet/db.h + the SQLite backend in sqlite.cpp):
// records round-trip through Read/Write/Exists/Erase, overwrite vs insert, a full
// cursor and a prefix cursor, transactions (commit persists, abort discards), and
// cross-instance persistence (write, close, reopen, read).

#include <wallet/db.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <streams.h>
#include <util/fs.h>
#include <util/translation.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

std::unique_ptr<wallet::WalletDatabase> Open(const fs::path& dir)
{
    wallet::DatabaseOptions options;
    wallet::DatabaseStatus status;
    bilingual_str error;
    auto db = wallet::MakeDatabase(dir, options, status, error);
    if (!db) std::printf("    open error: %s\n", error.original.c_str());
    return db;
}
} // namespace

int main()
{
    // A SQLite wallet stamps the network's magic into the file as its
    // application_id, and refuses a file carrying another network's, so opening
    // one at all needs a network to have been chosen.
    SelectParams(ChainType::MAIN);

    const char* lad = std::getenv("LOCALAPPDATA");
    const std::string base = (lad && *lad) ? (std::string(lad) + "/lattica_walletdb_test")
                                           : std::string("lattica_walletdb_test");
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    const fs::path dir = fs::PathFromString(base);

    {
        auto db = Open(dir);
        Check("open wallet database", db != nullptr);
        auto batch = db->MakeBatch();

        // Read/Write/Exists.
        Check("write a record", batch->Write(std::string("alpha"), std::string("one")));
        std::string v;
        Check("read it back", batch->Read(std::string("alpha"), v) && v == "one");
        Check("Exists is true", batch->Exists(std::string("alpha")));
        Check("Exists is false for missing", !batch->Exists(std::string("nope")));

        // Overwrite (default) vs insert (overwrite=false on an existing key fails).
        Check("overwrite succeeds", batch->Write(std::string("alpha"), std::string("uno")));
        Check("read shows the overwrite", batch->Read(std::string("alpha"), v) && v == "uno");
        Check("no-overwrite on existing key fails", !batch->Write(std::string("alpha"), std::string("x"), /*fOverwrite=*/false));

        // Erase.
        Check("erase", batch->Erase(std::string("alpha")));
        Check("erased key is gone", !batch->Exists(std::string("alpha")));

        // Full cursor over several records.
        batch->Write(std::string("k1"), std::string("v1"));
        batch->Write(std::string("k2"), std::string("v2"));
        batch->Write(std::string("k3"), std::string("v3"));
        {
            auto cursor = db->MakeBatch()->GetNewCursor();
            int count = 0;
            DataStream key{}, value{};
            while (cursor->Next(key, value) == wallet::DatabaseCursor::Status::MORE) ++count;
            Check("cursor sees all three records", count == 3);
        }

        // Prefix cursor: composite (type, subkey) keys, scanned by the serialized
        // type. This is how the wallet groups records (e.g. all "key" entries).
        batch->Write(std::make_pair(std::string("grp"), std::string("a")), std::string("1"));
        batch->Write(std::make_pair(std::string("grp"), std::string("b")), std::string("2"));
        batch->Write(std::make_pair(std::string("xyz"), std::string("c")), std::string("3"));
        {
            DataStream pfx{};
            pfx << std::string("grp"); // serialized "grp" = the common prefix of the grp keys
            const std::span<const std::byte> prefix{pfx.data(), pfx.size()};
            auto cursor = db->MakeBatch()->GetNewPrefixCursor(prefix);
            int count = 0;
            DataStream key{}, value{};
            while (cursor->Next(key, value) == wallet::DatabaseCursor::Status::MORE) ++count;
            Check("prefix cursor sees only the two grp records", count == 2);
        }

        // Transactions: commit persists, abort discards.
        {
            auto b = db->MakeBatch();
            Check("TxnBegin", b->TxnBegin());
            b->Write(std::string("tx_commit"), std::string("yes"));
            Check("TxnCommit", b->TxnCommit());
            Check("committed record is present", b->Exists(std::string("tx_commit")));

            Check("TxnBegin again", b->TxnBegin());
            b->Write(std::string("tx_abort"), std::string("no"));
            Check("TxnAbort", b->TxnAbort());
            Check("aborted record is absent", !b->Exists(std::string("tx_abort")));
        }
    }

    // Cross-instance persistence: reopen the same directory and read a record.
    {
        auto db = Open(dir);
        auto batch = db->MakeBatch();
        std::string v;
        Check("reopened db: committed record persists", batch->Read(std::string("tx_commit"), v) && v == "yes");
        Check("reopened db: k2 persists", batch->Read(std::string("k2"), v) && v == "v2");
        Check("reopened db: aborted record absent", !batch->Exists(std::string("tx_abort")));
    }

    std::filesystem::remove_all(base);
    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
