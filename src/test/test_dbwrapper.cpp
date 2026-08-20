// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for the LevelDB wrapper (dbwrapper): write/read/exists/erase, batched
// writes, and iteration, all against an in-memory (memory_only) database so no
// filesystem is touched.

#include <dbwrapper.h>

#include <cstdio>
#include <memory>
#include <string>

namespace {
int g_fail = 0;
void Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}
} // namespace

int main()
{
    CDBWrapper db({.path = "unused-memory-db", .cache_bytes = 1 << 20, .memory_only = true});

    // Write / Read / Exists.
    db.Write(std::string("hello"), std::string("world"));
    std::string v;
    Check("Read returns written value", db.Read(std::string("hello"), v) && v == "world");
    Check("Exists true", db.Exists(std::string("hello")));
    Check("Read absent key false", !db.Read(std::string("missing"), v));

    // Erase.
    db.Erase(std::string("hello"));
    Check("after Erase: !Exists", !db.Exists(std::string("hello")));

    // Batched writes.
    {
        CDBBatch batch(db);
        batch.Write(std::string("a"), std::string("1"));
        batch.Write(std::string("b"), std::string("2"));
        batch.Write(std::string("c"), std::string("3"));
        db.WriteBatch(batch);
        std::string va, vb, vc;
        bool ok = db.Read(std::string("a"), va) && db.Read(std::string("b"), vb) && db.Read(std::string("c"), vc);
        Check("batch values readable", ok && va == "1" && vb == "2" && vc == "3");
    }

    // Iteration sees all three keys.
    {
        std::unique_ptr<CDBIterator> it(db.NewIterator());
        int count = 0;
        for (it->SeekToFirst(); it->Valid(); it->Next()) ++count;
        Check("iterator sees 3 keys", count == 3);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
