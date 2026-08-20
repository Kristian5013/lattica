// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_IPC_TEST_IPC_TEST_H
#define LATTICA_IPC_TEST_IPC_TEST_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <univalue.h>
#include <util/fs.h>
#include <validation.h>

class FooImplementation
{
public:
    int add(int a, int b) { return a + b; }
    COutPoint passOutPoint(COutPoint o) { return o; }
    UniValue passUniValue(UniValue v) { return v; }
    CTransactionRef passTransaction(CTransactionRef t) { return t; }
    std::vector<char> passVectorChar(std::vector<char> v) { return v; }
    BlockValidationState passBlockState(BlockValidationState s) { return s; }
    CScript passScript(CScript s) { return s; }
};

void IpcPipeTest();
void IpcSocketPairTest();
void IpcSocketTest(const fs::path& datadir);

//! Pass/fail check shared by the IPC test translation units (Lattica tests are
//! standalone mains, not Boost.Test). Defined in test_ipc.cpp.
void IpcCheck(const char* name, bool ok);

#endif // LATTICA_IPC_TEST_IPC_TEST_H
