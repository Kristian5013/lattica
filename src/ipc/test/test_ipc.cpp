// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Standalone runner for the multiprocess IPC tests (Lattica uses per-file test
// mains, not Boost.Test). Exercises the type-conversion round-trip over an
// in-process pipe (IpcPipeTest), the Protocol serve()/connect() over a
// socketpair (IpcSocketPairTest), the Process bind()/connect() over a unix
// socket (IpcSocketTest), and the address parser. Built only under ENABLE_IPC
// (unix); see src/ipc/CMakeLists.txt.

#include <ipc/process.h>
#include <ipc/test/ipc_test.h>
#include <util/fs.h>

#include <cstdio>
#include <memory>
#include <string>
#include <system_error>

int g_fail = 0;
void IpcCheck(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

//! Test ipc::Process address parsing (canonicalization + error reporting).
static void ParseAddressTest()
{
    std::unique_ptr<ipc::Process> process{ipc::MakeProcess()};
    fs::path datadir{"/var/empty/notexist"};
    auto check_address{[&](std::string address, std::string expect_address, std::string expect_error) {
        std::string addr{address};
        bool threw_expected{false};
        try {
            process->connect(datadir, "test_lattica", addr);
        } catch (const std::system_error& e) {
            // Address parsed fine; the socket file just doesn't exist (datadir is absent).
            threw_expected = expect_error.empty() && e.code() == std::errc::no_such_file_or_directory;
        } catch (const std::invalid_argument& e) {
            threw_expected = !expect_error.empty() && std::string{e.what()}.find(expect_error) != std::string::npos;
        }
        IpcCheck(("parse throws: " + address).c_str(), threw_expected);
        IpcCheck(("parse canonical: " + address).c_str(), addr == expect_address);
    }};
    const std::string long_name{std::string(100, '0') + ".sock"};
    check_address("unix", "unix:/var/empty/notexist/test_lattica.sock", "");
    check_address("unix:", "unix:/var/empty/notexist/test_lattica.sock", "");
    check_address("unix:path.sock", "unix:/var/empty/notexist/path.sock", "");
    check_address("unix:" + long_name, "unix:/var/empty/notexist/" + long_name,
                  "exceeded maximum socket path length");
    check_address("invalid", "invalid", "Unrecognized address 'invalid'");
}

int main()
{
    IpcPipeTest();
    IpcSocketPairTest();
    IpcSocketTest(fs::temp_directory_path());
    ParseAddressTest();
    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
