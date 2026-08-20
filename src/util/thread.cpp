// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <util/thread.h>

#include <util/exception.h>
#include <util/log.h>
#include <util/threadnames.h>

#include <exception>
#include <functional>
#include <string>

void util::TraceThread(std::string_view thread_name, std::function<void()> thread_func)
{
    util::ThreadRename(std::string{thread_name});
    try {
        LogInfo("%s thread start", thread_name);
        thread_func();
        LogInfo("%s thread exit", thread_name);
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, thread_name);
        throw;
    } catch (...) {
        PrintExceptionContinue(nullptr, thread_name);
        throw;
    }
}
