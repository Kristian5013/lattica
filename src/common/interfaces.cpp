// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Implementations of the small, process-agnostic interface helpers declared in
// interfaces/: the signal/cleanup Handlers and the Echo test interface. The
// heavier Node/Chain/Mining/Wallet implementations live in node/interfaces.cpp
// and wallet/interfaces.cpp.

#include <interfaces/echo.h>
#include <interfaces/handler.h>
#include <util/btcsignals.h>

#include <memory>
#include <utility>

namespace common {
namespace {
class CleanupHandler : public interfaces::Handler
{
public:
    explicit CleanupHandler(std::function<void()> cleanup) : m_cleanup(std::move(cleanup)) {}
    ~CleanupHandler() override { if (!m_cleanup) return; m_cleanup(); m_cleanup = nullptr; }
    void disconnect() override { if (!m_cleanup) return; m_cleanup(); m_cleanup = nullptr; }
    std::function<void()> m_cleanup;
};

class SignalHandler : public interfaces::Handler
{
public:
    explicit SignalHandler(btcsignals::connection connection) : m_connection(std::move(connection)) {}

    void disconnect() override { m_connection.disconnect(); }

    btcsignals::scoped_connection m_connection;
};

class EchoImpl : public interfaces::Echo
{
public:
    std::string echo(const std::string& echo) override { return echo; }
};
} // namespace
} // namespace common

namespace interfaces {
std::unique_ptr<Handler> MakeCleanupHandler(std::function<void()> cleanup)
{
    return std::make_unique<common::CleanupHandler>(std::move(cleanup));
}

std::unique_ptr<Handler> MakeSignalHandler(btcsignals::connection connection)
{
    return std::make_unique<common::SignalHandler>(std::move(connection));
}

std::unique_ptr<Echo> MakeEcho() { return std::make_unique<common::EchoImpl>(); }
} // namespace interfaces
