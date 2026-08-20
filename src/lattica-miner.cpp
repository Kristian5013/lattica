// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// lattica-miner — a standalone CPU miner. It talks to a running latticad over
// JSON-RPC: getblocktemplate to obtain the next block, assembles it (coinbase +
// the template's transactions + the SHA3 merkle root), grinds the 80-byte header
// against the consensus SHA3-256d proof-of-work (CBlockHeader::GetPoWHash, so the
// mined work is bit-identical to the node's own), and submitblock's the first
// solution. The extranonce rolls between rounds; a tip check drops stale work.
//
// The node's own generatetoaddress RPC is single-threaded and defaults to a
// million tries, which is 0.02% of the ~2^32 needed at difficulty 1 -- fine for
// regtest, useless for mining. This exists so a plain CPU can actually take part
// from the first block.
//
// Modes:
//   lattica-miner -address=<addr>   mine to a running latticad
//   lattica-miner -benchmark        measure this machine's SHA3-256d hashrate

#include <addresstype.h>
#include <arith_uint256.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <compat/compat.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <key_io.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/request.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/exception.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>

#include <netbase.h>
#include <util/sock.h>
#include <util/string.h>
#include <util/syserror.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

static const int DEFAULT_HTTP_CLIENT_TIMEOUT = 900;

static void SetupMinerArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);
    SetupChainParamsBaseOptions(argsman);
    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-conf=<file>", strprintf("Specify configuration file. Relative paths will be prefixed by datadir location. (default: %s)", BITCOIN_CONF_FILENAME), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-datadir=<dir>", "Specify data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcconnect=<ip>", "Send commands to node running on <ip> (default: 127.0.0.1)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcport=<port>", "Connect to JSON-RPC on <port> (default: chain-specific)", ArgsManager::ALLOW_ANY | ArgsManager::NETWORK_ONLY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpccookiefile=<loc>", "Location of the auth cookie (default: data dir)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcuser=<user>", "Username for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-rpcpassword=<pw>", "Password for JSON-RPC connections", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-address=<addr>", "Mine the coinbase reward to this address (required for network mining)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-threads=<n>", "Worker threads (default: all cores)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-benchmark", "Measure this machine's SHA3-256d hashrate and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-seconds=<s>", "Benchmark duration in seconds (default: 8)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);}

// ----------------------------------------------------------------------------
// Minimal Sock-based JSON-RPC client (modeled on lattica-cli).
// ----------------------------------------------------------------------------
class CConnectionFailed : public std::runtime_error
{
public:
    explicit inline CConnectionFailed(const std::string& msg) : std::runtime_error(msg) {}
};

struct HTTPError : std::runtime_error {
    explicit inline HTTPError(const std::string& msg) : std::runtime_error(msg) {}
};

class HTTPResponseHeaders
{
    std::vector<std::pair<std::string, std::string>> m_headers;

public:
    void Read(util::LineReader& reader);
    std::optional<std::string> FindFirst(std::string_view key) const;
};

void HTTPResponseHeaders::Read(util::LineReader& reader)
{
    while (auto maybe_line = reader.ReadLine()) {
        const std::string_view line = *maybe_line;
        if (line.empty()) return;
        const size_t pos{line.find(':')};
        if (pos == std::string::npos) throw HTTPError{"Header missing colon (:)"};
        std::string key = util::TrimString(std::string_view(line).substr(0, pos));
        std::string value = util::TrimString(std::string_view(line).substr(pos + 1));
        if (key.empty()) throw HTTPError{"Empty header name"};
        m_headers.emplace_back(std::move(key), std::move(value));
    }
}

std::optional<std::string> HTTPResponseHeaders::FindFirst(std::string_view key) const
{
    for (const auto& item : m_headers) {
        if (CaseInsensitiveEqual(key, item.first)) return item.second;
    }
    return std::nullopt;
}

struct HTTPResponse {
    int status{0};
    std::string body;
};

class HTTPClient
{
public:
    static HTTPClient Connect(const std::string& host, uint16_t port, std::chrono::seconds timeout);
    HTTPResponse Post(const std::string& endpoint,
                      std::span<const std::pair<std::string, std::string>> headers,
                      const std::string& body);

private:
    struct RecvEOF : CConnectionFailed { using CConnectionFailed::CConnectionFailed; };
    std::unique_ptr<Sock> m_socket;
    std::string m_host;
    std::chrono::seconds m_timeout;

    HTTPClient(std::unique_ptr<Sock>&& socket, const std::string& host, std::chrono::seconds timeout)
        : m_socket(std::move(socket)), m_host(host), m_timeout(timeout) {}
    bool SendRequest(std::string_view request);
    HTTPResponse ReadResponse();
    std::optional<std::string> Recv(std::chrono::time_point<std::chrono::steady_clock> deadline);
};

HTTPClient HTTPClient::Connect(const std::string& host, uint16_t port, std::chrono::seconds timeout)
{
    std::vector<CService> services = Lookup(host, port, /*fAllowLookup=*/true, /*nMaxSolutions=*/256);
    if (services.empty()) throw CConnectionFailed(strprintf("Could not resolve host: %s", host));

    const auto deadline{std::chrono::steady_clock::now() + timeout};
    for (const CService& service : services) {
        const auto time_left{std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())};
        if (time_left.count() <= 0) break;
        auto sock = ConnectDirectly(service, /*manual_connection=*/true, time_left);
        if (sock) return HTTPClient{std::move(sock), host, timeout};
    }
    throw CConnectionFailed{"Could not connect to the server"};
}

HTTPResponse HTTPClient::Post(const std::string& endpoint,
                              std::span<const std::pair<std::string, std::string>> headers,
                              const std::string& body)
{
    try {
        std::string request = strprintf("POST %s HTTP/1.1\r\n"
                                        "Host: %s\r\n"
                                        "Connection: close\r\n"
                                        "Content-Length: %d\r\n",
                                        endpoint, m_host, body.size());
        for (const auto& [name, value] : headers) request += strprintf("%s: %s\r\n", name, value);
        request += "\r\n";
        request += body;
        if (!SendRequest(request)) throw CConnectionFailed("Failed to send HTTP request");
        return ReadResponse();
    } catch (const HTTPError& e) {
        throw CConnectionFailed(strprintf("HTTP error: %s", e.what()));
    }
}

bool HTTPClient::SendRequest(std::string_view request)
{
    const auto deadline{std::chrono::steady_clock::now() + m_timeout};
    while (!request.empty()) {
        Sock::Event event{0};
        auto time_left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (time_left.count() <= 0 || !m_socket->Wait(time_left, Sock::SendEvent, &event)) return false;
        if (!(event & Sock::SendEvent)) continue;
        ssize_t sent = m_socket->Send(request.data(), request.size(), MSG_NOSIGNAL);
        if (sent < 0) {
            int err = WSAGetLastError();
            if (!IOErrorIsPermanent(err)) { std::this_thread::yield(); continue; }
            return false;
        }
        request.remove_prefix(sent);
    }
    return true;
}

HTTPResponse HTTPClient::ReadResponse()
{
    HTTPResponse response;
    std::string buffer;
    const auto deadline{std::chrono::steady_clock::now() + m_timeout};
    size_t headers_end = 0;

    while (headers_end == 0) {
        if (auto result{Recv(deadline)}) buffer.append(*result);
        else { std::this_thread::yield(); continue; }
        size_t pos = buffer.find("\r\n\r\n");
        if (pos != std::string::npos) headers_end = pos + 4;
    }

    util::LineReader reader(std::string_view{buffer.data(), headers_end}, headers_end);
    auto status_line = reader.ReadLine();
    if (!status_line) throw HTTPError{"Failed to read status line"};
    const std::string_view status_str = *status_line;
    if (status_str.size() < 12 || !status_str.starts_with("HTTP/")) throw HTTPError{"Invalid status line"};
    size_t space1 = status_str.find(' ');
    if (space1 == std::string::npos || space1 + 4 > status_str.size()) throw HTTPError{"Invalid status line format"};
    const std::string_view status_code_str = status_str.substr(space1 + 1, 3);
    auto status_code = ToIntegral<int>(status_code_str);
    if (!status_code) throw HTTPError{"Invalid status code"};
    response.status = *status_code;

    HTTPResponseHeaders headers;
    headers.Read(reader);

    size_t content_length = 0;
    bool chunked = false;
    auto transfer_encoding = headers.FindFirst("transfer-encoding");
    if (transfer_encoding && ToLower(*transfer_encoding).find("chunked") != std::string::npos) {
        chunked = true;
    } else {
        auto content_length_header = headers.FindFirst("content-length");
        if (content_length_header) {
            auto maybe_len = ToIntegral<size_t>(*content_length_header);
            if (!maybe_len) throw HTTPError{"Invalid Content-Length"};
            content_length = *maybe_len;
        }
    }

    buffer.erase(0, headers_end);

    if (chunked) {
        std::string body;
        while (true) {
            std::string_view chunk_data{buffer};
            size_t line_end = chunk_data.find("\r\n");
            if (line_end != std::string::npos) {
                std::string_view size_str = chunk_data.substr(0, line_end);
                size_t semi = size_str.find(';');
                if (semi != std::string::npos) size_str = size_str.substr(0, semi);
                const auto chunk_size{ToIntegral<uint64_t>(util::TrimStringView(size_str), /*base=*/16)};
                if (!chunk_size) throw HTTPError{"Invalid chunk size"};
                if (*chunk_size == 0) {
                    buffer.erase(0, line_end + 2);
                    while (true) {
                        size_t crlf_pos = buffer.find("\r\n");
                        if (crlf_pos == std::string::npos) {
                            if (auto result{Recv(deadline)}) buffer.append(*result);
                            else std::this_thread::yield();
                            continue;
                        }
                        buffer.erase(0, crlf_pos + 2);
                        if (crlf_pos == 0) break;
                    }
                    break;
                }
                size_t chunk_start = line_end + 2;
                if (*chunk_size > std::numeric_limits<size_t>::max() - chunk_start - 2) throw HTTPError{"Chunk size too large"};
                size_t chunk_end = chunk_start + *chunk_size + 2;
                if (buffer.size() >= chunk_end) {
                    body.append(buffer, chunk_start, *chunk_size);
                    buffer.erase(0, chunk_end);
                    continue;
                }
            }
            while (true) {
                if (auto result{Recv(deadline)}) { buffer.append(*result); break; }
                else std::this_thread::yield();
            }
        }
        response.body = std::move(body);
    } else if (content_length > 0) {
        while (buffer.size() < content_length) {
            if (auto result{Recv(deadline)}) buffer.append(*result);
            else std::this_thread::yield();
        }
        buffer.resize(content_length);
        response.body = std::move(buffer);
    } else {
        try {
            while (true) {
                if (auto result{Recv(deadline)}) buffer.append(*result);
                else std::this_thread::yield();
            }
        } catch (const RecvEOF&) {}
        response.body = std::move(buffer);
    }
    return response;
}

std::optional<std::string> HTTPClient::Recv(const std::chrono::time_point<std::chrono::steady_clock> deadline)
{
    auto wait_for_readable{[this](std::chrono::milliseconds timeout) -> bool {
        Sock::Event event{0};
        if (!m_socket->Wait(timeout, Sock::RecvEvent, &event)) return false;
        return (event & Sock::RecvEvent) != 0;
    }};

    auto time_left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (time_left.count() <= 0 || !wait_for_readable(time_left)) throw CConnectionFailed{"timeout"};

    char recv_buf[4096];
    ssize_t nrecv = m_socket->Recv(recv_buf, sizeof(recv_buf), /*flags=*/0);
    if (nrecv < 0) {
        int err = WSAGetLastError();
        if (!IOErrorIsPermanent(err)) return std::nullopt;
        throw CConnectionFailed{strprintf("Read error: %s", NetworkErrorString(err))};
    }
    if (nrecv == 0) throw RecvEOF{"EOF"};
    return std::string{recv_buf, static_cast<size_t>(nrecv)};
}

static UniValue CallRPC(const std::string& method, const UniValue& params)
{
    const std::string host{gArgs.GetArg("-rpcconnect", "127.0.0.1")};
    const uint16_t port{static_cast<uint16_t>(gArgs.GetIntArg("-rpcport", BaseParams().RPCPort()))};

    std::string auth;
    if (gArgs.GetArg("-rpcpassword", "").empty()) {
        if (GetAuthCookie(auth) != AuthCookieResult::Ok) {
            throw std::runtime_error("Could not locate RPC credentials. Pass -rpcpassword or ensure the node's .cookie is readable.");
        }
    } else {
        auth = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    }

    UniValue request(UniValue::VOBJ);
    request.pushKV("jsonrpc", "2.0");
    request.pushKV("id", "lattica-miner");
    request.pushKV("method", method);
    request.pushKV("params", params);
    const std::string body{request.write() + "\n"};

    const std::pair<std::string, std::string> headers[]{
        {"Content-Type", "application/json"},
        {"Authorization", "Basic " + EncodeBase64(auth)},
    };

    HTTPResponse response;
    try {
        HTTPClient client{HTTPClient::Connect(host, port, std::chrono::seconds(DEFAULT_HTTP_CLIENT_TIMEOUT))};
        response = client.Post("/", headers, body);
    } catch (const CConnectionFailed&) {
        throw std::runtime_error(strprintf("Could not connect to the server %s:%d — is latticad running?", host, port));
    }
    if (response.status == 401) throw std::runtime_error("incorrect rpcuser/rpcpassword");

    UniValue reply;
    if (!reply.read(response.body)) throw std::runtime_error("couldn't parse reply from server");
    const UniValue& err{reply.find_value("error")};
    if (!err.isNull()) throw std::runtime_error(strprintf("RPC error for %s: %s", method, err.write()));
    return reply.find_value("result");
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// Block assembly
// ----------------------------------------------------------------------------
static CBlock BlockFromTemplate(const UniValue& tmpl, const CScript& payout_script, uint32_t extranonce)
{
    CBlock block;
    block.nVersion = tmpl.find_value("version").getInt<int>();
    block.hashPrevBlock = uint256::FromHex(tmpl.find_value("previousblockhash").get_str()).value();
    block.nTime = tmpl.find_value("curtime").getInt<int64_t>();
    block.nBits = static_cast<uint32_t>(std::stoul(tmpl.find_value("bits").get_str(), nullptr, 16));
    block.nNonce = 0;

    const int height{tmpl.find_value("height").getInt<int>()};
    const CAmount coinbase_value{tmpl.find_value("coinbasevalue").getInt<int64_t>()};

    CMutableTransaction coinbase;
    coinbase.version = 1;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << height << CScriptNum(extranonce);
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = coinbase_value;
    coinbase.vout[0].scriptPubKey = payout_script;

    const UniValue& wc{tmpl.find_value("default_witness_commitment")};
    if (wc.isStr() && !wc.get_str().empty()) {
        const std::vector<unsigned char> script_bytes{ParseHex(wc.get_str())};
        coinbase.vout.emplace_back(CAmount{0}, CScript(script_bytes.begin(), script_bytes.end()));
        coinbase.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
    }

    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));

    const UniValue& txs{tmpl.find_value("transactions")};
    for (size_t i = 0; i < txs.size(); ++i) {
        CMutableTransaction tx;
        if (!DecodeHexTx(tx, txs[i].find_value("data").get_str())) {
            throw std::runtime_error("getblocktemplate returned an undecodable transaction");
        }
        block.vtx.push_back(MakeTransactionRef(std::move(tx)));
    }

    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

// ----------------------------------------------------------------------------
// CPU proof-of-work grind
// ----------------------------------------------------------------------------

static unsigned WorkerCount()
{
    const int64_t requested{gArgs.GetIntArg("-threads", 0)};
    if (requested > 0) return static_cast<unsigned>(requested);
    const unsigned hw{std::thread::hardware_concurrency()};
    return hw ? hw : 4;
}

// Sweep the 32-bit nonce space across `nthreads` workers. Returns the winning
// nonce, or nullopt when the range is exhausted or `abort` reports a new tip.
//
// Each worker owns its own copy of the header, so nothing is shared but the
// atomics: the hot loop is a pure function of the nonce.
static std::optional<uint32_t> Grind(const CBlockHeader& header,
                                     const uint256& target,
                                     unsigned nthreads,
                                     const std::function<bool()>& abort,
                                     std::atomic<uint64_t>& hashes)
{
    const arith_uint256 bn_target{UintToArith256(target)};
    std::atomic<bool> stop{false};
    std::atomic<uint32_t> winner{0};
    std::atomic<bool> have_winner{false};

    auto worker = [&](unsigned tid) {
        CBlockHeader hdr{header};
        uint64_t local{0};
        for (uint64_t n = tid; n <= std::numeric_limits<uint32_t>::max(); n += nthreads) {
            if ((local & 0xffff) == 0xffff) {
                hashes.fetch_add(0x10000, std::memory_order_relaxed);
                if (stop.load(std::memory_order_relaxed)) return;
                // Only one worker pays for the tip check, and only rarely.
                if (tid == 0 && (local & 0xfffff) == 0xfffff && abort()) {
                    stop.store(true, std::memory_order_relaxed);
                    return;
                }
            }
            ++local;
            hdr.nNonce = static_cast<uint32_t>(n);
            if (UintToArith256(hdr.GetPoWHash()) <= bn_target) {
                if (!have_winner.exchange(true)) winner.store(static_cast<uint32_t>(n));
                stop.store(true, std::memory_order_relaxed);
                return;
            }
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    for (unsigned t = 0; t < nthreads; ++t) pool.emplace_back(worker, t);
    for (auto& th : pool) th.join();

    if (!have_winner.load()) return std::nullopt;
    return winner.load();
}

static int Benchmark()
{
    const unsigned nthreads{WorkerCount()};
    const double secs{static_cast<double>(gArgs.GetIntArg("-seconds", 8))};

    CBlockHeader hdr;
    hdr.nVersion = 1;
    hdr.hashPrevBlock.SetNull();
    hdr.hashMerkleRoot.SetNull();
    hdr.nTime = 1;
    hdr.nBits = 0x1d00ffff;

    // A target of zero is unreachable, so the sweep runs the full window.
    std::atomic<uint64_t> hashes{0};
    std::atomic<bool> stop{false};
    const auto t0{std::chrono::steady_clock::now()};

    auto worker = [&](unsigned tid) {
        CBlockHeader h{hdr};
        uint64_t local{0};
        while (!stop.load(std::memory_order_relaxed)) {
            for (int i = 0; i < 0x10000; ++i) {
                h.nNonce = static_cast<uint32_t>(tid + nthreads * local++);
                (void)h.GetPoWHash();
            }
            hashes.fetch_add(0x10000, std::memory_order_relaxed);
        }
    };
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < nthreads; ++t) pool.emplace_back(worker, t);
    std::this_thread::sleep_for(std::chrono::duration<double>(secs));
    stop.store(true);
    for (auto& th : pool) th.join();

    const double dt{std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count()};
    const double hps{static_cast<double>(hashes.load()) / dt};
    tfm::format(std::cout, "SHA3-256d: %.2f MH/s on %d threads (%.2f MH/s per thread)\n",
                hps / 1e6, nthreads, hps / nthreads / 1e6);
    // At difficulty 1 a block needs 2^32 hashes on average.
    tfm::format(std::cout, "at difficulty 1 that is one block every %.1f minutes\n",
                4294967296.0 / hps / 60.0);
    return EXIT_SUCCESS;
}

static int NetworkMine()
{
    const std::string addr{gArgs.GetArg("-address", "")};
    if (addr.empty()) throw std::runtime_error("Specify the payout address with -address=<addr>");
    std::string addr_err;
    const CTxDestination dest{DecodeDestination(addr, Params(), addr_err)};
    if (!IsValidDestination(dest)) throw std::runtime_error(strprintf("Invalid -address: %s", addr_err));
    const CScript payout_script{GetScriptForDestination(dest)};
    const unsigned nthreads{WorkerCount()};

    tfm::format(std::cout, "lattica-miner: chain=%s threads=%d payout=%s\n",
                ChainTypeToString(gArgs.GetChainType()), nthreads, addr);

    uint32_t extranonce{0};
    uint64_t blocks_found{0};
    while (true) {
        UniValue tmpl;
        try {
            UniValue gbt_params(UniValue::VOBJ);
            UniValue rules(UniValue::VARR);
            rules.push_back("segwit");
            gbt_params.pushKV("rules", rules);
            UniValue gbt_args(UniValue::VARR);
            gbt_args.push_back(gbt_params);
            tmpl = CallRPC("getblocktemplate", gbt_args);
        } catch (const std::exception& e) {
            tfm::format(std::cerr, "getblocktemplate failed: %s\nretrying in 5s...\n", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        const int height{tmpl.find_value("height").getInt<int>()};
        const uint256 target_u{uint256::FromHex(tmpl.find_value("target").get_str()).value()};
        const uint256 prev{uint256::FromHex(tmpl.find_value("previousblockhash").get_str()).value()};

        CBlock block{BlockFromTemplate(tmpl, payout_script, extranonce++)};

        tfm::format(std::cout, "mining block %d (prev %s, target %s)\n",
                    height, prev.GetHex().substr(0, 16), target_u.GetHex().substr(0, 16));

        // Abort the sweep the moment the network extends past this tip.
        const std::string prev_hex{prev.GetHex()};
        auto abort = [&]() -> bool {
            try { return CallRPC("getbestblockhash", UniValue{UniValue::VARR}).get_str() != prev_hex; }
            catch (const std::exception&) { return false; }
        };

        std::atomic<uint64_t> hashes{0};
        const auto t0{std::chrono::steady_clock::now()};
        const auto found{Grind(block, target_u, nthreads, abort, hashes)};
        const double dt{std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count()};
        tfm::format(std::cout, "  %.0f Mhash in %.0fs (%.2f MH/s)\n",
                    static_cast<double>(hashes.load()) / 1e6, dt,
                    static_cast<double>(hashes.load()) / dt / 1e6);

        if (!found) continue;  // range exhausted, or the tip moved -- refetch.

        block.nNonce = *found;
        DataStream ss;
        ss << TX_WITH_WITNESS(block);
        try {
            UniValue sb_args(UniValue::VARR);
            sb_args.push_back(HexStr(ss));
            const UniValue res{CallRPC("submitblock", sb_args)};
            if (res.isNull()) {
                ++blocks_found;
                tfm::format(std::cout, "FOUND block %d -> %s  (total %d)\n",
                            height, block.GetHash().GetHex(), blocks_found);
            } else {
                tfm::format(std::cerr, "block %d rejected: %s\n", height, res.write());
            }
        } catch (const std::exception& e) {
            tfm::format(std::cerr, "submitblock failed: %s\n", e.what());
        }
    }
    return EXIT_SUCCESS;
}

static int AppMain(int argc, char* argv[])
{
    SetupEnvironment();
    if (!SetupNetworking()) throw std::runtime_error("Error: Initializing networking failed");

    SetupMinerArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }
    if (HelpRequested(gArgs) || gArgs.IsArgSet("-version")) {
        std::string strUsage{CLIENT_NAME " miner version " + FormatFullVersion() + "\n"};
        if (!gArgs.IsArgSet("-version")) {
            strUsage += "\nUsage:  lattica-miner [options] -address=<addr>\n"
                        "\nCPU-mine to a running latticad.\n\n" + gArgs.GetHelpMessage();
        }
        tfm::format(std::cout, "%s", strUsage);
        return EXIT_SUCCESS;
    }

    if (!CheckDataDirOption(gArgs)) {
        throw std::runtime_error(strprintf("Specified data directory \"%s\" does not exist.", gArgs.GetArg("-datadir", "")));
    }
    if (!gArgs.ReadConfigFiles(error, true)) {
        throw std::runtime_error(strprintf("Error reading configuration file: %s", error));
    }

    SelectBaseParams(gArgs.GetChainType());
    if (gArgs.GetBoolArg("-benchmark", false)) return Benchmark();
    SelectParams(gArgs.GetChainType());
    return NetworkMine();
}

MAIN_FUNCTION
{
    try {
        return AppMain(argc, argv);
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "lattica-miner");
    } catch (...) {
        PrintExceptionContinue(nullptr, "lattica-miner");
    }
    return EXIT_FAILURE;
}
