// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// lattica-miner-gpu — a standalone GPU miner (OpenCL, portable across NVIDIA / AMD /
// Intel). It talks to a running latticad over JSON-RPC: getblocktemplate to
// obtain the next block, assembles it (coinbase + the template's transactions +
// the SHA3 merkle root), grinds the 80-byte header on the GPU against the
// consensus SHA3-256d proof-of-work (CBlockHeader::GetPoWHash, so the mined PoW is
// bit-identical to the node's own miner), and submitblock's the first solution.
// The extranonce rolls between rounds; a tip check drops stale work.
//
// Modes:
//   lattica-miner-gpu -address=<addr>            mine to a running latticad (GPU)
//   lattica-miner-gpu -benchmark                 measure the GPU's SHA3-256d hashrate
//   lattica-miner-gpu -genesis -nbits=<hex> -ntime=<n>
//                                             mine a genesis block (rolls nTime)

#define CL_TARGET_OPENCL_VERSION 120
#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

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

#include "miner_kernel.h"

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
    argsman.AddArg("-device=<n>", "OpenCL GPU index to use (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-benchmark", "Measure the GPU's SHA3-256d hashrate and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-seconds=<s>", "Benchmark duration in seconds (default: 8)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-genesis", "Mine a genesis block (rolls nTime); needs -nbits and -ntime", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-nbits=<hex>", "Compact target for -genesis (e.g. 1c01d41b)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-ntime=<n>", "Base block time for -genesis (unix seconds)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
}

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
    request.pushKV("id", "lattica-miner-gpu");
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
// OpenCL GPU back-end for the SHA3-256d proof of work.
// ----------------------------------------------------------------------------
static void ClCheck(cl_int e, const char* what)
{
    if (e != CL_SUCCESS) throw std::runtime_error(strprintf("OpenCL %s failed (error %d)", what, (int)e));
}

// Serialize an 80-byte header into 10 little-endian 64-bit lanes for the kernel.
static void HeaderLanes(const CBlockHeader& h, uint64_t out[10])
{
    DataStream ss;
    ss << h;
    if (ss.size() != 80) throw std::runtime_error("unexpected header serialization size");
    std::memcpy(out, ss.data(), 80);
}

// A uint256 already stores 32 little-endian bytes = the 4 limbs the kernel wants.
static void TargetLimbs(const uint256& t, uint64_t out[4])
{
    std::memcpy(out, t.data(), 32);
}

class GpuMiner
{
public:
    void Init(int device_index)
    {
        cl_platform_id plats[16]; cl_uint np = 0;
        ClCheck(clGetPlatformIDs(16, plats, &np), "clGetPlatformIDs");
        std::vector<cl_device_id> devs;
        for (cl_uint p = 0; p < np; ++p) {
            cl_device_id d[32]; cl_uint nd = 0;
            if (clGetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, 32, d, &nd) == CL_SUCCESS)
                for (cl_uint i = 0; i < nd; ++i) devs.push_back(d[i]);
        }
        if (devs.empty()) throw std::runtime_error("no OpenCL GPU devices found");
        m_ndev = (int)devs.size();
        if (device_index < 0 || device_index >= m_ndev) throw std::runtime_error("-device index out of range");
        cl_device_id dev = devs[device_index];
        char nm[256] = {0};
        clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(nm), nm, nullptr);
        m_name = nm;

        cl_int e;
        m_ctx = clCreateContext(nullptr, 1, &dev, nullptr, nullptr, &e); ClCheck(e, "clCreateContext");
        m_q = clCreateCommandQueue(m_ctx, dev, CL_QUEUE_PROFILING_ENABLE, &e); ClCheck(e, "clCreateCommandQueue");
        const char* src = SHA3D_CL_SOURCE;
        m_prog = clCreateProgramWithSource(m_ctx, 1, &src, nullptr, &e); ClCheck(e, "clCreateProgramWithSource");
        e = clBuildProgram(m_prog, 1, &dev, "-cl-std=CL1.2", nullptr, nullptr);
        if (e != CL_SUCCESS) {
            size_t n = 0; clGetProgramBuildInfo(m_prog, dev, CL_PROGRAM_BUILD_LOG, 0, nullptr, &n);
            std::string log(n, '\0'); clGetProgramBuildInfo(m_prog, dev, CL_PROGRAM_BUILD_LOG, n, log.data(), nullptr);
            throw std::runtime_error("OpenCL kernel build failed:\n" + log);
        }
        m_self = clCreateKernel(m_prog, "selftest", &e); ClCheck(e, "kernel selftest");
        m_bench = clCreateKernel(m_prog, "bench", &e); ClCheck(e, "kernel bench");
        m_mine = clCreateKernel(m_prog, "mine", &e); ClCheck(e, "kernel mine");
        m_hdr = clCreateBuffer(m_ctx, CL_MEM_READ_ONLY, 10 * sizeof(uint64_t), nullptr, &e); ClCheck(e, "buf hdr");
        m_target = clCreateBuffer(m_ctx, CL_MEM_READ_ONLY, 4 * sizeof(uint64_t), nullptr, &e); ClCheck(e, "buf target");
        m_found = clCreateBuffer(m_ctx, CL_MEM_READ_WRITE, sizeof(cl_uint), nullptr, &e); ClCheck(e, "buf found");
        SelfTest();
    }

    const std::string& Name() const { return m_name; }
    int DeviceCount() const { return m_ndev; }

    // Grind the whole 32-bit nNonce space for a fixed header. Returns the winning
    // nonce, or nullopt if exhausted or abort() asked to stop.
    std::optional<uint32_t> Grind(const uint64_t hdr[10], const uint64_t target[4],
                                  const std::function<bool()>& abort)
    {
        ClCheck(clEnqueueWriteBuffer(m_q, m_hdr, CL_TRUE, 0, 10 * sizeof(uint64_t), hdr, 0, nullptr, nullptr), "write hdr");
        ClCheck(clEnqueueWriteBuffer(m_q, m_target, CL_TRUE, 0, 4 * sizeof(uint64_t), target, 0, nullptr, nullptr), "write target");
        cl_uint found = 0xFFFFFFFFu;
        ClCheck(clEnqueueWriteBuffer(m_q, m_found, CL_TRUE, 0, sizeof(found), &found, 0, nullptr, nullptr), "init found");

        size_t global = GLOBAL, local = LOCAL;
        const cl_uint iters = 256;
        const uint64_t per = (uint64_t)global * iters;
        int since_check = 0;
        for (uint64_t base = 0; base < (uint64_t{1} << 32); base += per) {
            ClCheck(clSetKernelArg(m_mine, 0, sizeof(m_hdr), &m_hdr), "m0");
            ClCheck(clSetKernelArg(m_mine, 1, sizeof(m_target), &m_target), "m1");
            ClCheck(clSetKernelArg(m_mine, 2, sizeof(base), &base), "m2");
            ClCheck(clSetKernelArg(m_mine, 3, sizeof(iters), &iters), "m3");
            ClCheck(clSetKernelArg(m_mine, 4, sizeof(m_found), &m_found), "m4");
            ClCheck(clEnqueueNDRangeKernel(m_q, m_mine, 1, nullptr, &global, &local, 0, nullptr, nullptr), "enqueue mine");
            ClCheck(clFinish(m_q), "clFinish");
            ClCheck(clEnqueueReadBuffer(m_q, m_found, CL_TRUE, 0, sizeof(found), &found, 0, nullptr, nullptr), "read found");
            if (found != 0xFFFFFFFFu) return (uint32_t)found;
            if (abort && ++since_check >= 8) { since_check = 0; if (abort()) return std::nullopt; }
        }
        return std::nullopt;
    }

    double Benchmark(double seconds)
    {
        uint64_t hdr[10]; for (int i = 0; i < 10; ++i) hdr[i] = 0x0123456789abcdefULL * (i + 1);
        ClCheck(clEnqueueWriteBuffer(m_q, m_hdr, CL_TRUE, 0, 10 * sizeof(uint64_t), hdr, 0, nullptr, nullptr), "write hdr");
        cl_int e;
        cl_mem sink = clCreateBuffer(m_ctx, CL_MEM_WRITE_ONLY, GLOBAL * sizeof(uint64_t), nullptr, &e); ClCheck(e, "buf sink");

        size_t global = GLOBAL, local = LOCAL;
        const cl_uint iters = 64;
        double total_hashes = 0, total_ns = 0;
        uint64_t nonce_base = 0;
        while (total_ns < seconds * 1e9) {
            ClCheck(clSetKernelArg(m_bench, 0, sizeof(m_hdr), &m_hdr), "b0");
            ClCheck(clSetKernelArg(m_bench, 1, sizeof(nonce_base), &nonce_base), "b1");
            ClCheck(clSetKernelArg(m_bench, 2, sizeof(iters), &iters), "b2");
            ClCheck(clSetKernelArg(m_bench, 3, sizeof(sink), &sink), "b3");
            cl_event ev;
            ClCheck(clEnqueueNDRangeKernel(m_q, m_bench, 1, nullptr, &global, &local, 0, nullptr, &ev), "enqueue bench");
            ClCheck(clWaitForEvents(1, &ev), "wait bench");
            cl_ulong t0 = 0, t1 = 0;
            clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_START, sizeof(t0), &t0, nullptr);
            clGetEventProfilingInfo(ev, CL_PROFILING_COMMAND_END, sizeof(t1), &t1, nullptr);
            clReleaseEvent(ev);
            total_ns += (double)(t1 - t0);
            total_hashes += (double)global * iters;
            nonce_base += (uint64_t)global * iters;
        }
        clReleaseMemObject(sink);
        return total_hashes / (total_ns / 1e9);
    }

private:
    static constexpr size_t GLOBAL = size_t{1} << 20;
    static constexpr size_t LOCAL = 256;

    void SelfTest()
    {
        cl_int e;
        cl_mem out = clCreateBuffer(m_ctx, CL_MEM_WRITE_ONLY, 64, nullptr, &e); ClCheck(e, "buf selftest");
        ClCheck(clSetKernelArg(m_self, 0, sizeof(out), &out), "arg self");
        size_t one = 1;
        ClCheck(clEnqueueNDRangeKernel(m_q, m_self, 1, nullptr, &one, &one, 0, nullptr, nullptr), "enqueue self");
        unsigned char h[64];
        ClCheck(clEnqueueReadBuffer(m_q, out, CL_TRUE, 0, 64, h, 0, nullptr, nullptr), "read self");
        clReleaseMemObject(out);
        // SHA3-256("") and SHA3-256("abc"), FIPS 202.
        const std::string want = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
                                 "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
        static const char* hx = "0123456789abcdef";
        std::string got;
        got.reserve(128);
        for (int i = 0; i < 64; ++i) { got += hx[h[i] >> 4]; got += hx[h[i] & 0xf]; }
        if (got != want) throw std::runtime_error("FIPS 202 self-test failed — GPU kernel is not Lattica-compatible");
    }

    cl_context m_ctx{};
    cl_command_queue m_q{};
    cl_program m_prog{};
    cl_kernel m_self{}, m_bench{}, m_mine{};
    cl_mem m_hdr{}, m_target{}, m_found{};
    std::string m_name;
    int m_ndev{0};
};

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

// The genesis coinbase carries the headline; its single output is unspendable.
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nBits)
{
    const char* pszTimestamp = "Google Quantum AI 30/Mar/2026 ECDLP-256 in minutes on under half a million physical qubits";
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4)
                                       << std::vector<unsigned char>((const unsigned char*)pszTimestamp,
                                                                     (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = 50 * COIN;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nVersion = 1;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = 0;
    genesis.hashPrevBlock.SetNull();
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

// ----------------------------------------------------------------------------
// Modes
// ----------------------------------------------------------------------------
static int MineGenesis(GpuMiner& gpu)
{
    if (!gArgs.IsArgSet("-nbits") || !gArgs.IsArgSet("-ntime"))
        throw std::runtime_error("-genesis needs -nbits=<hex> and -ntime=<unix seconds>");
    const uint32_t nBits = (uint32_t)std::stoul(gArgs.GetArg("-nbits", ""), nullptr, 16);
    const uint32_t base_time = (uint32_t)std::stoul(gArgs.GetArg("-ntime", ""), nullptr, 10);

    arith_uint256 bn; bn.SetCompact(nBits);
    const uint256 target_u = ArithToUint256(bn);
    uint64_t target[4]; TargetLimbs(target_u, target);
    // Genesis mining is chain-independent: the target = the nBits value it decodes
    // to (a genesis sits at powLimit), so we don't need the network's chainparams
    // (whose genesis assert would be stale while we are re-mining it).
    Consensus::Params consensus{};
    consensus.powLimit = target_u;

    tfm::format(std::cout, "mining genesis on %s: nBits=%08x base nTime=%u target=%s\n",
                gpu.Name(), nBits, base_time, target_u.GetHex());
    tfm::format(std::cout, "(nNonce is 32-bit; rolling nTime when a sweep is exhausted)\n");

    for (uint32_t off = 0; ; ++off) {
        const uint32_t nTime = base_time + off;
        CBlock g{CreateGenesisBlock(nTime, nBits)};
        uint64_t hdr[10]; HeaderLanes(g, hdr);
        auto found = gpu.Grind(hdr, target, {});
        if (found) {
            g.nNonce = *found;
            if (!CheckProofOfWork(g.GetPoWHash(), g.nBits, consensus))
                throw std::runtime_error("GPU reported a nonce the node rejects — kernel/consensus mismatch");
            tfm::format(std::cout, "\nFOUND genesis:\n");
            tfm::format(std::cout, "  nTime            = %u\n", nTime);
            tfm::format(std::cout, "  nNonce           = %u\n", g.nNonce);
            tfm::format(std::cout, "  nBits            = 0x%08x\n", nBits);
            tfm::format(std::cout, "  hashMerkleRoot   = %s\n", g.hashMerkleRoot.GetHex());
            tfm::format(std::cout, "  hashGenesisBlock = %s\n", g.GetHash().GetHex());
            return EXIT_SUCCESS;
        }
        tfm::format(std::cout, "  nTime=%u swept\r", nTime);
        std::cout.flush();
    }
}

static int NetworkMine(GpuMiner& gpu)
{
    const std::string addr{gArgs.GetArg("-address", "")};
    if (addr.empty()) throw std::runtime_error("Specify the payout address with -address=<addr>");
    std::string addr_err;
    const CTxDestination dest{DecodeDestination(addr, Params(), addr_err)};
    if (!IsValidDestination(dest)) throw std::runtime_error(strprintf("Invalid -address: %s", addr_err));
    const CScript payout_script{GetScriptForDestination(dest)};

    tfm::format(std::cout, "lattica-miner-gpu: chain=%s gpu=%s payout=%s\n",
                ChainTypeToString(gArgs.GetChainType()), gpu.Name(), addr);

    uint32_t extranonce{0};
    uint64_t blocks_found{0};
    while (true) {
        UniValue gbt_params(UniValue::VOBJ);
        UniValue rules(UniValue::VARR);
        rules.push_back("segwit");
        gbt_params.pushKV("rules", rules);
        UniValue tmpl;
        try {
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
        uint64_t hdr[10]; HeaderLanes(block, hdr);
        uint64_t target[4]; TargetLimbs(target_u, target);

        tfm::format(std::cout, "mining block %d (prev %s, target %s)\n",
                    height, prev.GetHex().substr(0, 16), target_u.GetHex().substr(0, 16));

        // Abort the sweep the moment the network extends past this tip.
        const std::string prev_hex{prev.GetHex()};
        auto abort = [&]() -> bool {
            try { return CallRPC("getbestblockhash", UniValue{UniValue::VARR}).get_str() != prev_hex; }
            catch (const std::exception&) { return false; }
        };

        auto found = gpu.Grind(hdr, target, abort);
        if (!found) continue;  // exhausted this extranonce, or a new tip — refetch.

        block.nNonce = *found;
        DataStream ss;
        ss << TX_WITH_WITNESS(block);
        try {
            UniValue sb_args(UniValue::VARR);
            sb_args.push_back(HexStr(ss));
            const UniValue res{CallRPC("submitblock", sb_args)};
            if (res.isNull()) {
                ++blocks_found;
                tfm::format(std::cout, "FOUND block %d -> %s  (total %d)\n", height, block.GetHash().GetHex(), blocks_found);
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
            strUsage += "\nUsage:  lattica-miner-gpu [options] -address=<addr>\n"
                        "\nGPU-mine (OpenCL) to a running latticad.\n\n" + gArgs.GetHelpMessage();
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

    GpuMiner gpu;
    gpu.Init((int)gArgs.GetIntArg("-device", 0));
    tfm::format(std::cout, "GPU: %s%s\n", gpu.Name(),
                gpu.DeviceCount() > 1 ? strprintf("  (%d GPUs; -device N to pick)", gpu.DeviceCount()) : "");

    if (gArgs.GetBoolArg("-benchmark", false)) {
        const double secs = gArgs.GetIntArg("-seconds", 8);
        const double hps = gpu.Benchmark(secs);
        tfm::format(std::cout, "SHA3-256d hashrate: %.3f MH/s  (%.4f GH/s)\n", hps / 1e6, hps / 1e9);
        return EXIT_SUCCESS;
    }
    if (gArgs.GetBoolArg("-genesis", false)) return MineGenesis(gpu);
    SelectParams(gArgs.GetChainType());
    return NetworkMine(gpu);
}

MAIN_FUNCTION
{
    try {
        return AppMain(argc, argv);
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "lattica-miner-gpu");
    } catch (...) {
        PrintExceptionContinue(nullptr, "lattica-miner-gpu");
    }
    return EXIT_FAILURE;
}
