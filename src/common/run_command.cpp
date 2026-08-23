// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <common/run_command.h>

#include <tinyformat.h>
#include <univalue.h>
#include <util/string.h>
#include <util/subprocess.h>

#include <sstream>
#include <stdexcept>
#include <utility>

UniValue RunCommandParseJSON(const std::vector<std::string>& cmd_args, const std::string& str_std_in)
{
    namespace sp = subprocess;

    UniValue result_json;
    std::istringstream stdout_stream;
    std::istringstream stderr_stream;

    if (cmd_args.empty()) return UniValue::VNULL;

    auto c = sp::Popen(cmd_args, sp::input{sp::PIPE}, sp::output{sp::PIPE}, sp::error{sp::PIPE});
    if (!str_std_in.empty()) {
        c.send(str_std_in);
    }
    auto [out_res, err_res] = c.communicate();
    stdout_stream.str(std::string{out_res.buf.begin(), out_res.buf.end()});
    stderr_stream.str(std::string{err_res.buf.begin(), err_res.buf.end()});

    std::string result;
    std::string error;
    std::getline(stdout_stream, result);
    std::getline(stderr_stream, error);

    const int n_error = c.retcode();
    if (n_error) throw std::runtime_error(strprintf("RunCommandParseJSON error: process(%s) returned %d: %s\n", util::Join(cmd_args, " "), n_error, error));
    if (!result_json.read(result)) throw std::runtime_error("Unable to parse JSON: " + result);

    return result_json;
}
