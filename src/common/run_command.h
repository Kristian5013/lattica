// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_COMMON_RUN_COMMAND_H
#define LATTICA_COMMON_RUN_COMMAND_H

#include <string>
#include <vector>

class UniValue;

/**
 * Execute a command which returns JSON, and parse the result.
 *
 * @param cmd_args The command and arguments
 * @param str_std_in string to pass to stdin
 * @return parsed JSON
 */
UniValue RunCommandParseJSON(const std::vector<std::string>& cmd_args, const std::string& str_std_in = "");

#endif // LATTICA_COMMON_RUN_COMMAND_H
