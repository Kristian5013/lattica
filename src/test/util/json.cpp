// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <test/util/json.h>

#include <univalue.h>
#include <util/check.h>

#include <string_view>

UniValue read_json(std::string_view jsondata)
{
    UniValue v;
    Assert(v.read(jsondata) && v.isArray());
    return v.get_array();
}
