// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_REST_H
#define LATTICA_REST_H

#include <string>

enum class RESTResponseFormat {
    UNDEF,
    BINARY,
    HEX,
    JSON,
};

/**
 * Parse a URI to get the data format and URI without data format
 * and query string.
 *
 * @param[out]  param   The strReq without the data format string and
 *                      without the query string (if any).
 * @param[in]   strReq  The URI to be parsed.
 * @return      RESTResponseFormat that was parsed from the URI.
 */
RESTResponseFormat ParseDataFormat(std::string& param, const std::string& strReq);

#endif // LATTICA_REST_H
