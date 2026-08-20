// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_COMMON_URL_H
#define LATTICA_COMMON_URL_H

#include <string>
#include <string_view>

/* Decode a URL.
 *
 * Notably this implementation does not decode a '+' to a ' '.
 */
std::string UrlDecode(std::string_view url_encoded);

/* Encode a URL. */
std::string UrlEncode(std::string_view str);

#endif // LATTICA_COMMON_URL_H
