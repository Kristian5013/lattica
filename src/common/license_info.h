// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_COMMON_LICENSE_INFO_H
#define LATTICA_COMMON_LICENSE_INFO_H

#include <string>

std::string CopyrightHolders(const std::string& strPrefix);

/** Returns licensing information (for -version) */
std::string LicenseInfo();

#endif // LATTICA_COMMON_LICENSE_INFO_H
