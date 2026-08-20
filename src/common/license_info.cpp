// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <lattica-build-config.h> // IWYU pragma: keep

#include <common/license_info.h>

#include <tinyformat.h>
#include <util/translation.h>

#include <string>

std::string CopyrightHolders(const std::string& strPrefix)
{
    return strPrefix + COPYRIGHT_HOLDERS;
}

std::string LicenseInfo()
{
    return CopyrightHolders(strprintf(_("Copyright (C) %i"), COPYRIGHT_YEAR).translated + " ") + "\n" +
           "\n" +
           _("This is experimental software.") + "\n" +
           strprintf(_("Distributed under the MIT software license, see the accompanying file %s or %s"), "COPYING", "<https://opensource.org/license/MIT>").translated +
           "\n";
}
