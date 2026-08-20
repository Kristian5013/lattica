// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <util/exception.h>

#include <clientversion.h>

#include <tinyformat.h>
#include <util/log.h>

#include <exception>
#include <iostream>
#include <string>
#include <typeinfo>

#ifdef WIN32
#include <windows.h>
#endif // WIN32

static std::string FormatException(const std::exception* pex, std::string_view thread_name)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(nullptr, pszModule, sizeof(pszModule));
#else
    const char* pszModule = CLIENT_NAME;
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, thread_name);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, thread_name);
}

void PrintExceptionContinue(const std::exception* pex, std::string_view thread_name)
{
    std::string message = FormatException(pex, thread_name);
    LogWarning("\n\n************************\n%s", message);
    tfm::format(std::cerr, "\n\n************************\n%s\n", message);
}
