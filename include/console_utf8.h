#pragma once

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>

inline void enableUTF8Console() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U8TEXT);
}
#else
inline void enableUTF8Console() {
    // UTF-8 console is enabled by default on non-Windows platforms
}
#endif