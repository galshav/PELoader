#pragma once
#include <exception>

#define VERIFY(condition, exception) \
if (!(condition)) throw exception

#define VERIFY_WINAPI(condition) VERIFY(condition, WinException())
