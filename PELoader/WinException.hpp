#pragma once
#include <exception>
#include <Windows.h>
#include <string>
class WinException : public std::exception
{
public:
	WinException();
	const char* what() const throw();

public:
	DWORD m_ErrorCode = 0;
	std::string m_ErrorMessage = std::string();
};
