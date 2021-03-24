#include "WinException.hpp"
#include <string>
#include <sstream>

WinException::WinException() :
	m_ErrorCode(GetLastError()),
	m_ErrorMessage("Error Code:" + std::to_string(m_ErrorCode))
{
}

const char* WinException::what() const throw()
{
	return m_ErrorMessage.c_str();
}
