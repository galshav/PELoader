#include <Windows.h>
#include <vector>
#include <iostream>
#include "WinException.hpp"
#include "Verifiers.hpp"
#include "PELoader.hpp"

typedef int(*exportedCallback)(void);

int main(void)
{
	try
	{
		// Get PE from external resource.
		std::cout << "Reading compact image from disk." << std::endl;
		const HANDLE hUnammapedModule = ::CreateFileW(
			L"C:\\Users\\galsh\\source\\repos\\Elbit\\Debug\\ArbitaryDLL.dll",
			GENERIC_READ,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_READ_ATTRIBUTES,
			NULL);															
		VERIFY_WINAPI(INVALID_HANDLE_VALUE != hUnammapedModule);
		const HANDLE hFileMapping = ::CreateFileMappingW(hUnammapedModule, NULL, PAGE_READONLY, 0, 0, NULL);
		VERIFY_WINAPI(NULL != hFileMapping);
		const LPVOID module = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		VERIFY_WINAPI(NULL != module);

		// Extract PE headers (DOS and NT headers) and PE's Sections.
		std::cout << "Verify image headers." << std::endl;
		const PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)module;
		VERIFY(pDosHeader->e_magic == IMAGE_DOS_SIGNATURE, std::exception("MZ magic not found in module"));
		const PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)module + pDosHeader->e_lfanew);
		VERIFY(pNtHeader->Signature == IMAGE_NT_SIGNATURE, std::exception("PE magic not found in module"));
		const PIMAGE_SECTION_HEADER pFirstSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeader + sizeof(IMAGE_NT_HEADERS));
		
		// Find in which section the Export table exist.
		const PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
		const PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)(&(pNtHeader->OptionalHeader));
		const size_t rdataSectionIndex = Core::PELoader::GetSectionHeaderIndexByVirtualAddress(
			pFirstSectionHeader,
			pFileHeader->NumberOfSections,
			pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
		// Get the Export table from the section found.
		const PIMAGE_SECTION_HEADER rdataSectionHeader = Core::PELoader::GetSectionHeaderByIndex(pFirstSectionHeader, rdataSectionIndex);
		CHAR sectionName[9] = { 0 }; // 8 Bytes for section name + 1 byte for null terminator.
		memcpy(sectionName, rdataSectionHeader->Name, 8);
		std::cout << "Export table found in section: " << sectionName << std::endl;
		const PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)Core::PELoader::GetEntityWithinSection(
			module,
			rdataSectionHeader->PointerToRawData,
			pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
			rdataSectionHeader->VirtualAddress);

		// Get dll name.
		const char* dllName = (char*)Core::PELoader::GetEntityWithinSection(
			module, 
			rdataSectionHeader->PointerToRawData,
			pExportDirectory->Name,
			rdataSectionHeader->VirtualAddress);
		std::cout << "DLL Name: " << dllName << std::endl;

		// Iterate exported methods names.
		const PDWORD functionsNames = (PDWORD)Core::PELoader::GetEntityWithinSection(
			module,
			rdataSectionHeader->PointerToRawData,
			pExportDirectory->AddressOfNames,
			rdataSectionHeader->VirtualAddress);
		for (size_t i = 0; i < pExportDirectory->NumberOfNames; ++i)
		{
			const char* currentName = (char*)Core::PELoader::GetEntityWithinSection(
				module,
				rdataSectionHeader->PointerToRawData,
				*(functionsNames + i),
				rdataSectionHeader->VirtualAddress);
			std::cout << "Exported function: " << currentName << std::endl;
		}

		/* 
			Iterate exported methods addresses (Don't care about ordinals array because I know how my DLL looks like).
			I know the RVA's are of function pointers, so they must reside in
			the .text section.
		*/
		const PDWORD functionsAddresses = (PDWORD)Core::PELoader::GetEntityWithinSection(
			module,
			rdataSectionHeader->PointerToRawData,
			pExportDirectory->AddressOfFunctions,
			rdataSectionHeader->VirtualAddress);
		for (size_t i = 0; i < pExportDirectory->NumberOfFunctions; ++i)
		{
			const size_t textSectionIndex = Core::PELoader::GetSectionHeaderIndexByVirtualAddress(
				pFirstSectionHeader,
				pFileHeader->NumberOfSections,
				*(functionsAddresses + i));
			const PIMAGE_SECTION_HEADER pTextSectionHeader = Core::PELoader::GetSectionHeaderByIndex(
				pFirstSectionHeader,
				textSectionIndex);
			LPCVOID callback = Core::PELoader::GetEntityWithinSection(
				module,
				pTextSectionHeader->PointerToRawData,
				*(functionsAddresses + i),
				pTextSectionHeader->VirtualAddress);
			std::cout << "Exported function address: " << callback << std::endl;

			/*
				Allocate memory for function and call it.
				I know it bit cracky, for deployment we can assure deletion on allocated memory
				after execution, we also need to keep our allocated objects destroyed on completion using
				C++ idioms such as RAII for example.
			*/
			const auto ptr = ::VirtualAlloc(NULL, 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			memcpy(ptr, callback, 512);
			if (1 == i)
			{
				const int result = ((exportedCallback)ptr)();
				std::cout << "Result from second callback: " << result << std::endl;
			}
		}



		const auto closeResult = ::CloseHandle(hUnammapedModule);
		return 0;
	}

	/* 
		Just for debugging, I don't want my app to crash yet.
		I want to examine the winapi error code first.
	*/
	catch (const WinException& error)
	{
		std::cout << error.what() << std::endl;
		return error.m_ErrorCode;
	}

	catch (const std::exception& error)
	{
		std::cout << error.what() << std::endl;
		throw;
	}

	catch (...)
	{
		std::cout << "Unhandled exception" << std::endl;
		throw;
	}
}