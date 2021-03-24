#pragma once
#include <windows.h>

namespace Core
{
	class PELoader
	{
	public:
		static size_t GetSectionHeaderIndexByVirtualAddress(
			PIMAGE_SECTION_HEADER firstSectionHeader,
			size_t numberOfSections,
			const DWORD virtualAddress);

		static PIMAGE_SECTION_HEADER GetSectionHeaderByIndex(
			PIMAGE_SECTION_HEADER firstSectionHeader,
			size_t sectionIndex);

		static LPVOID GetEntityWithinSection(
			LPCVOID moduleBase, 
			const DWORD pointerToRawData, 
			const DWORD entityRVA, const DWORD sectionRVA);
	};
}
