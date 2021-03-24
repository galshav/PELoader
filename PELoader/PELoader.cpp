#include "PELoader.hpp"
#include "Verifiers.hpp"

size_t Core::PELoader::GetSectionHeaderIndexByVirtualAddress(
    PIMAGE_SECTION_HEADER firstSectionHeader,
    size_t numberOfSections, 
    const DWORD virtualAddress)
{
	for (size_t i = 0; i < numberOfSections; ++i)
	{
		if ((firstSectionHeader[i].VirtualAddress <= virtualAddress) &&
			(virtualAddress < firstSectionHeader[i].VirtualAddress + firstSectionHeader[i].Misc.VirtualSize))
		{
			return i;
		}
	}

	VERIFY(false, std::exception("RVA isn't in sections."));
}

PIMAGE_SECTION_HEADER Core::PELoader::GetSectionHeaderByIndex(
	PIMAGE_SECTION_HEADER firstSectionHeader,
	size_t sectionIndex)
{
	return &firstSectionHeader[sectionIndex];
}

LPVOID Core::PELoader::GetEntityWithinSection(
	LPCVOID moduleBase,
	const DWORD pointerToRawData,
	const DWORD entityRVA,
	const DWORD sectionRVA)
{
	return (LPVOID)((PCHAR)moduleBase + pointerToRawData + (entityRVA - sectionRVA));
}
