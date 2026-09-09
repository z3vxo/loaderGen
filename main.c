#include "includes/main/core.h"
#include "includes/apis/apidefs.h"
#include "includes/apis/apis.h"

#include "stdio.h"



#ifdef OUTPUT_DLL

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fwReason, LPVOID lpvReserved) {
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH: 
		CreateThread(NULL, 0, LoadMain, NULL, 0, NULL);
	case DLL_PROCESS_DETACH:
		break;
						   

	}
	
}

#endif




int main() {
	

	
	printf("#define HASHED_NTDLL 0x%08x\n", HasherW(L"ntdll.dll"));
	
	if (!LoadMain()) return 1;






	return 0;
}



