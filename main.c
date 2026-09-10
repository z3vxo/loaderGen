#include "includes/core/core.h"
#include "includes/apis/apidefs.h"
#include "includes/apis/apis.h"

#include "stdio.h"
#include "winhttp.h"



#ifdef OUTPUT_DLL

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fwReason, LPVOID lpvReserved) {
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH: 
		CreateThread(NULL, 0, LoadMain, hinstDLL, 0, NULL);
	case DLL_PROCESS_DETACH:
		break;
						   

	}
	
}

#endif




int main() {
	
	/*printf("WinHttpReadData hash: 0x%08x\n", HasherA("WinHttpReadData"));
	return 1;*/
	if (!LoadMain(NULL)) return 1;

	return 0;
}



